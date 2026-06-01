defmodule AttestoPhoenix.Controller.RegistrationControllerTest do
  @moduledoc """
  Tests for the OAuth 2.0 Dynamic Client Registration endpoint (RFC 7591 §3).

  These exercise the controller-owned protocol framing: Content-Type guarding
  (RFC 7591 §3.1), metadata validation against the server's advertised policy
  (RFC 7591 §2), credential issuance via the `Attesto` core, host-owned
  persistence through the `:register_client` callback, the RFC 7591 §3.2.1
  client information response, no-store cache headers (RFC 7234 §5.2), and the
  RFC 7591 §3.2.2 error body. The host policy is injected through an
  `AttestoPhoenix.Config` struct placed on the conn, so no live datastore is
  required.
  """
  use ExUnit.Case, async: true

  import Plug.Test
  import Plug.Conn

  alias AttestoPhoenix.Config
  alias AttestoPhoenix.Controller.RegistrationController

  @endpoint_path "/oauth/register"

  # A minimal validated config struct. The registration controller never
  # touches the keystore/repo/auth callbacks, so those enforce-keys carry inert
  # placeholders; only the registration-relevant fields matter here.
  defp config(overrides) do
    base = %{
      issuer: "https://issuer.example",
      keystore: :unused,
      repo: :unused,
      load_client: fn _id -> {:error, :not_found} end,
      verify_client_secret: fn _client, _secret -> false end,
      load_principal: fn _subject -> {:error, :not_found} end,
      register_client: fn attrs -> {:ok, attrs} end,
      scopes_supported: ["read", "write"]
    }

    struct(Config, Map.merge(base, Map.new(overrides)))
  end

  defp post_register(config, metadata, content_type \\ "application/json") do
    :post
    |> conn(@endpoint_path, metadata)
    |> put_req_header("content-type", content_type)
    |> Map.put(:body_params, metadata)
    |> put_private(:attesto_phoenix_config, config)
    |> RegistrationController.create(%{})
  end

  defp delete_register(config, client_id, token) do
    conn =
      :delete
      |> conn(@endpoint_path <> "/" <> client_id)
      |> put_private(:attesto_phoenix_config, config)

    conn =
      if is_binary(token) do
        put_req_header(conn, "authorization", "Bearer " <> token)
      else
        conn
      end

    RegistrationController.delete(conn, %{"client_id" => client_id})
  end

  defp body(conn), do: JSON.decode!(conn.resp_body)

  describe "successful registration (RFC 7591 §3.2.1)" do
    test "registers a confidential client and returns 201 with credentials" do
      conn =
        post_register(config([]), %{
          "grant_types" => ["authorization_code"],
          "redirect_uris" => ["https://client.example/callback"],
          "scope" => "read write"
        })

      payload = body(conn)

      assert conn.status == 201
      assert is_binary(payload["client_id"]) and payload["client_id"] != ""
      assert is_binary(payload["client_secret"]) and payload["client_secret"] != ""
      # RFC 7591 §3.2.1: client_secret_expires_at is REQUIRED whenever a
      # client_secret is issued; 0 denotes a non-expiring secret.
      assert payload["client_secret_expires_at"] == 0
      assert payload["redirect_uris"] == ["https://client.example/callback"]
      assert payload["scope"] == "read write"
      assert is_integer(payload["client_id_issued_at"])
      assert is_binary(payload["registration_access_token"])

      assert payload["registration_client_uri"] ==
               "https://issuer.example/oauth/register/" <> payload["client_id"]
    end

    test "registration_client_uri follows a custom :oauth_path_prefix (RFC 7592 §2)" do
      conn =
        post_register(config(oauth_path_prefix: "/mcp/oauth"), %{
          "grant_types" => ["authorization_code"],
          "redirect_uris" => ["https://client.example/callback"]
        })

      payload = body(conn)

      assert conn.status == 201

      assert payload["registration_client_uri"] ==
               "https://issuer.example/mcp/oauth/register/" <> payload["client_id"]
    end

    test "a public client (token_endpoint_auth_method none) is issued no secret" do
      conn =
        post_register(config([]), %{
          "grant_types" => ["authorization_code"],
          "redirect_uris" => ["https://client.example/callback"],
          "token_endpoint_auth_method" => "none"
        })

      payload = body(conn)

      assert conn.status == 201
      refute Map.has_key?(payload, "client_secret")
      # RFC 7591 §3.2.1: with no secret issued, client_secret_expires_at is omitted.
      refute Map.has_key?(payload, "client_secret_expires_at")
      assert payload["token_endpoint_auth_method"] == "none"
    end

    test "omits scope from the response when none was requested" do
      conn = post_register(config([]), %{"grant_types" => ["client_credentials"]})

      assert conn.status == 201
      refute Map.has_key?(body(conn), "scope")
    end

    test "every response carries no-store cache headers (RFC 7234 §5.2)" do
      conn = post_register(config([]), %{"grant_types" => ["client_credentials"]})

      assert get_resp_header(conn, "cache-control") == ["no-store"]
      assert get_resp_header(conn, "pragma") == ["no-cache"]
    end
  end

  describe "RFC 7591 §2 metadata passthrough" do
    test "carries known client-identity metadata through to the host store and response" do
      test_pid = self()

      config =
        config(
          register_client: fn attrs ->
            send(test_pid, {:persisted, attrs})
            {:ok, attrs}
          end
        )

      conn =
        post_register(config, %{
          "grant_types" => ["authorization_code"],
          "redirect_uris" => ["https://client.example/callback"],
          "client_name" => "Acme MCP",
          "client_uri" => "https://acme.example",
          "logo_uri" => "https://acme.example/logo.png",
          "tos_uri" => "https://acme.example/tos",
          "policy_uri" => "https://acme.example/privacy",
          "contacts" => ["ops@acme.example"],
          "jwks" => %{"keys" => [%{"kty" => "RSA", "kid" => "client-key"}]}
        })

      payload = body(conn)

      assert conn.status == 201
      assert payload["client_name"] == "Acme MCP"
      assert payload["client_uri"] == "https://acme.example"
      assert payload["logo_uri"] == "https://acme.example/logo.png"
      assert payload["tos_uri"] == "https://acme.example/tos"
      assert payload["policy_uri"] == "https://acme.example/privacy"
      assert payload["contacts"] == ["ops@acme.example"]
      assert payload["jwks"] == %{"keys" => [%{"kty" => "RSA", "kid" => "client-key"}]}

      assert_receive {:persisted, attrs}
      assert attrs["client_name"] == "Acme MCP"
      assert attrs["contacts"] == ["ops@acme.example"]
      assert attrs["jwks"] == %{"keys" => [%{"kty" => "RSA", "kid" => "client-key"}]}
    end

    test "drops unknown fields and never hands them to the host store" do
      test_pid = self()

      config =
        config(
          register_client: fn attrs ->
            send(test_pid, {:persisted, attrs})
            {:ok, attrs}
          end
        )

      conn =
        post_register(config, %{
          "grant_types" => ["authorization_code"],
          "redirect_uris" => ["https://client.example/callback"],
          "is_admin" => true,
          "internal_trust_level" => "root"
        })

      payload = body(conn)

      assert conn.status == 201
      refute Map.has_key?(payload, "is_admin")
      refute Map.has_key?(payload, "internal_trust_level")

      assert_receive {:persisted, attrs}
      refute Map.has_key?(attrs, "is_admin")
      refute Map.has_key?(attrs, "internal_trust_level")
    end

    test "a passthrough member cannot override a protocol-critical member" do
      test_pid = self()

      config =
        config(
          register_client: fn attrs ->
            send(test_pid, {:persisted, attrs})
            {:ok, attrs}
          end
        )

      # A request that also smuggles a redirect_uris-shaped client_name must
      # not corrupt the validated redirect_uris.
      conn =
        post_register(config, %{
          "grant_types" => ["authorization_code"],
          "redirect_uris" => ["https://client.example/callback"],
          "client_name" => "legit"
        })

      assert conn.status == 201
      assert_receive {:persisted, attrs}
      assert attrs["redirect_uris"] == ["https://client.example/callback"]
    end

    test "rejects a malformed known metadata member with invalid_client_metadata" do
      conn =
        post_register(config([]), %{
          "grant_types" => ["client_credentials"],
          "client_name" => 12_345
        })

      assert conn.status == 400
      assert body(conn)["error"] == "invalid_client_metadata"
    end

    test "rejects a non-array contacts member" do
      conn =
        post_register(config([]), %{
          "grant_types" => ["client_credentials"],
          "contacts" => "ops@acme.example"
        })

      assert conn.status == 400
      assert body(conn)["error"] == "invalid_client_metadata"
    end

    test "rejects a malformed inline jwks member" do
      conn =
        post_register(config([]), %{
          "grant_types" => ["client_credentials"],
          "jwks" => ["not", "an", "object"]
        })

      assert conn.status == 400
      assert body(conn)["error"] == "invalid_client_metadata"
    end
  end

  describe "persistence (host-owned)" do
    test "persists the at-rest secret hash, never the plaintext" do
      test_pid = self()

      config =
        config(
          register_client: fn attrs ->
            send(test_pid, {:persisted, attrs})
            {:ok, attrs}
          end
        )

      conn =
        post_register(config, %{
          "grant_types" => ["authorization_code"],
          "redirect_uris" => ["https://client.example/callback"]
        })

      plaintext = body(conn)["client_secret"]
      registration_access_token = body(conn)["registration_access_token"]

      assert_receive {:persisted, attrs}
      refute Map.has_key?(attrs, "client_secret")
      # client_secret_expires_at is a response-only member (RFC 7591 §3.2.1),
      # not client metadata, so it is never handed to the host for persistence.
      refute Map.has_key?(attrs, "client_secret_expires_at")
      assert attrs["client_secret_hash"] == Attesto.Secret.hash(plaintext)
      refute Map.has_key?(attrs, "registration_access_token")
      refute Map.has_key?(attrs, "registration_client_uri")

      assert attrs["registration_access_token_hash"] ==
               Attesto.Secret.hash(registration_access_token)
    end

    test "renders a host store rejection as invalid_client_metadata, not a 500" do
      config = config(register_client: fn _attrs -> {:error, :duplicate} end)

      conn =
        post_register(config, %{
          "grant_types" => ["authorization_code"],
          "redirect_uris" => ["https://client.example/callback"]
        })

      assert conn.status == 400
      assert body(conn)["error"] == "invalid_client_metadata"
    end
  end

  describe "registration management delete (RFC 7592 §2)" do
    test "deletes a dynamically registered client with its registration access token" do
      test_pid = self()
      token = "registration-token"

      client = %{
        client_id: "client-123",
        registration_access_token_hash: Attesto.Secret.hash(token)
      }

      config =
        config(
          load_client: fn "client-123" -> {:ok, client} end,
          client_registration_access_token_hash: fn loaded ->
            loaded.registration_access_token_hash
          end,
          unregister_client: fn loaded ->
            send(test_pid, {:deleted, loaded})
            :ok
          end
        )

      conn = delete_register(config, "client-123", token)

      assert conn.status == 204
      assert conn.resp_body == ""
      assert_receive {:deleted, ^client}
    end

    test "rejects missing or invalid registration access tokens" do
      client = %{
        client_id: "client-123",
        registration_access_token_hash: Attesto.Secret.hash("registration-token")
      }

      config =
        config(
          load_client: fn "client-123" -> {:ok, client} end,
          client_registration_access_token_hash: fn loaded ->
            loaded.registration_access_token_hash
          end,
          unregister_client: fn _loaded -> flunk("invalid token must not delete") end
        )

      missing = delete_register(config, "client-123", nil)
      invalid = delete_register(config, "client-123", "wrong-token")

      assert missing.status == 401
      assert body(missing)["error"] == "invalid_token"
      assert invalid.status == 401
      assert body(invalid)["error"] == "invalid_token"
    end
  end

  describe "event emission (RFC 7591)" do
    test "emits a :client_registered event carrying the client_id, never the secret" do
      test_pid = self()
      config = config(on_event: fn event -> send(test_pid, {:event, event}) end)

      conn =
        post_register(config, %{
          "grant_types" => ["authorization_code"],
          "redirect_uris" => ["https://client.example/callback"]
        })

      client_id = body(conn)["client_id"]

      assert_receive {:event, event}
      assert event.name == :client_registered
      assert event.client_id == client_id
    end
  end

  describe "request guards and validation (RFC 7591 §2 / §3.1)" do
    test "rejects a non-JSON Content-Type with invalid_client_metadata" do
      conn =
        post_register(
          config([]),
          %{"grant_types" => ["client_credentials"]},
          "application/x-www-form-urlencoded"
        )

      assert conn.status == 400
      assert body(conn)["error"] == "invalid_client_metadata"
    end

    test "rejects a missing redirect_uri for authorization_code with invalid_redirect_uri" do
      conn = post_register(config([]), %{"grant_types" => ["authorization_code"]})

      assert conn.status == 400
      assert body(conn)["error"] == "invalid_redirect_uri"
    end

    test "rejects a non-absolute redirect_uri with invalid_redirect_uri" do
      conn =
        post_register(config([]), %{
          "grant_types" => ["authorization_code"],
          "redirect_uris" => ["/relative/callback"]
        })

      assert conn.status == 400
      assert body(conn)["error"] == "invalid_redirect_uri"
    end

    test "rejects an unknown scope with invalid_client_metadata" do
      conn =
        post_register(config([]), %{
          "grant_types" => ["client_credentials"],
          "scope" => "read delete"
        })

      assert conn.status == 400
      assert body(conn)["error"] == "invalid_client_metadata"
    end

    test "rejects a grant_type outside the supported set with invalid_client_metadata" do
      # The default catalog is the RFC 6749 §1.3 set the core understands;
      # `password` is not offered.
      conn = post_register(config([]), %{"grant_types" => ["password"]})

      assert conn.status == 400
      assert body(conn)["error"] == "invalid_client_metadata"
    end

    test "rejects a token_endpoint_auth_method outside the supported set" do
      # The default supported methods are client_secret_basic and none;
      # client_secret_post is not offered.
      conn =
        post_register(config([]), %{
          "grant_types" => ["client_credentials"],
          "token_endpoint_auth_method" => "client_secret_post"
        })

      assert conn.status == 400
      assert body(conn)["error"] == "invalid_client_metadata"
    end
  end
end
