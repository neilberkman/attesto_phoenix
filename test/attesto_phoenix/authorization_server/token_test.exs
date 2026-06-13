defmodule AttestoPhoenix.AuthorizationServer.TokenTest do
  @moduledoc """
  Direct, data-level unit tests for the conn-free token core
  (RFC 6749 §3.2 / §4).

  These exercise `AttestoPhoenix.AuthorizationServer.Token.issue/2` against a
  `%Request{}` of plain data - no `Plug.Conn`, no controller. The focus is the
  contract the controller depends on: the function returns the RFC 6749 §5.1
  response body (or an `OAuthError`) together with the audit events it produced
  *as data* (the core emits nothing itself), and it never touches a conn.
  """
  use ExUnit.Case, async: false

  alias AttestoPhoenix.AuthorizationServer.Token
  alias AttestoPhoenix.AuthorizationServer.Token.Request
  alias AttestoPhoenix.{Config, Event, OAuthError}

  # A throwaway RSA keypair for the minting paths.
  @signing_pem JOSE.JWK.generate_key({:rsa, 2048}) |> JOSE.JWK.to_pem() |> elem(1)

  defmodule Keystore do
    @moduledoc false
    @behaviour Attesto.Keystore

    @impl true
    def signing_pem do
      :attesto_phoenix
      |> Application.fetch_env!(__MODULE__)
      |> Keyword.fetch!(:signing_pem)
    end

    @impl true
    def verification_pems, do: [signing_pem()]
  end

  defmodule StubRepo do
    @moduledoc false
  end

  # One principal kind so `Attesto.Token.mint/3` has a kind to issue under.
  @client_kind Attesto.PrincipalKind.new("client", "oc_", required_claims: [{"client_id", :non_empty_string}])

  @client %{id: "client-1", public?: false}

  setup do
    Application.put_env(:attesto_phoenix, __MODULE__.Keystore, signing_pem: @signing_pem)
    on_exit(fn -> Application.delete_env(:attesto_phoenix, __MODULE__.Keystore) end)
    :ok
  end

  defp config(overrides \\ []) do
    [
      issuer: "https://issuer.example",
      audience: "https://issuer.example",
      keystore: __MODULE__.Keystore,
      repo: StubRepo,
      load_client: fn _ -> {:error, :not_found} end,
      verify_client_secret: fn _client, _given -> false end,
      load_principal: fn _ -> {:error, :not_found} end,
      client_public?: fn client -> Map.get(client, :public?, false) end,
      client_id: fn client -> Map.get(client, :id) end,
      authorize_scope: fn _client, requested -> {:ok, requested} end,
      principal_kinds: [@client_kind],
      build_principal: fn client, subject, scope ->
        %{
          kind: "client",
          sub: ensure_sub(subject),
          scopes: scope,
          claims: %{"client_id" => Map.get(client, :id, "unknown")}
        }
      end
    ]
    |> Keyword.merge(overrides)
    |> Config.new()
  end

  defp ensure_sub("oc_" <> _ = sub), do: sub
  defp ensure_sub(sub), do: "oc_" <> to_string(sub)

  defp request(config, overrides) do
    fields =
      [
        config: config,
        client: @client,
        grant_type: "client_credentials",
        params: %{},
        sender_constraint_input: %{
          dpop_proof: nil,
          mtls_cert_der: nil,
          http_uri: "https://issuer.example/oauth/token",
          http_method: "POST"
        },
        client_ip: "203.0.113.7",
        request_client_id: nil
      ]
      |> Keyword.merge(overrides)

    struct!(Request, fields)
  end

  describe "client_credentials grant (RFC 6749 §4.4)" do
    test "returns the RFC 6749 §5.1 body and a :token_issued event as data" do
      config = config()
      request = request(config, params: %{"scope" => "read write"})

      assert {:ok, response, events} = Token.issue(config, request)

      assert is_binary(response.access_token)
      assert response.token_type == "Bearer"
      assert is_integer(response.expires_in)
      assert response.scope == "read write"
      # RFC 6749 §4.4.3: no refresh token for client_credentials.
      refute Map.has_key?(response, :refresh_token)

      assert [%Event{} = event] = events

      assert %Event{
               name: :token_issued,
               client_id: "client-1",
               grant_type: "client_credentials",
               scope: "read write",
               metadata: %{client_ip: "203.0.113.7"}
             } = event
    end

    test "the core emits nothing itself: a configured :on_event is not invoked" do
      test_pid = self()
      config = config(on_event: fn event -> send(test_pid, {:event, event}) end)
      request = request(config, params: %{"scope" => "read"})

      assert {:ok, _response, [_event]} = Token.issue(config, request)
      refute_received {:event, _}
    end
  end

  describe "denials (RFC 6749 §5.2)" do
    test "an unsupported grant type returns an OAuthError and a :token_denied event" do
      config = config()
      request = request(config, grant_type: "password", params: %{"scope" => "read"})

      assert {:error, %OAuthError{error: :unsupported_grant_type, status: 400}, events} =
               Token.issue(config, request)

      assert [%Event{name: :token_denied} = event] = events
      assert event.client_id == "client-1"
      assert event.grant_type == "password"
      assert event.scope == "read"
      assert event.result == "unsupported_grant_type"
      assert event.metadata.error == "unsupported_grant_type"
      assert event.metadata.http_status == 400
      assert event.metadata.client_ip == "203.0.113.7"
      # The sender-constraint context is derived from the request input data,
      # never from a conn.
      assert event.metadata.sender_constraint == %{
               dpop_present: false,
               mtls_cert_present: false
             }
    end

    test "an invalid scope decision (RFC 6749 §5.2) surfaces invalid_scope" do
      config = config(authorize_scope: fn _client, _requested -> {:error, :invalid_scope} end)
      request = request(config, params: %{"scope" => "admin"})

      assert {:error, %OAuthError{error: :invalid_scope}, [event]} = Token.issue(config, request)
      assert event.name == :token_denied
      assert event.result == "invalid_scope"
      assert event.scope == "admin"
    end

    test "the request-derived client_id is the denial fallback when no :client_id callback" do
      config = config(client_id: nil)

      request =
        request(config,
          grant_type: "password",
          request_client_id: "from-request"
        )

      assert {:error, %OAuthError{}, [event]} = Token.issue(config, request)
      assert event.client_id == "from-request"
    end
  end

  describe "registered grant types (RFC 6749 §4)" do
    test "a grant the client is not registered for is rejected before dispatch" do
      config = config(client_grant_types: fn _client -> ["authorization_code"] end)
      request = request(config, grant_type: "client_credentials")

      assert {:error, %OAuthError{error: :unsupported_grant_type}, [event]} =
               Token.issue(config, request)

      assert event.name == :token_denied
    end

    test "a registered grant proceeds to dispatch and mints a token" do
      config = config(client_grant_types: fn _client -> ["client_credentials"] end)
      request = request(config, params: %{"scope" => "read"})

      assert {:ok, %{access_token: token}, [%Event{name: :token_issued}]} =
               Token.issue(config, request)

      assert is_binary(token)
    end
  end
end
