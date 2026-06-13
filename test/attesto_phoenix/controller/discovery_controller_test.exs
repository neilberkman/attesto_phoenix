defmodule AttestoPhoenix.Controller.DiscoveryControllerTest do
  use ExUnit.Case, async: true

  import Plug.Conn
  import Plug.Test

  alias Attesto.Config, as: ProtocolConfig
  alias Attesto.PrincipalKind
  alias Attesto.RequestObject.Policy
  alias AttestoPhoenix.Config
  alias AttestoPhoenix.Controller.DiscoveryController

  @issuer "https://issuer.example"

  # A keystore module reference is all Attesto.Config validation requires
  # (it checks the value is a module, not that it implements anything).
  defmodule StubKeystore do
    @moduledoc false
    @behaviour Attesto.Keystore

    @pem JOSE.JWK.generate_key({:rsa, 2048}) |> JOSE.JWK.to_pem() |> elem(1)

    @impl true
    def signing_pem, do: @pem

    @impl true
    def verification_pems, do: [@pem]
  end

  # Build the host-facing AttestoPhoenix.Config. Only the members the
  # discovery document sources from it are varied by the tests.
  defp host_config(overrides \\ []) do
    Config.new(
      Keyword.merge(
        [
          issuer: @issuer,
          keystore: StubKeystore,
          repo: __MODULE__.StubRepo,
          load_client: fn _ -> {:error, :not_found} end,
          verify_client_secret: fn _, _ -> false end,
          load_principal: fn _ -> {:error, :not_found} end
        ],
        overrides
      )
    )
  end

  # Build the protocol-level Attesto.Config the core metadata builder reads.
  # principal_kinds is legitimate test-owned policy.
  defp protocol_config do
    ProtocolConfig.new(
      issuer: @issuer,
      audience: @issuer,
      keystore: StubKeystore,
      principal_kinds: [
        PrincipalKind.new("client", "oc_", required_claims: [{"client_id", :non_empty_string}])
      ]
    )
  end

  # Invoke the controller action directly with both configs placed where the
  # action expects them, mirroring what a router pipeline installs.
  defp call_show(host, protocol) do
    conn(:get, "/.well-known/oauth-authorization-server")
    |> put_private(:attesto_phoenix_config, host)
    |> put_private(:attesto_protocol_config, protocol)
    |> DiscoveryController.show(%{})
  end

  defp decode_body(conn), do: JSON.decode!(conn.resp_body)

  describe "show/2" do
    test "renders the RFC 8414 protocol members as JSON" do
      conn = call_show(host_config(), protocol_config())
      body = decode_body(conn)

      assert conn.status == 200
      assert body["issuer"] == @issuer
      assert body["token_endpoint"] == "#{@issuer}/oauth/token"
      assert body["jwks_uri"] == "#{@issuer}/.well-known/jwks.json"
      assert "code" in body["response_types_supported"]

      assert body["response_modes_supported"] ==
               ["query", "jwt", "query.jwt", "fragment.jwt", "form_post.jwt"]
    end

    test "advertises the JARM authorization signing algorithms (RFC 8414 / §5.4)" do
      body = call_show(host_config(), protocol_config()) |> decode_body()

      # Same key as ID Tokens; the test keystore is RSA, so RS256.
      assert body["authorization_signing_alg_values_supported"] == ["RS256"]
    end

    test "advertises the introspection endpoint, auth methods, and signing algs (RFC 7662 / 9701)" do
      body = call_show(host_config(), protocol_config()) |> decode_body()

      assert body["introspection_endpoint"] == "#{@issuer}/oauth/introspect"
      methods = body["introspection_endpoint_auth_methods_supported"]
      assert is_list(methods)
      refute "none" in methods
      assert body["introspection_signing_alg_values_supported"] == ["RS256"]
    end

    test "advertises S256 as the only code challenge method (RFC 7636)" do
      body = call_show(host_config(), protocol_config()) |> decode_body()

      assert body["code_challenge_methods_supported"] == ["S256"]
    end

    test "advertises the DPoP signing algorithms (RFC 9449)" do
      body = call_show(host_config(), protocol_config()) |> decode_body()

      assert body["dpop_signing_alg_values_supported"] == Attesto.DPoP.allowed_algs()
    end

    test "advertises only the grant types the token endpoint dispatches (RFC 6749)" do
      body = call_show(host_config(), protocol_config()) |> decode_body()

      assert body["grant_types_supported"] ==
               [
                 "authorization_code",
                 "refresh_token",
                 "client_credentials",
                 "urn:ietf:params:oauth:grant-type:token-exchange"
               ]
    end

    test "advertises only the client-auth methods the token endpoint accepts (RFC 8414)" do
      body = call_show(host_config(), protocol_config()) |> decode_body()

      # The token endpoint reads a secret from HTTP Basic (client_secret_basic)
      # or the request body (client_secret_post), accepts private_key_jwt, and
      # admits a public client presenting only a client_id and relying on PKCE
      # (none).
      assert body["token_endpoint_auth_methods_supported"] ==
               ["client_secret_basic", "client_secret_post", "private_key_jwt", "none"]
    end

    test "advertises configured token endpoint auth methods" do
      host = host_config(token_endpoint_auth_methods_supported: ["private_key_jwt"])

      body = call_show(host, protocol_config()) |> decode_body()

      assert body["token_endpoint_auth_methods_supported"] == ["private_key_jwt"]
    end

    test "advertises private_key_jwt signing algorithms for client assertions" do
      body = call_show(host_config(), protocol_config()) |> decode_body()

      assert body["token_endpoint_auth_signing_alg_values_supported"] ==
               Attesto.SigningAlg.fapi_algs()
    end

    test "advertised signing algorithms reflect a configured :client_auth_signing_algs" do
      # The advertised metadata and the verification policy read the same Config
      # value, so they cannot drift: configuring the set changes discovery too.
      algs = ["PS256", "ES256", "RS256"]

      body =
        call_show(host_config(client_auth_signing_algs: algs), protocol_config()) |> decode_body()

      assert body["token_endpoint_auth_signing_alg_values_supported"] == algs
    end

    test "advertises RFC 9207 authorization response iss support when enabled" do
      host = host_config(authorization_response_iss: true)

      body = call_show(host, protocol_config()) |> decode_body()

      assert body["authorization_response_iss_parameter_supported"] == true
    end

    test "omits RFC 9207 authorization response iss support when disabled" do
      body =
        call_show(host_config(authorization_response_iss: false), protocol_config())
        |> decode_body()

      refute Map.has_key?(body, "authorization_response_iss_parameter_supported")
    end

    test "advertises when pushed authorization requests are required" do
      host = host_config(require_pushed_authorization_requests: true)

      body = call_show(host, protocol_config()) |> decode_body()

      assert body["require_pushed_authorization_requests"] == true
    end

    test "advertises configured scopes" do
      body =
        call_show(host_config(scopes_supported: ["read", "write"]), protocol_config())
        |> decode_body()

      assert body["scopes_supported"] == ["read", "write"]
    end

    test "omits scopes_supported when none are configured" do
      body = call_show(host_config(scopes_supported: []), protocol_config()) |> decode_body()

      refute Map.has_key?(body, "scopes_supported")
    end

    test "omits registration_endpoint when dynamic registration is disabled" do
      body =
        call_show(host_config(registration_enabled: false), protocol_config())
        |> decode_body()

      refute Map.has_key?(body, "registration_endpoint")
    end

    test "advertises registration_endpoint when enabled (RFC 7591)" do
      host =
        host_config(
          registration_enabled: true,
          register_client: fn _ -> {:error, :unsupported} end
        )

      body = call_show(host, protocol_config()) |> decode_body()

      assert body["registration_endpoint"] == "#{@issuer}/oauth/register"
    end

    test "advertises endpoint URLs under a custom :oauth_path_prefix (RFC 8414 §2)" do
      host =
        host_config(
          oauth_path_prefix: "/mcp/oauth",
          registration_enabled: true,
          register_client: fn _ -> {:error, :unsupported} end
        )

      body = call_show(host, protocol_config()) |> decode_body()

      # token_endpoint comes from the core builder; this test passes the host
      # config's resolved token path into the protocol config the same way
      # to_attesto_config/2 does in production.
      assert body["pushed_authorization_request_endpoint"] == "#{@issuer}/mcp/oauth/par"
      assert body["registration_endpoint"] == "#{@issuer}/mcp/oauth/register"
      # The well-known JWKS document is anchored at the host root (RFC 8615) and
      # is NOT relocated by the prefix.
      assert body["jwks_uri"] == "#{@issuer}/.well-known/jwks.json"
    end

    test "an explicit per-endpoint override wins over :oauth_path_prefix" do
      host =
        host_config(
          oauth_path_prefix: "/mcp/oauth",
          par_path: "/custom/par",
          registration_enabled: true,
          register_client: fn _ -> {:error, :unsupported} end
        )

      body = call_show(host, protocol_config()) |> decode_body()

      assert body["pushed_authorization_request_endpoint"] == "#{@issuer}/custom/par"
      # The unoverridden endpoint still follows the prefix.
      assert body["registration_endpoint"] == "#{@issuer}/mcp/oauth/register"
    end

    test "marks the response publicly cacheable (RFC 8414 §3)" do
      conn = call_show(host_config(), protocol_config())

      assert get_resp_header(conn, "cache-control") == ["public, max-age=3600"]
    end

    test "fails closed when the host config is not installed on the conn" do
      conn =
        conn(:get, "/.well-known/oauth-authorization-server")
        |> put_private(:attesto_protocol_config, protocol_config())

      assert_raise RuntimeError, fn -> DiscoveryController.show(conn, %{}) end
    end

    test "fails closed when the protocol config is not installed on the conn" do
      conn =
        conn(:get, "/.well-known/oauth-authorization-server")
        |> put_private(:attesto_phoenix_config, host_config())

      assert_raise RuntimeError, fn -> DiscoveryController.show(conn, %{}) end
    end
  end

  describe "show/2 signed request object metadata (RFC 9101 §10.5)" do
    test "advertises request_object_signing_alg_values_supported when JAR is supported" do
      # OAuth AS metadata (RFC 8414) carries the same JAR metadata as the OpenID
      # Provider document, so a FAPI client reading either sees identical support.
      host = host_config(client_jwks: fn _client -> %{"keys" => []} end)
      body = call_show(host, protocol_config()) |> decode_body()

      assert body["request_object_signing_alg_values_supported"] == ["PS256", "ES256", "EdDSA"]
    end

    test "omits the JAR metadata without request-object capability" do
      body = call_show(host_config(), protocol_config()) |> decode_body()

      refute Map.has_key?(body, "request_object_signing_alg_values_supported")
      refute Map.has_key?(body, "require_signed_request_object")
    end

    test "advertises require_signed_request_object=true under the FAPI Message Signing policy" do
      host =
        host_config(
          request_object_policy: Policy.fapi_message_signing(),
          client_jwks: fn _client -> %{"keys" => []} end
        )

      body = call_show(host, protocol_config()) |> decode_body()

      assert body["require_signed_request_object"] == true
      assert body["request_object_signing_alg_values_supported"] == ["PS256", "ES256", "EdDSA"]
    end
  end

  defmodule StubRepo do
    @moduledoc false
  end
end
