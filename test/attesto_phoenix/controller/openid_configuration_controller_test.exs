defmodule AttestoPhoenix.Controller.OpenIDConfigurationControllerTest do
  use ExUnit.Case, async: true

  import Plug.Test
  import Plug.Conn

  alias Attesto.Config, as: ProtocolConfig
  alias Attesto.PrincipalKind
  alias Attesto.RequestObject.Policy
  alias AttestoPhoenix.Config
  alias AttestoPhoenix.Controller.OpenIDConfigurationController

  @issuer "https://issuer.example"
  @authorization_endpoint "https://issuer.example/authorize"
  @userinfo_endpoint "https://issuer.example/userinfo"

  # A keystore module reference is all Attesto.Config validation requires
  # (it checks the value is a module, not that it implements anything).
  defmodule StubKeystore do
    @moduledoc false
  end

  # Build the host-facing AttestoPhoenix.Config. Only the members the OpenID
  # Provider Metadata document sources from it are varied by the tests.
  defp host_config(overrides \\ []) do
    Config.new(
      Keyword.merge(
        [
          issuer: @issuer,
          keystore: StubKeystore,
          repo: __MODULE__.StubRepo,
          load_client: fn _ -> {:error, :not_found} end,
          verify_client_secret: fn _, _ -> false end,
          load_principal: fn _ -> {:error, :not_found} end,
          authorization_endpoint: @authorization_endpoint,
          userinfo_endpoint: @userinfo_endpoint,
          scopes_supported: ["profile", "email"],
          claims_supported: ["sub", "name", "email"]
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
    conn(:get, "/.well-known/openid-configuration")
    |> put_private(:attesto_phoenix_config, host)
    |> put_private(:attesto_protocol_config, protocol)
    |> OpenIDConfigurationController.show(%{})
  end

  defp decode_body(conn), do: JSON.decode!(conn.resp_body)

  describe "show/2" do
    test "renders the required OIDC Provider Metadata fields as JSON" do
      conn = call_show(host_config(), protocol_config())
      body = decode_body(conn)

      assert conn.status == 200

      # Shared OAuth members (OpenID Connect Discovery §3 / RFC 8414).
      assert body["issuer"] == @issuer
      assert body["token_endpoint"] == "#{@issuer}/oauth/token"
      assert body["jwks_uri"] == "#{@issuer}/.well-known/jwks.json"
      assert "code" in body["response_types_supported"]

      # OIDC-required members fixed by protocol (OpenID Connect Discovery §3,
      # OpenID Connect Core §15.1 / §5.6).
      assert body["subject_types_supported"] == ["public"]
      assert body["id_token_signing_alg_values_supported"] == ["RS256"]
      assert body["claim_types_supported"] == ["normal"]

      # Host-owned endpoints sourced from AttestoPhoenix.Config (RFC 6749 §3.1,
      # OpenID Connect Core §5.3).
      assert body["authorization_endpoint"] == @authorization_endpoint
      assert body["userinfo_endpoint"] == @userinfo_endpoint
    end

    test "scopes_supported includes the reserved openid scope (OIDC Core §3.1.2.1)" do
      body = call_show(host_config(), protocol_config()) |> decode_body()

      assert "openid" in body["scopes_supported"]
      assert "profile" in body["scopes_supported"]
      assert "email" in body["scopes_supported"]
    end

    test "advertises the configured claims catalog (OIDC Discovery §3)" do
      body = call_show(host_config(), protocol_config()) |> decode_body()

      assert body["claims_supported"] == ["sub", "name", "email"]
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

      assert body["token_endpoint_auth_methods_supported"] ==
               ["client_secret_basic", "client_secret_post", "private_key_jwt", "none"]
    end

    test "advertises the query and JARM response modes (JARM §2.3 / §5.4)" do
      body = call_show(host_config(), protocol_config()) |> decode_body()

      assert body["response_modes_supported"] ==
               ["query", "jwt", "query.jwt", "fragment.jwt", "form_post.jwt"]
    end

    test "advertises authorization_signing_alg_values_supported matching the ID Token algs" do
      # JARM responses are signed with the same key as ID Tokens.
      body = call_show(host_config(), protocol_config()) |> decode_body()

      assert body["authorization_signing_alg_values_supported"] ==
               body["id_token_signing_alg_values_supported"]
    end

    test "advertises the introspection endpoint, its auth methods, and signing algs (RFC 7662 / 9701)" do
      body = call_show(host_config(), protocol_config()) |> decode_body()

      assert body["introspection_endpoint"] == "#{@issuer}/oauth/introspect"
      methods = body["introspection_endpoint_auth_methods_supported"]
      assert is_list(methods)
      refute "none" in methods

      assert body["introspection_signing_alg_values_supported"] ==
               body["id_token_signing_alg_values_supported"]
    end

    test "advertises configured token endpoint auth methods" do
      host = host_config(token_endpoint_auth_methods_supported: ["private_key_jwt"])

      body = call_show(host, protocol_config()) |> decode_body()

      assert body["token_endpoint_auth_methods_supported"] == ["private_key_jwt"]
    end

    test "advertises when pushed authorization requests are required" do
      host = host_config(require_pushed_authorization_requests: true)

      body = call_show(host, protocol_config()) |> decode_body()

      assert body["require_pushed_authorization_requests"] == true
    end

    test "advertises request_parameter_supported=true when the host can resolve client JWKS" do
      # JAR support exists only when a client's trusted JWKS is resolvable
      # (a :client_jwks callback here), so discovery tracks actual capability.
      host = host_config(client_jwks: fn _client -> %{"keys" => []} end)
      body = call_show(host, protocol_config()) |> decode_body()

      assert body["request_parameter_supported"] == true
    end

    test "advertises request_parameter_supported=false without request-object capability" do
      # No :client_jwks (and no :client_store) means no client can use a signed
      # request object, so the OP must not advertise JAR support it cannot honour.
      body = call_show(host_config(), protocol_config()) |> decode_body()

      assert body["request_parameter_supported"] == false
    end

    test "advertises request_uri_parameter_supported=false (OIDC Discovery §3 / Core §6.2)" do
      body = call_show(host_config(), protocol_config()) |> decode_body()

      assert body["request_uri_parameter_supported"] == false
    end

    test "advertises request_object_signing_alg_values_supported when JAR is supported (RFC 9101 §10.5)" do
      # Default policy leaves accepted_algs unset, so the verifier default
      # (PS256, ES256, EdDSA) is advertised - but only when request objects are
      # actually supported.
      host = host_config(client_jwks: fn _client -> %{"keys" => []} end)
      body = call_show(host, protocol_config()) |> decode_body()

      assert body["request_object_signing_alg_values_supported"] == ["PS256", "ES256", "EdDSA"]
    end

    test "omits request_object_signing_alg_values_supported without request-object capability" do
      body = call_show(host_config(), protocol_config()) |> decode_body()

      refute Map.has_key?(body, "request_object_signing_alg_values_supported")
    end

    test "omits require_signed_request_object under the default policy (RFC 9101 §10.5)" do
      body = call_show(host_config(), protocol_config()) |> decode_body()

      refute Map.has_key?(body, "require_signed_request_object")
    end

    test "advertises require_signed_request_object=true under the FAPI Message Signing policy" do
      body =
        call_show(
          host_config(request_object_policy: Policy.fapi_message_signing()),
          protocol_config()
        )
        |> decode_body()

      assert body["require_signed_request_object"] == true
    end

    test "advertises claims_parameter_supported=false by default (OIDC Discovery §3)" do
      body = call_show(host_config(), protocol_config()) |> decode_body()

      assert body["claims_parameter_supported"] == false
    end

    test "advertises claims_parameter_supported=true when the host enables it (OIDC Core §5.5)" do
      body =
        call_show(host_config(claims_parameter_supported: true), protocol_config())
        |> decode_body()

      assert body["claims_parameter_supported"] == true
    end

    test "advertises acr_values_supported only when the host configures them (OIDC Discovery §3)" do
      default = call_show(host_config(), protocol_config()) |> decode_body()
      refute Map.has_key?(default, "acr_values_supported")

      configured =
        call_show(
          host_config(acr_values_supported: ["urn:mace:incommon:iap:silver", "phr"]),
          protocol_config()
        )
        |> decode_body()

      assert configured["acr_values_supported"] ==
               ["urn:mace:incommon:iap:silver", "phr"]
    end

    test "advertises ui_locales_supported only when the host configures them (OIDC Discovery §3)" do
      default = call_show(host_config(), protocol_config()) |> decode_body()
      refute Map.has_key?(default, "ui_locales_supported")

      configured =
        call_show(host_config(ui_locales_supported: ["en-US", "de-DE"]), protocol_config())
        |> decode_body()

      assert configured["ui_locales_supported"] == ["en-US", "de-DE"]
    end

    test "synthesises an openid-only scope catalog when none are configured (OIDC Core §3.1.2.1)" do
      body = call_show(host_config(scopes_supported: []), protocol_config()) |> decode_body()

      # An OpenID Provider MUST support the openid scope, so the core builder
      # advertises it even when the host configures no other scopes.
      assert body["scopes_supported"] == ["openid"]
    end

    test "omits authorization_endpoint when the host does not supply one" do
      body =
        call_show(host_config(authorization_endpoint: nil), protocol_config()) |> decode_body()

      refute Map.has_key?(body, "authorization_endpoint")
    end

    test "omits userinfo_endpoint when the host does not supply one" do
      body = call_show(host_config(userinfo_endpoint: nil), protocol_config()) |> decode_body()

      refute Map.has_key?(body, "userinfo_endpoint")
    end

    test "omits claims_supported when none are configured" do
      body = call_show(host_config(claims_supported: []), protocol_config()) |> decode_body()

      refute Map.has_key?(body, "claims_supported")
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

    test "advertises endpoint URLs under a custom :oauth_path_prefix" do
      host =
        host_config(
          oauth_path_prefix: "/mcp/oauth",
          registration_enabled: true,
          register_client: fn _ -> {:error, :unsupported} end
        )

      body = call_show(host, protocol_config()) |> decode_body()

      assert body["revocation_endpoint"] == "#{@issuer}/mcp/oauth/revoke"
      assert body["pushed_authorization_request_endpoint"] == "#{@issuer}/mcp/oauth/par"
      assert body["registration_endpoint"] == "#{@issuer}/mcp/oauth/register"
      # authorization_endpoint / userinfo_endpoint stay host-supplied and are
      # not relocated by the prefix.
      assert body["authorization_endpoint"] == @authorization_endpoint
      assert body["userinfo_endpoint"] == @userinfo_endpoint
      assert body["jwks_uri"] == "#{@issuer}/.well-known/jwks.json"
    end

    test "marks the response publicly cacheable (OIDC Discovery §4)" do
      conn = call_show(host_config(), protocol_config())

      assert get_resp_header(conn, "cache-control") == ["public, max-age=3600"]
    end

    test "fails closed when the host config is not installed on the conn" do
      conn =
        conn(:get, "/.well-known/openid-configuration")
        |> put_private(:attesto_protocol_config, protocol_config())

      assert_raise RuntimeError, fn -> OpenIDConfigurationController.show(conn, %{}) end
    end

    test "fails closed when the protocol config is not installed on the conn" do
      conn =
        conn(:get, "/.well-known/openid-configuration")
        |> put_private(:attesto_phoenix_config, host_config())

      assert_raise RuntimeError, fn -> OpenIDConfigurationController.show(conn, %{}) end
    end
  end

  defmodule StubRepo do
    @moduledoc false
  end
end
