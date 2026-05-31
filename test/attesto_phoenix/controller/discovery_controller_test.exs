defmodule AttestoPhoenix.Controller.DiscoveryControllerTest do
  use ExUnit.Case, async: true

  import Plug.Test
  import Plug.Conn

  alias Attesto.Config, as: ProtocolConfig
  alias Attesto.PrincipalKind
  alias AttestoPhoenix.Config
  alias AttestoPhoenix.Controller.DiscoveryController

  @issuer "https://issuer.example"

  # A keystore module reference is all Attesto.Config validation requires
  # (it checks the value is a module, not that it implements anything).
  defmodule StubKeystore do
    @moduledoc false
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

  defp decode_body(conn), do: Jason.decode!(conn.resp_body)

  describe "show/2" do
    test "renders the RFC 8414 protocol members as JSON" do
      conn = call_show(host_config(), protocol_config())
      body = decode_body(conn)

      assert conn.status == 200
      assert body["issuer"] == @issuer
      assert body["token_endpoint"] == "#{@issuer}/oauth/token"
      assert body["jwks_uri"] == "#{@issuer}/.well-known/jwks.json"
      assert "code" in body["response_types_supported"]
      assert body["response_modes_supported"] == ["query"]
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

  defmodule StubRepo do
    @moduledoc false
  end
end
