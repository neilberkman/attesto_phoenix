defmodule AttestoPhoenix.Plug.AuthenticateTest do
  @moduledoc false
  use ExUnit.Case, async: false

  import Plug.Conn
  import Plug.Test

  alias Attesto.DPoP.ReplayCache
  alias Attesto.Token
  alias AttestoPhoenix.Config
  alias AttestoPhoenix.Plug.Authenticate
  alias ReqDPoP.Key, as: DPoPKey

  @issuer "https://issuer.example"
  @subject "ou_user-123"
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

  defmodule CertCallbacks do
    @moduledoc false

    def cert_der(_conn), do: Process.get(:attesto_phoenix_test_cert_der)
  end

  defmodule RevokedTokenStore do
    @moduledoc false

    def access_token_revoked?(jti), do: jti == Process.get(:attesto_phoenix_revoked_jti)
  end

  @user_kind Attesto.PrincipalKind.new("user", "ou_", required_claims: [{"client_id", :non_empty_string}])

  setup do
    Application.put_env(:attesto_phoenix, __MODULE__.Keystore, signing_pem: @signing_pem)
    on_exit(fn -> Application.delete_env(:attesto_phoenix, __MODULE__.Keystore) end)

    config =
      Config.new(
        issuer: @issuer,
        audience: @issuer,
        keystore: __MODULE__.Keystore,
        repo: __MODULE__.Repo,
        load_client: fn _ -> {:error, :not_found} end,
        verify_client_secret: fn _, _ -> false end,
        load_principal: fn subject -> {:ok, %{subject: subject, kind: :user}} end,
        on_event: fn event -> send(self(), {:event, event}) end,
        principal_kinds: [@user_kind],
        require_https: false
      )

    %{config: config}
  end

  test "delegates token verification to core and assigns neutral Phoenix context", %{
    config: config
  } do
    token = mint(config, scope: "openid read:reports")

    conn =
      :get
      |> conn("/reports")
      |> put_req_header("authorization", "Bearer " <> token)
      |> Authenticate.call(Authenticate.init(config: config))

    refute conn.halted
    assert conn.assigns.attesto_claims["sub"] == @subject
    assert conn.assigns.attesto_principal == %{subject: @subject, kind: :user}

    assert conn.assigns.attesto_context == %{
             subject: @subject,
             client_id: "client-1",
             scope: ["openid", "read:reports"],
             claims: conn.assigns.attesto_claims,
             cnf: nil,
             principal: %{subject: @subject, kind: :user}
           }

    assert_receive {:event, %AttestoPhoenix.Event{name: :auth_succeeded, subject: @subject}}
  end

  test "a missing principal is rendered as invalid_token without exposing lookup detail", %{
    config: config
  } do
    config = %{config | load_principal: fn _subject -> {:error, :not_found} end}
    token = mint(config, scope: "openid")

    conn =
      :get
      |> conn("/reports")
      |> put_req_header("authorization", "Bearer " <> token)
      |> Authenticate.call(Authenticate.init(config: config))

    assert conn.halted
    assert conn.status == 401
    assert JSON.decode!(conn.resp_body) == %{"error" => "invalid_token"}
    assert ["Bearer " <> _] = get_resp_header(conn, "www-authenticate")
    assert_receive {:event, %AttestoPhoenix.Event{name: :auth_denied, result: :invalid_token}}
  end

  test "rejects an access token revoked after authorization-code reuse", %{config: config} do
    token = mint(config, scope: "openid")
    Process.put(:attesto_phoenix_revoked_jti, peek_claims(config, token)["jti"])
    config = %{config | code_store: __MODULE__.RevokedTokenStore}

    conn =
      :get
      |> conn("/reports")
      |> put_req_header("authorization", "Bearer " <> token)
      |> Authenticate.call(Authenticate.init(config: config))

    assert conn.halted
    assert conn.status == 401
    assert JSON.decode!(conn.resp_body) == %{"error" => "invalid_token"}
    assert ["Bearer " <> _] = get_resp_header(conn, "www-authenticate")
    assert_receive {:event, %AttestoPhoenix.Event{name: :auth_denied, result: :invalid_token}}
  end

  test "supports custom assign keys", %{config: config} do
    token = mint(config, scope: "read:reports")

    conn =
      :get
      |> conn("/reports")
      |> put_req_header("authorization", "Bearer " <> token)
      |> Authenticate.call(
        Authenticate.init(
          config: config,
          claims_key: :claims,
          principal_key: :principal,
          context_key: :auth_context
        )
      )

    refute conn.halted
    assert conn.assigns.claims["sub"] == @subject
    assert conn.assigns.principal.subject == @subject
    assert conn.assigns.auth_context.scope == ["read:reports"]
  end

  test "enforces the configured HTTPS boundary before verifying credentials", %{config: config} do
    config = %{config | require_https: true}
    token = mint(config, scope: "openid")

    conn =
      :get
      |> conn("/reports")
      |> put_req_header("authorization", "Bearer " <> token)
      |> Authenticate.call(Authenticate.init(config: config))

    assert conn.halted
    assert conn.status == 401
    assert JSON.decode!(conn.resp_body)["error"] == "invalid_token"

    assert_receive {:event, %AttestoPhoenix.Event{name: :auth_denied, result: :insecure_transport}}
  end

  test "uses configured error transport for core verifier failures", %{config: config} do
    config = %{
      config
      | send_error: fn conn, status, body ->
          conn
          |> put_resp_content_type("application/vnd.host-test+json")
          |> send_resp(status, JSON.encode!(%{"error" => body}))
          |> halt()
        end
    }

    conn =
      :get
      |> conn("/reports")
      |> Authenticate.call(Authenticate.init(config: config))

    assert conn.halted
    assert conn.status == 401
    assert JSON.decode!(conn.resp_body)["error"]["error"] == "invalid_token"
    assert ["Bearer " <> _] = get_resp_header(conn, "www-authenticate")
  end

  test "normalizes {module, function} cert_der callbacks before calling core", %{config: config} do
    der = self_signed_cert_der()
    {:ok, thumbprint} = Attesto.MTLS.compute_thumbprint(der)
    Process.put(:attesto_phoenix_test_cert_der, der)

    config = %{config | mtls_enabled: true, cert_der: {__MODULE__.CertCallbacks, :cert_der}}
    token = mint(config, scope: "openid", mtls_cert_thumbprint: thumbprint)

    conn =
      :get
      |> conn("/reports")
      |> put_req_header("authorization", "Bearer " <> token)
      |> Authenticate.call(Authenticate.init(config: config))

    refute conn.halted
    assert conn.assigns.attesto_claims["cnf"]["x5t#S256"] == thumbprint
    assert_receive {:event, %AttestoPhoenix.Event{name: :auth_succeeded, subject: @subject}}
  end

  test "accepts DPoP requests generated by req_dpop", %{config: config} do
    start_supervised!({ReplayCache, []})

    dpop_key = DPoPKey.generate(:es256)
    token = mint(config, scope: "openid read:reports", dpop_jkt: DPoPKey.thumbprint(dpop_key))
    parent = self()

    adapter = fn request ->
      send(parent, {:request, request})
      {request, %Req.Response{status: 204}}
    end

    Req.new(base_url: @issuer, adapter: adapter)
    |> ReqDPoP.attach(key: dpop_key, access_token: token)
    |> Req.get!(url: "/reports", params: [page: "1"])

    assert_receive {:request, req_request}

    conn =
      :get
      |> conn(@issuer <> "/reports?page=1")
      |> put_req_header(
        "authorization",
        req_request |> Req.Request.get_header("authorization") |> List.first()
      )
      |> put_req_header("dpop", req_request |> Req.Request.get_header("dpop") |> List.first())
      |> Authenticate.call(Authenticate.init(config: config))

    refute conn.halted
    assert conn.assigns.attesto_claims["cnf"]["jkt"] == DPoPKey.thumbprint(dpop_key)
    assert conn.assigns.attesto_context.scope == ["openid", "read:reports"]
    assert_receive {:event, %AttestoPhoenix.Event{name: :auth_succeeded, subject: @subject}}
  end

  defp mint(config, opts) do
    attesto_config = Config.to_attesto_config(config, principal_kinds: [@user_kind])

    principal = %{
      kind: "user",
      sub: @subject,
      scopes: String.split(Keyword.fetch!(opts, :scope), " "),
      claims: %{"client_id" => "client-1"}
    }

    mint_opts =
      []
      |> maybe_mint_opt(:mtls_cert_thumbprint, Keyword.get(opts, :mtls_cert_thumbprint))
      |> maybe_mint_opt(:dpop_jkt, Keyword.get(opts, :dpop_jkt))

    {:ok, %{access_token: token}} = Token.mint(attesto_config, principal, mint_opts)
    token
  end

  defp maybe_mint_opt(opts, _key, nil), do: opts
  defp maybe_mint_opt(opts, key, value), do: [{key, value} | opts]

  defp self_signed_cert_der do
    %{cert: der} = :public_key.pkix_test_root_cert(~c"CN=attesto-phoenix-plug-test", [])
    der
  end

  defp peek_claims(config, token) do
    attesto_config = Config.to_attesto_config(config, principal_kinds: [@user_kind])
    {:ok, claims} = Token.peek_signed_claims(attesto_config, token)
    claims
  end
end
