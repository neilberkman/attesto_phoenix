defmodule AttestoPhoenix.Controller.UserinfoControllerTest do
  @moduledoc """
  Tests for the OpenID Connect UserInfo endpoint (OpenID Connect Core §5.3).

  These exercise the controller-owned framing: reuse of the engine verify path
  (`Attesto.Plug.Authenticate`) for Bearer authentication, the `openid`-scope
  requirement (OpenID Connect Core §5.3.1 / RFC 6750 §3.1), scope-gated claim
  release (OpenID Connect Core §5.4), the always-present `sub` (OpenID Connect
  Core §5.3.2), and GET/POST acceptance (OpenID Connect Core §5.3.1).

  Tokens are minted with the real `Attesto.Token` so the verify path runs end
  to end; host policy is a real `%AttestoPhoenix.Config{}` resolved from the
  application environment, exactly as a deployment supplies it.
  """
  use ExUnit.Case, async: false

  import Plug.Conn
  import Plug.Test

  alias Attesto.Token
  alias AttestoPhoenix.Controller.UserinfoController

  @endpoint_path "/oauth/userinfo"
  @issuer "https://issuer.example"
  # The subject must begin with the `:user` principal kind's `sub_prefix`
  # (`"ou_"`), or `Attesto.Token.mint/3` rejects it with `:invalid_sub`.
  @subject "ou_user-123"

  # A throwaway RSA keypair for this module, stashed in the application env so
  # the inline keystore reads it without committed key material.
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

  defmodule RevokedTokenStore do
    @moduledoc false

    def access_token_revoked?(jti), do: jti == Process.get(:attesto_phoenix_revoked_jti)
  end

  # One principal kind so `Attesto.Token.mint/3` has a kind to issue under.
  @user_kind Attesto.PrincipalKind.new("user", "ou_", required_claims: [{"client_id", :non_empty_string}])

  # The host's claim source. Returns a full profile/email/address/phone claim
  # set keyed by string claim name; the controller shapes it against the
  # granted scopes (OpenID Connect Core §5.4).
  @host_claims %{
    "name" => "Ada Lovelace",
    "given_name" => "Ada",
    "family_name" => "Lovelace",
    "preferred_username" => "ada",
    "email" => "ada@example.com",
    "email_verified" => true,
    "address" => %{"locality" => "London", "country" => "GB"},
    "phone_number" => "+15551234567",
    "phone_number_verified" => false,
    # A value with no authorizing scope: never released.
    "unscoped_secret" => "nope"
  }

  setup do
    Application.put_env(:attesto_phoenix, __MODULE__.Keystore, signing_pem: @signing_pem)
    on_exit(fn -> Application.delete_env(:attesto_phoenix, __MODULE__.Keystore) end)

    base = [
      issuer: @issuer,
      audience: @issuer,
      keystore: __MODULE__.Keystore,
      repo: __MODULE__.Repo,
      load_client: fn _ -> {:error, :not_found} end,
      verify_client_secret: fn _, _ -> false end,
      load_principal: fn _ -> {:error, :not_found} end,
      principal_kinds: [@user_kind],
      # The endpoint is exercised over plain Plug.Test conns; the verify path
      # would otherwise refuse a non-HTTPS request.
      require_https: false,
      # The host's UserInfo claim source (OpenID Connect Core §5.3).
      build_userinfo_claims: fn subject, _scopes, _requested ->
        Map.put(@host_claims, "host_saw_subject", subject)
      end
    ]

    put_config(base)
    :ok
  end

  describe "authentication (OpenID Connect Core §5.3 / RFC 6750)" do
    test "returns 401 with a Bearer challenge when no token is presented" do
      conn = get_userinfo(nil)

      assert conn.status == 401
      assert ["Bearer" <> _] = get_resp_header(conn, "www-authenticate")
      assert body(conn)["error"] == "invalid_token"
    end

    test "returns 401 for a malformed token" do
      conn = get_userinfo("not-a-jwt")

      assert conn.status == 401
      assert body(conn)["error"] == "invalid_token"
    end

    test "returns 401 when a previously issued access token has been revoked" do
      :attesto_phoenix
      |> Application.fetch_env!(AttestoPhoenix.Config)
      |> Keyword.put(:code_store, __MODULE__.RevokedTokenStore)
      |> put_config()

      token = mint(scope: "openid")
      Process.put(:attesto_phoenix_revoked_jti, peek_claims(token)["jti"])

      conn = get_userinfo(token)

      assert conn.status == 401
      assert body(conn)["error"] == "invalid_token"
      assert ["Bearer " <> _] = get_resp_header(conn, "www-authenticate")
    end
  end

  describe "scope requirement (OpenID Connect Core §5.3.1 / RFC 6750 §3.1)" do
    test "returns 403 insufficient_scope when the token lacks openid" do
      token = mint(scope: "profile email")
      conn = get_userinfo(token)

      assert conn.status == 403
      assert body(conn)["error"] == "insufficient_scope"

      assert [challenge] = get_resp_header(conn, "www-authenticate")
      assert challenge =~ "Bearer"
      assert challenge =~ ~s(scope="openid")
    end
  end

  describe "claims (OpenID Connect Core §5.3.2 / §5.4)" do
    test "returns only sub for a bare openid token" do
      token = mint(scope: "openid")
      conn = get_userinfo(token)

      assert conn.status == 200
      assert body(conn) == %{"sub" => @subject}
    end

    test "always includes sub set to the verified token subject" do
      token = mint(scope: "openid profile")
      claims = body(get_userinfo(token))

      # sub is the verified token subject, not a host-supplied value.
      assert claims["sub"] == @subject
    end

    test "releases the profile claim set for the profile scope" do
      token = mint(scope: "openid profile")
      claims = body(get_userinfo(token))

      assert claims["name"] == "Ada Lovelace"
      assert claims["given_name"] == "Ada"
      assert claims["preferred_username"] == "ada"
      # Not authorized by profile.
      refute Map.has_key?(claims, "email")
      refute Map.has_key?(claims, "address")
    end

    test "releases email and email_verified for the email scope" do
      token = mint(scope: "openid email")
      claims = body(get_userinfo(token))

      assert claims["email"] == "ada@example.com"
      assert claims["email_verified"] == true
      refute Map.has_key?(claims, "name")
    end

    test "releases address and phone claims for their scopes" do
      token = mint(scope: "openid address phone")
      claims = body(get_userinfo(token))

      assert claims["address"] == %{"locality" => "London", "country" => "GB"}
      assert claims["phone_number"] == "+15551234567"
      assert claims["phone_number_verified"] == false
    end

    test "never releases a claim with no authorizing scope" do
      token = mint(scope: "openid profile email address phone")
      claims = body(get_userinfo(token))

      refute Map.has_key?(claims, "unscoped_secret")
      refute Map.has_key?(claims, "host_saw_subject")
    end

    test "marks the response no-store (RFC 7234 §5.2)" do
      token = mint(scope: "openid")
      conn = get_userinfo(token)

      assert get_resp_header(conn, "cache-control") == ["no-store"]
      assert get_resp_header(conn, "pragma") == ["no-cache"]
    end
  end

  describe "individually requested claims (OpenID Connect Core §5.5)" do
    test "releases a claim named by the claims parameter's userinfo member" do
      # The `email` claim is requested individually even though the `email`
      # scope is not granted; OIDC Core §5.5 says it is returned anyway.
      token = mint(scope: "openid", request_claims: %{"userinfo" => %{"email" => nil}})
      claims = body(get_userinfo(token))

      assert claims["email"] == "ada@example.com"
      # email_verified was NOT individually requested and email scope is absent.
      refute Map.has_key?(claims, "email_verified")
    end

    test "individually requested claims add to, not replace, scope-gated claims" do
      token =
        mint(
          scope: "openid profile",
          request_claims: %{"userinfo" => %{"phone_number" => nil}}
        )

      claims = body(get_userinfo(token))

      # Scope-implied profile claim plus the individually requested phone_number.
      assert claims["name"] == "Ada Lovelace"
      assert claims["phone_number"] == "+15551234567"
    end

    test "omits an individually requested claim the host source does not supply" do
      token =
        mint(scope: "openid", request_claims: %{"userinfo" => %{"does_not_exist" => nil}})

      claims = body(get_userinfo(token))

      # A UserInfo response need not contain every requested claim (OIDC §5.5).
      assert claims == %{"sub" => @subject}
    end

    test "a malformed claims parameter releases nothing beyond scope" do
      token = mint(scope: "openid", request_claims: %{"userinfo" => "not-an-object"})
      claims = body(get_userinfo(token))

      assert claims == %{"sub" => @subject}
    end
  end

  describe "HTTP method (OpenID Connect Core §5.3.1)" do
    test "accepts POST as well as GET" do
      token = mint(scope: "openid profile")

      conn =
        :post
        |> conn(@endpoint_path, %{})
        |> put_req_header("authorization", "Bearer " <> token)
        |> UserinfoController.userinfo(%{})

      assert conn.status == 200
      assert body(conn)["sub"] == @subject
      assert body(conn)["name"] == "Ada Lovelace"
    end
  end

  # ── helpers ──────────────────────────────────────────────────────────────

  # Mint a signed access token carrying the given scope, the subject, and the
  # `client_id` the principal kind requires.
  defp mint(opts) do
    scope = Keyword.fetch!(opts, :scope)

    config =
      Attesto.Config.new(
        issuer: @issuer,
        audience: @issuer,
        keystore: __MODULE__.Keystore,
        principal_kinds: [@user_kind]
      )

    # `Attesto.Token.mint/3` reads the principal with atom keys: `:kind` names
    # the principal kind, `:sub` is the subject (which must start with the
    # kind's `sub_prefix`), `:scopes` is the list of granted scope tokens
    # (joined into the space-delimited `scope` claim), and `:claims` the extra
    # per-kind claims (here the kind's required `client_id`, plus an optional
    # OIDC `claims` request object recorded on the access token at issuance,
    # OpenID Connect Core §5.5).
    extra_claims =
      case Keyword.get(opts, :request_claims) do
        nil -> %{}
        request_claims -> %{"claims" => request_claims}
      end

    principal = %{
      kind: "user",
      sub: @subject,
      scopes: String.split(scope, " ", trim: true),
      claims: Map.put(extra_claims, "client_id", "test-client")
    }

    {:ok, %{access_token: token}} = Token.mint(config, principal)
    token
  end

  defp get_userinfo(token) do
    :get
    |> conn(@endpoint_path)
    |> maybe_authorization(token)
    |> UserinfoController.userinfo(%{})
  end

  defp peek_claims(token) do
    config =
      Attesto.Config.new(
        issuer: @issuer,
        audience: @issuer,
        keystore: __MODULE__.Keystore,
        principal_kinds: [@user_kind]
      )

    {:ok, claims} = Token.peek_signed_claims(config, token)
    claims
  end

  defp maybe_authorization(conn, nil), do: conn

  defp maybe_authorization(conn, token), do: put_req_header(conn, "authorization", "Bearer " <> token)

  defp put_config(opts) do
    Application.put_env(:attesto_phoenix, :otp_app, :attesto_phoenix)
    Application.put_env(:attesto_phoenix, AttestoPhoenix.Config, opts)
    on_exit(fn -> Application.delete_env(:attesto_phoenix, AttestoPhoenix.Config) end)
  end

  defp body(conn), do: JSON.decode!(conn.resp_body)
end
