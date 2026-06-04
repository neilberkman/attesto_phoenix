defmodule AttestoPhoenix.Controller.UserinfoController do
  @moduledoc """
  OpenID Connect UserInfo endpoint (OpenID Connect Core 1.0 §5.3).

  Returns claims about the authenticated subject as a JSON object. The
  endpoint is a protected resource: the caller presents the access token issued
  during authentication, and the endpoint releases the subject claims the
  token's scopes authorize.

  ## Authentication

  Verification is delegated to the engine's protected-resource verify path,
  `Attesto.Plug.Authenticate`, which this controller runs at the top of its
  action. That plug parses the `Authorization` header (Bearer, RFC 6750 §2.1,
  or DPoP, RFC 9449 §7.1), verifies the access token through `Attesto.Token`,
  and - for a sender-constrained token - enforces the DPoP / mTLS binding,
  honouring `cnf.jkt` / `cnf.x5t#S256`. A DPoP-bound token presented under the
  Bearer scheme is rejected there, not here. On failure the plug halts the conn
  with the RFC 6750 §3 / RFC 9449 §7.1 `WWW-Authenticate` challenge, which this
  controller returns unchanged.

  Per OpenID Connect Core §5.3.1 both `GET` and `POST` are accepted; the host
  router maps both verbs to the `:userinfo` action.

  ## Authorization

  The verified access token MUST carry the `openid` scope (OpenID Connect Core
  §5.3.1). A token without it is answered `403` with `error="insufficient_scope"`
  and the `scope="openid"` auth-param (RFC 6750 §3.1).

  ## Claims

  The scopes on the access token (its `scope` claim, RFC 9068 §2.2.3) gate which
  claims are released (OpenID Connect Core §5.4):

    * `profile` - the OpenID Connect Core §5.4 profile claim set.
    * `email` - `email` and `email_verified`.
    * `address` - the `address` claim (a JSON object, OpenID Connect Core §5.1.1).
    * `phone` - `phone_number` and `phone_number_verified`.

  The host supplies the claim *values* through the `:build_userinfo_claims`
  callback (see `AttestoPhoenix.Config`); this controller keeps only the values
  the granted scopes authorize and always includes `sub` (OpenID Connect Core
  §5.3.2), the stable subject identifier, regardless of scope.

  Beyond the scope-implied set, individual claims requested through the OpenID
  Connect `claims` request parameter's `userinfo` member (OpenID Connect Core
  §5.5) are also released. The authorization endpoint records that parameter on
  the access token (its `claims` claim) at issuance; the verify path surfaces it
  here, and the named claims are added to the release allow-list so a Relying
  Party can obtain a single claim without requesting the whole scope. A claim
  the host's source does not supply is simply omitted (a UserInfo response need
  not contain every requested claim, OpenID Connect Core §5.5). When the
  provider advertises `claims_parameter_supported: false` (the default, see
  `AttestoPhoenix.Config`), the access token carries no `claims` claim and this
  reduces to scope-gated release.

  ## Configuration contract

  Resolved through `AttestoPhoenix.Config` (see that module for the
  authoritative definitions):

    * `:build_userinfo_claims` - the host's claim source (required to mount
      this endpoint).
    * `:issuer`, `:audience`, `:keystore`, `:access_token_ttl` - claim-level
      policy supplied to the engine verify path as an `Attesto.Config`.
    * `:dpop_enabled`, `:dpop_nonce_required`, `:nonce_store`, `:replay_check`,
      `:cert_der`, `:mtls_enabled`, `:htu` - sender-constraint policy and
      stores, threaded into `Attesto.Plug.Authenticate`.
  """

  use Phoenix.Controller, formats: [:json]

  import Plug.Conn

  alias Attesto.DPoP.ReplayCache
  alias Attesto.Plug.Authenticate
  alias AttestoPhoenix.Callback
  alias AttestoPhoenix.Config
  alias AttestoPhoenix.RequestContext

  # The conn assign `Attesto.Plug.Authenticate` writes the verified claims
  # under (its default `:claims_key`).
  @claims_key :attesto_claims

  # OpenID Connect Core §5.3.1: the UserInfo endpoint requires the `openid`
  # scope (OpenID Connect Core §3.1.2.1).
  @openid_scope "openid"

  # RFC 7234 §5.2 / OpenID Connect Core §5.3.2: the response carries the
  # authenticated subject's claims and must not be cached by an intermediary.
  @cache_control_no_store "no-store"
  @pragma_no_cache "no-cache"

  # OpenID Connect Core §5.4: the scope -> claim-name mapping. `sub` is handled
  # separately (always returned, OpenID Connect Core §5.3.2) and is not listed.
  @scope_claims %{
    "profile" => ~w(
      name family_name given_name middle_name nickname preferred_username
      profile picture website gender birthdate zoneinfo locale updated_at
    ),
    "email" => ~w(email email_verified),
    "address" => ~w(address),
    "phone" => ~w(phone_number phone_number_verified)
  }

  @doc """
  UserInfo action (OpenID Connect Core §5.3). Handles both `GET` and `POST`
  (OpenID Connect Core §5.3.1).

  Named `userinfo` rather than `call` so it does not collide with the
  `Phoenix.Controller` plug entrypoint (`Phoenix.Controller.Pipeline.call/2`)
  that dispatches the action.
  """
  @spec userinfo(Plug.Conn.t(), map()) :: Plug.Conn.t()
  def userinfo(conn, _params) do
    config = resolve_config()

    # Reuse the engine verify path. On failure it halts the conn with the
    # RFC 6750 / RFC 9449 challenge already written; return it unchanged.
    conn = Authenticate.call(conn, authenticate_opts(config))

    cond do
      conn.halted ->
        conn

      access_token_revoked?(config, conn.assigns[@claims_key]) ->
        invalid_token(conn, scheme_of(conn.assigns[@claims_key]))

      true ->
        respond(conn, config)
    end
  end

  defp respond(conn, config) do
    claims = conn.assigns[@claims_key]
    granted_scopes = granted_scopes(claims)

    # OpenID Connect Core §5.3.1: the access token must carry the `openid` scope.
    if @openid_scope in granted_scopes do
      subject = claims["sub"]
      requested_claims = requested_claims(claims)

      userinfo =
        config
        |> Config.build_userinfo_claims(subject, granted_scopes, requested_claims)
        |> shape(granted_scopes, requested_claims)
        # OpenID Connect Core §5.3.2: `sub` is always present and is the
        # verified token subject, never an unverified host-supplied value.
        |> Map.put("sub", subject)

      conn
      |> put_no_store_headers()
      |> json(userinfo)
    else
      insufficient_scope(conn, scheme_of(claims))
    end
  end

  # OpenID Connect Core §5.4 / §5.5: keep the claims the granted scopes
  # authorize (§5.4) plus any claims individually requested for the UserInfo
  # response through the `claims` request parameter's `userinfo` member (§5.5),
  # which a Relying Party may use to obtain a claim without requesting the whole
  # scope-implied set. `sub` is added by the caller and is not gated here. A
  # claim the host did not supply is simply absent from the result (a UserInfo
  # response need not contain every requested claim, §5.5).
  defp shape(host_claims, granted_scopes, requested_claims) when is_map(host_claims) do
    allowed =
      granted_scopes
      |> Enum.flat_map(fn scope -> Map.get(@scope_claims, scope, []) end)
      |> Enum.concat(individually_requested_claim_names(requested_claims))
      |> MapSet.new()

    Map.take(host_claims, MapSet.to_list(allowed))
  end

  # OpenID Connect Core §5.5: the `claims` parameter is a JSON object whose
  # `userinfo` member names the claims to return from the UserInfo endpoint,
  # each mapped to `null` (default) or a request specification object. Only the
  # member names matter for release; the specification values are the host's to
  # honour. A missing or malformed `userinfo` member names nothing.
  defp individually_requested_claim_names(%{"userinfo" => userinfo}) when is_map(userinfo) do
    Map.keys(userinfo)
  end

  defp individually_requested_claim_names(_requested), do: []

  # RFC 9068 §2.2.3: the access token's `scope` claim is a space-delimited
  # string. An absent or malformed claim grants nothing.
  defp granted_scopes(%{"scope" => scope}) when is_binary(scope) do
    String.split(scope, ~r/\s+/, trim: true)
  end

  defp granted_scopes(_claims), do: []

  # OpenID Connect Core §5.5: individual claims are requested through the
  # `claims` request parameter, which the host may record on the access token.
  # Absent that, no individual claims are requested.
  defp requested_claims(%{"claims" => requested}) when is_map(requested), do: requested
  defp requested_claims(_claims), do: %{}

  # RFC 9449 §7.1: a DPoP-bound token (carrying `cnf.jkt`) gets a `DPoP`
  # challenge so the error scheme matches how the client authenticated; a
  # bearer or mTLS-bound token gets `Bearer`.
  defp scheme_of(%{"cnf" => %{"jkt" => jkt}}) when is_binary(jkt), do: :dpop
  defp scheme_of(_claims), do: :bearer

  defp access_token_revoked?(%Config{code_store: store}, %{"jti" => jti})
       when is_atom(store) and is_binary(jti) do
    function_exported?(store, :access_token_revoked?, 1) and store.access_token_revoked?(jti)
  end

  defp access_token_revoked?(_config, _claims), do: false

  defp invalid_token(conn, scheme) do
    challenge =
      challenge(scheme, [
        {"error", "invalid_token"}
      ])

    conn
    |> put_no_store_headers()
    |> put_resp_header("www-authenticate", challenge)
    |> put_status(:unauthorized)
    |> json(%{"error" => "invalid_token"})
  end

  # RFC 6750 §3.1: a valid token that lacks the required scope is answered 403
  # `insufficient_scope` with the `scope` auth-param naming what is needed.
  defp insufficient_scope(conn, scheme) do
    challenge =
      challenge(scheme, [
        {"error", "insufficient_scope"},
        {"error_description", "The UserInfo endpoint requires the openid scope."},
        {"scope", @openid_scope}
      ])

    conn
    |> put_no_store_headers()
    |> put_resp_header("www-authenticate", challenge)
    |> put_status(:forbidden)
    |> json(%{
      "error" => "insufficient_scope",
      "error_description" => "The UserInfo endpoint requires the openid scope."
    })
  end

  # RFC 9110 §11.1: `WWW-Authenticate` is `scheme SP #auth-param`; auth-param
  # values are quoted-strings whose `"` / `\` are escaped (RFC 9110 §11.2) so a
  # value cannot break out of the quotes and inject parameters.
  defp challenge(scheme, params) do
    scheme_label(scheme) <>
      " " <> Enum.map_join(params, ", ", fn {k, v} -> ~s(#{k}="#{escape(v)}") end)
  end

  defp scheme_label(:dpop), do: "DPoP"
  defp scheme_label(:bearer), do: "Bearer"

  defp escape(value) do
    value
    |> to_string()
    |> String.replace("\\", "\\\\")
    |> String.replace("\"", "\\\"")
  end

  defp put_no_store_headers(conn) do
    conn
    |> put_resp_header("cache-control", @cache_control_no_store)
    |> put_resp_header("pragma", @pragma_no_cache)
  end

  # ── Engine verify wiring ─────────────────────────────────────────────────

  # Translate the host's `%AttestoPhoenix.Config{}` into the options
  # `Attesto.Plug.Authenticate` consumes. The DPoP replay/nonce/cert wiring
  # mirrors the token endpoint so the userinfo endpoint enforces exactly the
  # same sender-constraint policy on the presented token.
  defp authenticate_opts(config) do
    [config: attesto_config(config), claims_key: @claims_key]
    |> put_optional(:replay_check, replay_check(config))
    |> put_optional(:nonce_check, nonce_check(config))
    |> put_optional(:nonce_issue, nonce_issue(config))
    |> put_optional(:cert_der, cert_der(config))
    # RFC 9449 §4.3: derive the DPoP `htu` the same way every other endpoint
    # does — via RequestContext.canonical_url, which honours a configured
    # `:htu` but otherwise gates `X-Forwarded-*`/Host on the trusted-proxy
    # allowlist (fail closed). Passing the raw `config.htu` (default nil) would
    # let the core plug fall back to the unguarded request Host on this endpoint
    # alone, an inconsistency with the rest of the server.
    |> Keyword.put(:htu, fn conn -> RequestContext.canonical_url(conn, config) end)
  end

  # The `Attesto.Config` consumed by `Attesto.Token`, derived from the same
  # `%AttestoPhoenix.Config{}` and carrying the host's principal-kind policy.
  defp attesto_config(config) do
    Config.to_attesto_config(config, principal_kinds_extra(config))
  end

  defp principal_kinds_extra(%Config{principal_kinds: kinds})
       when is_list(kinds) and kinds != [] do
    [principal_kinds: kinds]
  end

  defp principal_kinds_extra(%Config{principal_kinds: callback}) when not is_nil(callback) do
    case Callback.invoke(callback, []) do
      kinds when is_list(kinds) and kinds != [] -> [principal_kinds: kinds]
      _ -> []
    end
  end

  defp principal_kinds_extra(_config), do: []

  # RFC 9449 §11.1: a DPoP-bound token presented here is verified with replay
  # protection. The host's `:replay_check` is used when set; otherwise the
  # single-node ETS replay cache, matching the token endpoint default.
  defp replay_check(%Config{dpop_enabled: false}), do: nil
  defp replay_check(%Config{replay_check: nil}), do: &ReplayCache.check_and_record/2
  defp replay_check(%Config{replay_check: callback}), do: callback

  # RFC 9449 §8/§9: demand a server-issued nonce only when the host requires it
  # and has wired a nonce store. The callback receives the proof's `nonce`
  # (possibly `nil`) and returns `:ok` only for a currently-valid nonce, else
  # `{:error, :use_dpop_nonce}`; this mirrors the token endpoint exactly.
  defp nonce_check(%Config{dpop_nonce_required: true, nonce_store: store})
       when is_atom(store) and not is_nil(store) do
    fn nonce ->
      if store.valid?(nonce), do: :ok, else: {:error, :use_dpop_nonce}
    end
  end

  defp nonce_check(_config), do: nil

  # RFC 9449 §8: the `use_dpop_nonce` challenge carries a fresh nonce for the
  # client to echo; `Attesto.Plug.Authenticate` requires `:nonce_issue`
  # whenever `:nonce_check` is set.
  defp nonce_issue(%Config{dpop_nonce_required: true, nonce_store: store})
       when is_atom(store) and not is_nil(store) do
    &store.issue/0
  end

  defp nonce_issue(_config), do: nil

  # RFC 8705 §3: the client-certificate DER extractor, supplied only when the
  # host enabled mTLS (its presence is validated by `AttestoPhoenix.Config`).
  defp cert_der(%Config{mtls_enabled: true, cert_der: cert_der}), do: cert_der
  defp cert_der(_config), do: nil

  # ── Configuration resolution ─────────────────────────────────────────────

  # Resolve the validated `%AttestoPhoenix.Config{}` from the host's `:otp_app`
  # configuration, exactly as the other controllers do, so this controller
  # holds no policy of its own.
  defp resolve_config do
    otp_app = Application.get_env(:attesto_phoenix, :otp_app)
    Config.from_otp_app(otp_app, Config)
  end

  defp put_optional(opts, _key, nil), do: opts
  defp put_optional(opts, key, value), do: Keyword.put(opts, key, value)
end
