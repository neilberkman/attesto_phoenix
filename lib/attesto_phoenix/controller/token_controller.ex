defmodule AttestoPhoenix.Controller.TokenController do
  @moduledoc """
  OAuth 2.0 token endpoint (RFC 6749 §3.2).

  Handles `POST /oauth/token`. This module owns the HTTP and protocol-framing
  concerns only; every cryptographic and grant-state decision is delegated to
  the `Attesto` core, and every policy decision is delegated to a callback on
  `AttestoPhoenix.Config`. It carries no business-domain logic.

  ## Grant types

    * `authorization_code` (RFC 6749 §4.1.3) with mandatory PKCE (RFC 7636),
      redeemed through `Attesto.AuthorizationCode.redeem/4`.
    * `refresh_token` (RFC 6749 §6) with rotation and reuse detection
      (RFC 6749 §10.4, OAuth 2.0 Security BCP), via
      `Attesto.RefreshToken.rotate/3`.
    * `client_credentials` (RFC 6749 §4.4).
    * OAuth token exchange (RFC 8693) for downscoping a verified subject
      access token.

  ## Client authentication

  Accepts HTTP Basic credentials (RFC 6749 §2.3.1, RFC 7617), request-body
  credentials (RFC 6749 §2.3.1), and `private_key_jwt` assertions (RFC 7523 /
  OIDC Core §9). Presenting more than one client-authentication method is
  rejected (RFC 6749 §2.3). Confidential clients must authenticate; a client
  identified without a secret/assertion is admitted only when the host's
  `:client_public?` callback marks it public, in which case it relies on PKCE
  (RFC 7636) instead. Lookup, secret verification, and client public keys are
  supplied by the host's `:load_client`, `:verify_client_secret`, and
  `:client_jwks` callbacks on `AttestoPhoenix.Config`.

  Revocation is carried by `:load_client` itself: it returns
  `{:error, :revoked}` (or `{:error, :not_found}`) for a client that must not
  authenticate, and both the confidential and public paths fail closed on any
  non-`{:ok, _}` result. There is no separate revocation predicate - the
  single lookup is the revocation gate, so a revoked client is rejected on
  every grant.

  ## Sender-constrained tokens

  Access tokens are signed JWTs minted by `Attesto.Token`. When the
  request carries a DPoP proof (RFC 9449) the access token is bound to the
  proof's JWK thumbprint (`cnf.jkt`); when the client is configured for
  mutual TLS (RFC 8705) it is bound to the certificate thumbprint
  (`cnf.x5t#S256`). DPoP takes precedence when both are presentable
  (RFC 9449 §5). When a fresh DPoP nonce is required (RFC 9449 §8/§9), one is
  issued through the configured nonce store and returned in a `DPoP-Nonce`
  response header alongside a `use_dpop_nonce` error.

  ## Responses

  Success renders the RFC 6749 §5.1 body; failure renders the RFC 6749 §5.2
  error body. Both carry no-store cache headers (RFC 7234 §5.2) so credentials
  are never cached by an intermediary.

  ## Configuration contract

  All host policy is resolved through `AttestoPhoenix.Config`; nothing is
  hardcoded here. This controller reads (see `AttestoPhoenix.Config` for the
  authoritative definitions and defaults):

    * `:load_client`, `:verify_client_secret` - client lookup and
      constant-time secret check.
    * `:authorize_scope` - scope resolution through the `Attesto.Scope`
      algebra.
    * `:nonce_store`, `:cert_der`, `:dpop_enabled`, `:mtls_enabled`,
      `:dpop_nonce_required` - sender-constraint policy and stores.
    * `:on_event` - the optional audit/telemetry hook (via
      `AttestoPhoenix.Event`).
    * `:issuer`, `:audience`, `:keystore`, `:access_token_ttl` - claim-level
      policy, supplied to `Attesto.Token` as an `Attesto.Config` derived by
      `AttestoPhoenix.Config.to_attesto_config/2`.

  Further callbacks are read from the configuration so the host owns the
  client- and grant-shaped pieces this library cannot know generically. They
  are read defensively and fail closed when unset: a missing
  `:client_public?` treats every client as confidential (so no secretless
  authentication), a missing `:client_requires_mtls?` treats no client as
  mTLS-required, and a missing `:build_principal` yields a fail-closed
  `invalid_request` rather than a crash.

    * `:client_public?` - `(client -> boolean)` public/confidential
      discriminator (RFC 6749 §2.1). A client that is not public MUST present
      a secret.
    * `:client_requires_mtls?` - `(client -> boolean)` certificate-binding
      requirement (RFC 8705). A client that requires mTLS and calls without a
      certificate is rejected, not downgraded to Bearer.
    * `:client_id` - `(client -> String.t())` the client's identifier
      (RFC 6749 §2.2).
    * `:build_principal` - `(client, subject, scope -> Attesto principal map)`
      assembling the `Attesto.Token.mint/3` principal.
    * `:issue_refresh_token?` - `(client, granted_scope -> boolean)` gate on
      issuing an initial refresh token from the authorization-code grant
      (RFC 6749 §6). When unset, an initial refresh token is issued iff the
      granted scope contains `offline_access` (OIDC Core §11) and a
      `:refresh_store` is configured.
    * `:code_store` / `:refresh_store` - the `Attesto.CodeStore` /
      `Attesto.RefreshStore` modules backing the stateful grants.
  """

  use Phoenix.Controller, formats: [:json]

  import Plug.Conn

  alias Attesto.{AuthorizationCode, ClientAssertion, IDToken, MTLS, RefreshToken, Token}
  alias Attesto.DPoP.ReplayCache
  alias AttestoPhoenix.{Config, Event, RequestContext}

  require Logger

  # RFC 7234 §5.2: token responses and errors must never be cached.
  @cache_control_no_store "no-store"
  @pragma_no_cache "no-cache"

  # RFC 6749 §5.2 error codes.
  @error_invalid_request "invalid_request"
  @error_invalid_client "invalid_client"
  @error_invalid_grant "invalid_grant"
  @error_invalid_scope "invalid_scope"
  @error_unsupported_grant_type "unsupported_grant_type"
  @grant_token_exchange "urn:ietf:params:oauth:grant-type:token-exchange"
  @subject_token_type_access_token "urn:ietf:params:oauth:token-type:access_token"

  # RFC 9449 §5 / §8 / §9.
  @error_invalid_dpop_proof "invalid_dpop_proof"
  @error_use_dpop_nonce "use_dpop_nonce"
  @dpop_request_header "dpop"
  @dpop_nonce_header "dpop-nonce"

  # RFC 9449 §7.1 / RFC 6750: access-token presentation type.
  @token_type_dpop "DPoP"
  @token_type_bearer "Bearer"

  # RFC 9449 §4.2: the token endpoint is reached by POST, so the proof's `htm`
  # claim must equal this.
  @http_method_post "POST"

  # RFC 7523 / OIDC Core §9: client assertions are short-lived JWTs, but their
  # `jti` still has to be consumed once by the authorization server.
  @client_assertion_max_lifetime 300

  # Generic, non-revealing message for any failure on the client
  # authentication path (RFC 6749 §2.3): an attacker must not be able to tell
  # an unknown client from a wrong secret.
  @client_auth_failed "client authentication failed"

  @doc """
  Token endpoint action (RFC 6749 §3.2).

  Authenticates the client, dispatches on `grant_type`, and renders either the
  RFC 6749 §5.1 success body or an RFC 6749 §5.2 error. Every response carries
  no-store cache headers (RFC 7234 §5.2).
  """
  @spec create(Plug.Conn.t(), map()) :: Plug.Conn.t()
  def create(conn, params) do
    config = resolve_config()
    conn = put_no_store_headers(conn)

    case RequestContext.check_https(conn, config) do
      :ok ->
        create_checked(config, conn, params)

      {:error, :insecure_transport} ->
        # RFC 6749 §3.2 / §10.1: the token endpoint requires TLS.
        render_token_error(
          config,
          conn,
          params,
          nil,
          nil,
          error(@error_invalid_request, "TLS required")
        )
    end
  end

  defp create_checked(config, conn, params) do
    case authenticate_client(config, conn, params) do
      {:ok, client} ->
        create_authenticated(config, conn, params, client)

      {:error, %{} = err} ->
        render_token_error(config, conn, params, nil, nil, err)
    end
  end

  defp create_authenticated(config, conn, params, client) do
    case fetch_grant_type(params) do
      {:ok, grant_type} ->
        create_with_grant_type(config, conn, params, client, grant_type)

      {:error, %{} = err} ->
        render_token_error(config, conn, params, client, nil, err)
    end
  end

  defp create_with_grant_type(config, conn, params, client, grant_type) do
    with :ok <- require_registered_grant_type(config, client, grant_type),
         {:ok, response} <- dispatch(config, conn, client, grant_type, params) do
      conn
      |> put_status(:ok)
      |> json(response)
    else
      {:error, %{} = err} ->
        render_token_error(config, conn, params, client, grant_type, err)
    end
  end

  # ── Configuration resolution ─────────────────────────────────────────────

  # The validated `%AttestoPhoenix.Config{}` is resolved from the host's
  # `:otp_app` configuration (`AttestoPhoenix.Config.from_otp_app/2`), so the
  # controller holds no policy of its own and a deployment supplies everything
  # through application config.
  defp resolve_config do
    otp_app = Application.get_env(:attesto_phoenix, :otp_app)
    Config.from_otp_app(otp_app, Config)
  end

  # The `Attesto.Config` consumed by `Attesto.Token`. Derived from the same
  # `%AttestoPhoenix.Config{}`; the principal-kind declarations are host policy
  # carried alongside the config and passed through as the protocol `extra`.
  defp attesto_config(config) do
    Config.to_attesto_config(config, principal_kinds_extra(config))
  end

  defp principal_kinds_extra(config) do
    case config_callback(config, :principal_kinds) do
      kinds when is_list(kinds) and kinds != [] -> [principal_kinds: kinds]
      callback -> callback |> invoke([]) |> principal_kinds_kw()
    end
  end

  defp principal_kinds_kw(kinds) when is_list(kinds) and kinds != [] do
    [principal_kinds: kinds]
  end

  defp principal_kinds_kw(_other) do
    []
  end

  # ── Client authentication (RFC 6749 §2.3) ────────────────────────────────

  defp authenticate_client(config, conn, params) do
    case fetch_client_credentials(conn, params) do
      {:ok, :none, client_id} ->
        # RFC 6749 §2.1: identified but unauthenticated. Permitted only for
        # public clients, which must compensate with PKCE (RFC 7636).
        with :ok <- require_client_auth_method(config, "none") do
          load_public_client(config, client_id)
        end

      {:ok, :client_secret_basic, client_id, secret} ->
        with :ok <- require_client_auth_method(config, "client_secret_basic") do
          verify_confidential_client(config, client_id, secret)
        end

      {:ok, :client_secret_post, client_id, secret} ->
        with :ok <- require_client_auth_method(config, "client_secret_post") do
          verify_confidential_client(config, client_id, secret)
        end

      {:ok, :private_key_jwt, assertion} ->
        with :ok <- require_client_auth_method(config, "private_key_jwt") do
          verify_private_key_jwt_client(config, assertion)
        end

      {:error, _} = err ->
        err
    end
  end

  # RFC 6749 §2.3: a client MUST NOT use more than one authentication method.
  defp fetch_client_credentials(conn, params) do
    header = get_req_header(conn, "authorization")

    cond do
      assertion_credentials?(params) ->
        fetch_assertion_credentials(header, params)

      basic_credentials?(header) ->
        fetch_basic_credentials(header, params)

      header == [] ->
        fetch_body_credentials(params)

      true ->
        {:error, error(@error_invalid_client, "unsupported client authentication scheme")}
    end
  end

  defp assertion_credentials?(%{"client_assertion" => assertion})
       when is_binary(assertion) and assertion != "",
       do: true

  defp assertion_credentials?(_params), do: false

  defp basic_credentials?(["Basic " <> _]), do: true
  defp basic_credentials?(_header), do: false

  defp fetch_assertion_credentials(header, params) do
    if header != [] or has_body_secret?(params) do
      {:error, error(@error_invalid_request, "multiple client authentication methods")}
    else
      fetch_private_key_jwt_credentials(
        params["client_assertion_type"],
        params["client_assertion"]
      )
    end
  end

  defp fetch_basic_credentials(["Basic " <> _encoded], %{"client_id" => client_id})
       when is_binary(client_id) and client_id != "" do
    {:error, error(@error_invalid_request, "multiple client authentication methods")}
  end

  defp fetch_basic_credentials(["Basic " <> encoded], _params),
    do: decode_basic_credentials(encoded)

  defp fetch_body_credentials(%{"client_id" => client_id} = params)
       when is_binary(client_id) and client_id != "" do
    case params["client_secret"] do
      secret when is_binary(secret) and secret != "" ->
        {:ok, :client_secret_post, client_id, secret}

      _ ->
        {:ok, :none, client_id}
    end
  end

  defp fetch_body_credentials(_params) do
    {:error, error(@error_invalid_client, "client authentication required")}
  end

  # RFC 7617 §2 / RFC 6749 §2.3.1: the userid and password are
  # `application/x-www-form-urlencoded`-encoded, colon-separated, base64.
  defp decode_basic_credentials(encoded) do
    with {:ok, decoded} <- Base.decode64(encoded),
         [client_id, secret] <- String.split(decoded, ":", parts: 2) do
      {:ok, :client_secret_basic, URI.decode_www_form(client_id), URI.decode_www_form(secret)}
    else
      _ -> {:error, error(@error_invalid_client, "malformed Basic authorization header")}
    end
  end

  defp fetch_private_key_jwt_credentials(assertion_type, assertion) do
    if assertion_type == ClientAssertion.assertion_type() do
      {:ok, :private_key_jwt, assertion}
    else
      {:error, error(@error_invalid_client, @client_auth_failed)}
    end
  end

  defp require_client_auth_method(config, method) do
    case Map.get(config, :token_endpoint_auth_methods_supported) do
      methods when is_list(methods) and methods != [] ->
        if method in methods,
          do: :ok,
          else: {:error, error(@error_invalid_client, @client_auth_failed)}

      _ ->
        :ok
    end
  end

  defp has_body_secret?(%{"client_secret" => secret}) when is_binary(secret) and secret != "",
    do: true

  defp has_body_secret?(_params), do: false

  # The `:load_client` callback's contract (see `AttestoPhoenix.Config`)
  # carries both existence and the revocation gate: `{:ok, client}`,
  # `{:error, :not_found}`, or `{:error, :revoked}`. Revocation is therefore
  # checked here without a separate predicate (RFC 7009 semantics for an
  # already-revoked client).
  defp verify_confidential_client(config, client_id, secret) do
    case invoke(config.load_client, [client_id]) do
      {:ok, client} ->
        if invoke(config.verify_client_secret, [client, secret]) == true do
          {:ok, client}
        else
          {:error, error(@error_invalid_client, @client_auth_failed)}
        end

      _other ->
        # RFC 6749 §2.3 / OWASP: do not leak whether the client exists or is
        # revoked. Run a dummy verification so the lookup-failure path matches
        # the wrong-secret path in observable timing, and return one message.
        _ = invoke(config.verify_client_secret, [:unknown_client, secret])
        {:error, error(@error_invalid_client, @client_auth_failed)}
    end
  end

  defp verify_private_key_jwt_client(config, assertion) do
    with {:ok, client_id} <- ClientAssertion.peek_client_id(assertion),
         {:ok, client} <- load_existing_client(config, client_id),
         {:ok, jwks} <- client_jwks(config, client),
         {:ok, claims} <-
           ClientAssertion.verify(assertion, client_id, client_assertion_audiences(config), jwks,
             max_lifetime: @client_assertion_max_lifetime
           ),
         :ok <- consume_client_assertion_jti(config, client_id, claims) do
      {:ok, client}
    else
      _other -> {:error, error(@error_invalid_client, @client_auth_failed)}
    end
  end

  defp client_jwks(config, client) do
    case config_callback(config, :client_jwks) do
      nil ->
        {:error, :missing_client_jwks}

      callback ->
        case invoke(callback, [client]) do
          {:ok, jwks} -> {:ok, jwks}
          jwks when is_map(jwks) or is_list(jwks) -> {:ok, jwks}
          _other -> {:error, :missing_client_jwks}
        end
    end
  end

  defp client_assertion_audiences(config) do
    [config.issuer, Config.token_endpoint_url(config)]
  end

  defp consume_client_assertion_jti(config, client_id, %{"jti" => jti})
       when is_binary(jti) and jti != "" do
    key = client_assertion_replay_key(client_id, jti)

    case invoke(replay_check(config), [key, @client_assertion_max_lifetime]) do
      :ok -> :ok
      _other -> {:error, :assertion_replay}
    end
  end

  defp consume_client_assertion_jti(_config, _client_id, _claims), do: {:error, :missing_jti}

  defp client_assertion_replay_key(client_id, jti) do
    digest = :crypto.hash(:sha256, "#{client_id}\0#{jti}")
    "client_assertion:" <> Base.url_encode64(digest, padding: false)
  end

  defp replay_check(%Config{replay_check: nil}), do: &ReplayCache.check_and_record/2
  defp replay_check(%Config{replay_check: callback}), do: callback

  defp require_registered_grant_type(config, client, grant_type) do
    case client_grant_types(config, client) do
      grant_types when is_list(grant_types) ->
        if grant_type in grant_types do
          :ok
        else
          {:error, error(@error_unsupported_grant_type, "unsupported grant_type: #{grant_type}")}
        end

      _not_configured ->
        :ok
    end
  end

  defp client_grant_types(config, client) do
    invoke_with_default(config_callback(config, :client_grant_types), [client], nil)
  end

  # RFC 6749 §2.1: a client identified without a secret may proceed only if
  # it is a public client. A successful `:load_client` is sufficient
  # identification, but a confidential client MUST authenticate with a
  # secret (RFC 6749 §2.3.1): accepting it secretless would let anyone who
  # knows its `client_id` impersonate it, with no PKCE backstop on
  # client_credentials. The host's `:client_public?` callback is the
  # public/confidential discriminator; it MUST return `true` for the
  # secretless path to be allowed. A public client's security then rests on
  # PKCE (RFC 7636), enforced by `Attesto.AuthorizationCode` when the code
  # is redeemed. A revoked or unknown client - and a confidential client
  # presenting no secret - fails closed with the single generic message.
  defp load_public_client(config, client_id) do
    with {:ok, client} <- load_existing_client(config, client_id),
         true <- client_public?(config, client) do
      {:ok, client}
    else
      _other -> {:error, error(@error_invalid_client, @client_auth_failed)}
    end
  end

  defp load_existing_client(config, client_id) do
    case invoke(config.load_client, [client_id]) do
      {:ok, client} -> {:ok, client}
      _other -> {:error, :not_found}
    end
  end

  # The public/confidential discriminator (RFC 6749 §2.1). Read defensively
  # from the configuration; fail closed (treat as confidential, i.e. not
  # public) when the host has not supplied the callback, so a deployment
  # that forgets it cannot accidentally let confidential clients
  # authenticate without a secret.
  defp client_public?(config, client) do
    invoke_with_default(config_callback(config, :client_public?), [client], false) == true
  end

  # ── Grant dispatch (RFC 6749 §4) ─────────────────────────────────────────

  defp fetch_grant_type(%{"grant_type" => gt}) when is_binary(gt) and gt != "",
    do: {:ok, gt}

  defp fetch_grant_type(_params),
    do: {:error, error(@error_invalid_request, "missing grant_type")}

  # RFC 6749 §4.1.3 + RFC 7636: authorization-code grant. Public clients must
  # present PKCE; confidential clients do too by default, unless the host has
  # explicitly relaxed `:require_pkce` for Basic-profile compatibility.
  defp dispatch(config, conn, client, "authorization_code", params) do
    with {:ok, code} <- require_param(params, "code"),
         {:ok, verifier} <- fetch_code_verifier(config, client, params),
         {:ok, redirect_uri} <- require_param(params, "redirect_uri"),
         {:ok, binding, token_type} <- resolve_sender_constraint(config, conn, client),
         {:ok, grant} <-
           redeem_code(config, client, code, verifier, redirect_uri, binding_jkt(binding)),
         {:ok, scope} <- authorize_scope(config, client, grant.scope),
         {:ok, response} <-
           mint(
             config,
             client,
             grant.subject,
             scope,
             token_type,
             binding,
             access_token_claims(grant)
           ),
         # OIDC Core §3.1.3.3: when the request was an OpenID Connect
         # Authentication Request (granted scope contains `openid`), the token
         # response additionally carries an ID Token.
         {:ok, response} <- maybe_mint_id_token(config, client, grant, scope, code, response) do
      :ok = record_code_access_token(config, grant, response)
      emit(config, conn, :token_issued, client, scope, "authorization_code")
      # RFC 6749 §4.1.4 / §6: optionally issue an initial refresh token so the
      # client can refresh without re-running the authorization flow. The
      # initial token is minted into the code's `family_id` (OAuth 2.0 Security
      # BCP §4.13) so a later replay of the same code, surfaced as
      # `{:error, {:reuse, meta}}` by `Attesto.AuthorizationCode.redeem/4`,
      # carries the `family_id` needed to revoke this exact descendant family.
      maybe_issue_refresh_token(config, conn, client, grant, scope, binding, response)
    end
  end

  # RFC 6749 §6 + §10.4: refresh-token rotation with reuse detection.
  defp dispatch(config, conn, client, "refresh_token", params) do
    with {:ok, presented} <- require_param(params, "refresh_token"),
         requested = parse_requested_scope(params),
         {:ok, binding, token_type} <- resolve_sender_constraint(config, conn, client),
         {:ok, rotated} <-
           rotate_refresh(config, client, presented, requested, binding_jkt(binding)),
         {:ok, scope} <- authorize_scope(config, client, rotated.context.scope),
         {:ok, response} <-
           mint(config, client, rotated.context.subject, scope, token_type, binding) do
      emit(config, conn, :refresh_rotated, client, scope, "refresh_token")
      {:ok, Map.put(response, :refresh_token, rotated.token)}
    end
  end

  # RFC 6749 §4.4: client-credentials grant. No resource owner is involved, so
  # no refresh token is issued (RFC 6749 §4.4.3).
  defp dispatch(config, conn, client, "client_credentials", params) do
    with {:ok, binding, token_type} <- resolve_sender_constraint(config, conn, client),
         subject = client_id(config, client),
         {:ok, scope} <- authorize_scope(config, client, parse_requested_scope(params)),
         {:ok, response} <- mint(config, client, subject, scope, token_type, binding) do
      emit(config, conn, :token_issued, client, scope, "client_credentials")
      {:ok, response}
    end
  end

  # RFC 8693: exchange a valid Attesto access token for a new, host-authorized
  # access token. Scope policy still belongs to `:authorize_scope`; when no
  # `scope` is requested the subject token's existing scope is carried forward.
  defp dispatch(config, conn, client, @grant_token_exchange, params) do
    with {:ok, subject_token} <- require_param(params, "subject_token"),
         :ok <- require_subject_token_type(params),
         {:ok, binding, token_type} <- resolve_sender_constraint(config, conn, client),
         {:ok, claims} <- verify_subject_token(config, subject_token, binding),
         requested = requested_exchange_scope(params, claims),
         {:ok, scope} <- authorize_scope(config, client, requested),
         {:ok, response} <- mint_exchanged_token(config, claims, scope, token_type, binding) do
      emit(config, conn, :token_issued, client, scope, "token_exchange")
      {:ok, Map.put(response, :issued_token_type, @subject_token_type_access_token)}
    else
      {:error, %{} = err} -> {:error, err}
      {:error, _reason} -> {:error, error(@error_invalid_grant, "subject token is invalid")}
    end
  end

  # RFC 6749 §5.2.
  defp dispatch(_config, _conn, _client, grant_type, _params) do
    {:error, error(@error_unsupported_grant_type, "unsupported grant_type: #{grant_type}")}
  end

  # ── Grant-state delegation (Attesto core) ────────────────────────────────

  defp fetch_code_verifier(config, client, params) do
    if client_public?(config, client) or config_flag(config, :require_pkce) do
      require_param(params, "code_verifier")
    else
      {:ok, optional_param(params, "code_verifier")}
    end
  end

  defp redeem_code(config, client, code, verifier, redirect_uri, jkt) do
    params =
      %{
        redirect_uri: redirect_uri,
        client_id: client_id(config, client)
      }
      |> put_optional(:code_verifier, verifier)
      |> put_optional(:dpop_jkt, jkt)

    case AuthorizationCode.redeem(grant_store(config, :code_store), code, params) do
      {:ok, grant} ->
        {:ok, grant}

      # OAuth 2.0 Security BCP §4.13 / RFC 6749 §4.1.2: a re-presented,
      # already-redeemed code is the reuse attack signal. Revoke the
      # descendant refresh-token family recorded at the first redemption
      # (`meta.family_id`) before answering - the captured code and any tokens
      # it spawned are now compromised - then fail closed with the generic
      # `invalid_grant` so the replay learns nothing on the wire.
      {:error, {:reuse, meta}} ->
        revoke_reused_family(config, meta)
        revoke_reused_access_tokens(config, meta)
        {:error, grant_error(:invalid_grant)}

      {:error, reason} ->
        {:error, grant_error(reason)}
    end
  end

  # Revoke the refresh-token family linked to a replayed code (OAuth 2.0
  # Security BCP §4.13.2) through the configured `:refresh_store`. The reuse
  # `meta` carries a `family_id` (not a token), so the family-level
  # `c:Attesto.RefreshStore.revoke_family/1` is the right seam -
  # `Attesto.Revocation` is the per-token entry point and would need a token
  # to look the family up. Reuse detection only fires when a `:code_store`
  # tracks consumption; a deployment that wired no `:refresh_store` has no
  # family to revoke (the grant never minted one), so this is a no-op there,
  # as is an absent/empty `family_id`.
  defp revoke_reused_family(config, meta) do
    if refresh_store = grant_store(config, :refresh_store) do
      case reuse_family_id(meta) do
        family_id when is_binary(family_id) and family_id != "" ->
          :ok = refresh_store.revoke_family(family_id)

        _ ->
          :ok
      end
    end

    :ok
  end

  # The replayed code's first-redemption context is the
  # `Attesto.CodeStore.consumed_meta()` map (always a map per that callback's
  # spec). Read the `:family_id` under both atom and string keys so a store
  # that serialised it either way is honoured; absent it, return nil and the
  # caller treats revocation as a no-op.
  defp reuse_family_id(meta) do
    Map.get(meta, :family_id) || Map.get(meta, "family_id")
  end

  defp revoke_reused_access_tokens(config, meta) do
    store = grant_store(config, :code_store)

    if store && function_exported?(store, :revoke_family_access_tokens, 1) do
      case reuse_family_id(meta) do
        family_id when is_binary(family_id) and family_id != "" ->
          :ok = store.revoke_family_access_tokens(family_id)

        _ ->
          :ok
      end
    end

    :ok
  end

  defp rotate_refresh(config, client, presented, requested, jkt) do
    opts =
      [client_id: client_id(config, client)]
      |> put_optional_kw(:scope, requested)
      |> put_optional_kw(:dpop_jkt, jkt)

    case RefreshToken.rotate(grant_store(config, :refresh_store), presented, opts) do
      {:ok, rotated} -> {:ok, rotated}
      {:error, reason} -> {:error, grant_error(reason)}
    end
  end

  # ── Initial refresh-token issuance (RFC 6749 §4.1.4 / §6) ────────────────

  # RFC 6749 §6: an authorization-code grant MAY return a refresh token. It
  # is host policy whether to do so, so issuance is gated and only happens
  # when:
  #
  #   * a `:refresh_store` is configured (the persistence the refresh grant
  #     needs), and
  #   * the policy permits it: the host's `:issue_refresh_token?` callback
  #     returns `true` for this `(client, scope)`, OR - when the host does
  #     not supply that callback - the granted scope contains the
  #     `offline_access` scope (OIDC Core §11), the standard signal that the
  #     client asked for offline access.
  #
  # The refresh token is bound to the same DPoP key as the access token when
  # the request was DPoP-constrained (RFC 9449), so rotation later requires
  # the matching proof. An mTLS-bound request issues no DPoP binding on the
  # refresh token. The plaintext token is added to the RFC 6749 §5.1 body;
  # only its hash is persisted (see `Attesto.RefreshToken`).
  @offline_access_scope "offline_access"

  defp maybe_issue_refresh_token(config, conn, client, grant, scope, binding, response) do
    if refresh_store = grant_store(config, :refresh_store) do
      if issue_refresh_token?(config, client, scope) do
        issue_initial_refresh_token(
          config,
          conn,
          client,
          grant,
          scope,
          binding,
          refresh_store,
          response
        )
      else
        {:ok, response}
      end
    else
      {:ok, response}
    end
  end

  defp issue_initial_refresh_token(
         config,
         conn,
         client,
         grant,
         scope,
         binding,
         refresh_store,
         response
       ) do
    context =
      %{subject: grant.subject, scope: scope}
      |> put_optional(:client_id, client_id(config, client))
      |> put_optional(:dpop_jkt, binding_jkt(binding))

    # OAuth 2.0 Security BCP §4.13: mint the initial token into the code's
    # `family_id` so the spent code and its descendant tokens share one
    # family. `Attesto.RefreshToken.issue/3` takes `:family_id` as an option
    # (not in the context map) and starts a fresh family only when it is
    # absent; threading the grant's `family_id` here is what lets a later
    # code-reuse `{:reuse, meta}` revoke this exact family (see
    # `revoke_reused_family/2`). When the code carried no `family_id`,
    # `put_optional_kw/3` drops the option, a fresh family is generated, and
    # reuse detection simply has no family to revoke.
    issue_opts =
      [ttl: config.refresh_token_ttl]
      |> put_optional_kw(:family_id, grant.family_id)

    case RefreshToken.issue(refresh_store, context, issue_opts) do
      {:ok, %{token: token}} ->
        emit(config, conn, :refresh_issued, client, scope, "authorization_code")
        {:ok, Map.put(response, :refresh_token, token)}

      {:error, reason} ->
        # Issuance is a server/config fault, not a client error; do not leak
        # detail, and do not hand back an access token whose advertised
        # offline access we then failed to provide.
        Logger.error("refresh token issuance failed: #{inspect(reason)}")
        {:error, error(@error_invalid_request, "unable to issue token")}
    end
  end

  # The issuance gate. Prefer the host's `:issue_refresh_token?` callback;
  # when it is not supplied, fall back to the OIDC `offline_access` scope
  # signal. Read defensively so a host that wires neither simply never gets
  # an initial refresh token (fail-closed: no token rather than a crash).
  defp issue_refresh_token?(config, client, scope) do
    case config_callback(config, :issue_refresh_token?) do
      nil -> @offline_access_scope in scope
      callback -> invoke(callback, [client, scope]) == true
    end
  end

  # ── ID Token issuance (OpenID Connect Core §3.1.3.3) ─────────────────────

  # OIDC Core §3.1.3.3: the token response from an OpenID Connect
  # Authentication Request carries an ID Token in addition to the access
  # token. The trigger is the granted scope containing the `openid` scope
  # value (OIDC Core §3.1.2.1); a non-openid authorization-code grant is a
  # plain OAuth 2.0 response (access token only) and is left untouched.
  @openid_scope "openid"

  defp maybe_mint_id_token(config, client, grant, scope, code, response) do
    if @openid_scope in scope do
      mint_id_token(config, client, grant, scope, code, response)
    else
      {:ok, response}
    end
  end

  # The ID Token's `aud` is the OAuth `client_id` (OIDC Core §2), so a host
  # that does not expose `:client_id` cannot mint a well-addressed identity
  # assertion: fail closed rather than emit one without an audience.
  defp mint_id_token(config, client, grant, scope, code, response) do
    case client_id(config, client) do
      client_id when is_binary(client_id) and client_id != "" ->
        opts = id_token_opts(config, client, grant, scope, code, response)

        case IDToken.mint(attesto_config(config), grant.subject, client_id, opts) do
          {:ok, id_token} ->
            {:ok, Map.put(response, :id_token, id_token)}

          {:error, reason} ->
            # Minting is a server/config fault, not a client error; do not
            # leak detail, and do not hand back an access token whose OpenID
            # Connect contract (an ID Token) we then failed to satisfy.
            Logger.error("id token mint failed: #{inspect(reason)}")
            {:error, error(@error_invalid_request, "unable to issue token")}
        end

      _ ->
        Logger.error("id token mint failed: missing client_id")
        {:error, error(@error_invalid_request, "unable to issue token")}
    end
  end

  # OIDC Core §3.1.3.6 / §3.3.2.11: bind the ID Token to the artifacts of this
  # exchange. The `nonce` from the Authentication Request (OIDC Core §3.1.3.7
  # item 11) and the optional `auth_time`/`acr`/`amr` (OIDC Core §2) ride in
  # the authorization code's `claims`, carried verbatim from the authorization
  # endpoint by `Attesto.AuthorizationCode`. `at_hash` is computed from the
  # access token just minted and `c_hash` from the redeemed code.
  defp id_token_opts(config, client, grant, scope, code, response) do
    # `Attesto.AuthorizationCode` always materialises `:claims` as a map
    # (defaulting to `%{}` at construction), so it is read directly here.
    claims = grant.claims

    [access_token: response.access_token, code: code]
    |> put_optional_kw(:nonce, id_token_claim(claims, "nonce"))
    |> put_optional_kw(:auth_time, id_token_claim(claims, "auth_time"))
    |> put_optional_kw(:acr, id_token_claim(claims, "acr"))
    |> put_optional_kw(:amr, id_token_claim(claims, "amr"))
    # OIDC Core §5.4/§5.5: host userinfo / claims-param-requested claims ride
    # in as `Attesto.IDToken.mint/4`'s `:extra_claims`, where the protocol
    # claims stay authoritative (a collision is rejected, never shadowed).
    |> put_optional_kw(:extra_claims, userinfo_claims(config, client, grant, scope))
  end

  # OIDC Core §5.4 / §5.5: the additional identity claims an ID Token may
  # carry (e.g. `email`, `name`) are the host's to source - this library knows
  # no user store. The host's `:build_userinfo_claims` callback is given the
  # client, the authenticated `subject`, the granted `scope`, and the OIDC
  # `claims` request parameter the authorization endpoint stashed on the code
  # (OIDC Core §5.5, the claims-param-requested claims), and returns a map of
  # extra claims. They ride into `Attesto.IDToken.mint/4` via its `:claims`
  # option, where the standard claims (`iss`/`sub`/`aud`/...) always win, so
  # the host cannot forge protocol claims. Read defensively: a host that wires
  # no callback adds no extra claims (`nil` -> the `:claims` option is dropped
  # by `put_optional_kw/3`), and a callback that does not return a non-empty
  # map is treated the same (fail-closed: no claims rather than a crash or a
  # malformed token).
  defp userinfo_claims(config, client, grant, scope) do
    case config_callback(config, :build_userinfo_claims) do
      nil ->
        nil

      callback ->
        requested = id_token_claim(grant.claims, "claims")

        case invoke(callback, [client, grant.subject, scope, requested]) do
          map when is_map(map) and map_size(map) > 0 -> map
          _ -> nil
        end
    end
  end

  # The authorization code's `claims` is an opaque host map; read each OIDC
  # value under both its string and atom key so a host that stashed it either
  # way is honoured, and treat anything absent as `nil` (the option is then
  # simply not passed to `Attesto.IDToken.mint/4`).
  defp id_token_claim(claims, key) do
    Map.get(claims, key) || Map.get(claims, String.to_existing_atom(key))
  rescue
    ArgumentError -> Map.get(claims, key)
  end

  # ── Scope (RFC 6749 §3.3) ────────────────────────────────────────────────

  # RFC 6749 §3.3: the `scope` parameter is a space-delimited, case-sensitive
  # list of scope tokens. Splitting is pure framing; what the resulting list is
  # allowed to grant is decided by the host's `:authorize_scope` callback.
  defp parse_requested_scope(params) do
    case params["scope"] do
      value when is_binary(value) and value != "" -> String.split(value, " ", trim: true)
      _ -> []
    end
  end

  defp require_subject_token_type(params) do
    case params["subject_token_type"] do
      @subject_token_type_access_token -> :ok
      nil -> {:error, error(@error_invalid_request, "subject_token_type is required")}
      _ -> {:error, error(@error_invalid_request, "subject_token_type is unsupported")}
    end
  end

  defp verify_subject_token(config, token, binding) when binding in [nil, :none] do
    Token.verify(attesto_config(config), token, expected_typ: "access")
  end

  defp verify_subject_token(config, token, {:dpop, jkt}) do
    Token.verify(attesto_config(config), token, expected_typ: "access", dpop_jkt: jkt)
  end

  defp verify_subject_token(config, token, {:mtls, thumb}) do
    Token.verify(attesto_config(config), token,
      expected_typ: "access",
      mtls_cert_thumbprint: thumb
    )
  end

  defp requested_exchange_scope(params, claims) do
    case parse_requested_scope(params) do
      [] -> claims |> Map.get("scope", "") |> String.split(" ", trim: true)
      scopes -> scopes
    end
  end

  # RFC 6749 §3.3: scope resolution is host policy. The documented
  # `:authorize_scope` callback takes the client and the requested scope and
  # returns the granted scope or `{:error, :invalid_scope}` (RFC 6749 §5.2).
  defp authorize_scope(config, client, requested) do
    case invoke(config.authorize_scope, [client, requested]) do
      {:ok, scope} when is_list(scope) -> {:ok, scope}
      {:error, _reason} -> {:error, error(@error_invalid_scope, "scope not permitted")}
      _ -> {:error, error(@error_invalid_request, "scope policy unavailable")}
    end
  end

  # ── Token minting (Attesto.Token) ────────────────────────────────────────

  defp mint(config, client, subject, scope, token_type, binding, extra_claims \\ %{}) do
    with {:ok, principal} <- build_principal(config, client, subject, scope),
         principal = merge_principal_claims(principal, extra_claims),
         {:ok, minted} <- Token.mint(attesto_config(config), principal, mint_opts(binding)) do
      {:ok,
       %{
         access_token: minted.access_token,
         token_type: token_type,
         expires_in: minted.expires_in,
         scope: minted.scope
       }}
    else
      {:error, reason} ->
        # A mint failure here is a server/config fault, not a client error;
        # surface it as RFC 6749 §5.2 invalid_request rather than leak detail.
        Logger.error("token mint failed: #{inspect(reason)}")
        {:error, error(@error_invalid_request, "unable to issue token")}
    end
  end

  defp record_code_access_token(config, grant, response) do
    store = grant_store(config, :code_store)

    if store && function_exported?(store, :record_access_token, 3) do
      with family_id when is_binary(family_id) and family_id != "" <- grant.family_id,
           {:ok, %{"jti" => jti, "exp" => exp}} <-
             decode_access_token_claims(response.access_token),
           true <- is_binary(jti) and is_integer(exp) do
        :ok = store.record_access_token(family_id, jti, exp)
      else
        _ -> :ok
      end
    end

    :ok
  end

  defp decode_access_token_claims(token) when is_binary(token) do
    with [_header, payload, _signature] <- String.split(token, ".", parts: 3),
         {:ok, json} <- Base.url_decode64(payload, padding: false),
         {:ok, claims} <- JSON.decode(json) do
      {:ok, claims}
    else
      _ -> :error
    end
  end

  defp mint_exchanged_token(config, claims, scope, token_type, binding) do
    attesto_config = attesto_config(config)
    kind_claim = attesto_config.principal_kind_claim

    principal = %{
      kind: Map.get(claims, kind_claim),
      sub: Map.get(claims, "sub"),
      scopes: scope,
      claims: exchange_extra_claims(claims, kind_claim)
    }

    with {:ok, minted} <- Token.mint(attesto_config, principal, mint_opts(binding)) do
      {:ok,
       %{
         access_token: minted.access_token,
         token_type: token_type,
         expires_in: minted.expires_in,
         scope: minted.scope
       }}
    end
  end

  defp exchange_extra_claims(claims, principal_kind_claim) do
    reserved = MapSet.new(~w(iss aud exp iat nbf jti scope sub typ cnf) ++ [principal_kind_claim])

    claims
    |> Enum.reject(fn {key, _value} -> MapSet.member?(reserved, key) end)
    |> Map.new()
  end

  # RFC 9449 / RFC 8705: turn the resolved sender-constraint binding into the
  # `Attesto.Token.mint/3` confirmation opt. DPoP binds `cnf.jkt`; mTLS binds
  # `cnf.x5t#S256` (the certificate thumbprint, threaded here so a real
  # `cnf` is actually minted rather than dropped).
  defp mint_opts(:none), do: []
  defp mint_opts({:dpop, jkt}), do: [dpop_jkt: jkt]
  defp mint_opts({:mtls, thumbprint}), do: [mtls_cert_thumbprint: thumbprint]

  # The DPoP thumbprint a stateful grant (authorization-code redemption,
  # refresh rotation) binds to. Only DPoP flows through those engines'
  # `:dpop_jkt` opt; an mTLS binding carries no DPoP thumbprint.
  defp binding_jkt({:dpop, jkt}), do: jkt
  defp binding_jkt(_binding), do: nil

  defp build_principal(config, client, subject, scope) do
    case invoke(config_callback(config, :build_principal), [client, subject, scope]) do
      %{} = principal -> {:ok, principal}
      _ -> {:error, :no_principal_builder}
    end
  end

  # OIDC Core §5.5: the access token carries the claims request object so the
  # UserInfo endpoint can later shape its response. Only the `claims` object is
  # propagated; authentication-context values like nonce/auth_time stay code/ID
  # token state and are not access-token claims.
  defp access_token_claims(%{claims: claims}) when is_map(claims) do
    case id_token_claim(claims, "claims") do
      requested when is_map(requested) -> %{"claims" => requested}
      _ -> %{}
    end
  end

  defp access_token_claims(_grant), do: %{}

  defp merge_principal_claims(principal, extra_claims) when map_size(extra_claims) == 0,
    do: principal

  defp merge_principal_claims(principal, extra_claims) do
    claims =
      case Map.get(principal, :claims) do
        claims when is_map(claims) -> Map.merge(claims, extra_claims)
        _ -> extra_claims
      end

    Map.put(principal, :claims, claims)
  end

  # ── Sender-constraint resolution (RFC 9449 / RFC 8705) ───────────────────

  # Returns `{:ok, binding, token_type}` where `binding` is one of
  # `{:dpop, jkt}`, `{:mtls, thumbprint}`, or `:none`. DPoP takes precedence
  # when a proof is presented (RFC 9449 §5); otherwise an mTLS certificate
  # binds the token to its thumbprint; otherwise the token is an unbound
  # Bearer - but only if the client does not *require* mTLS.
  #
  # RFC 8705 §3: a client configured to require certificate-bound tokens MUST
  # NOT be silently downgraded to a Bearer token when it calls without a
  # certificate; that would strip the sender constraint the deployment relies
  # on. The host's `:client_requires_mtls?` callback gates this.
  defp resolve_sender_constraint(config, conn, client) do
    cond do
      config.dpop_enabled and dpop_present?(conn) ->
        bind_dpop(config, conn)

      config.mtls_enabled and mtls_cert_present?(config, conn) ->
        bind_mtls(config, conn)

      client_requires_mtls?(config, client) ->
        # No DPoP proof and no client certificate, yet this client must be
        # certificate-bound: refuse rather than issue an unbound token.
        {:error, error(@error_invalid_client, "client certificate required")}

      true ->
        {:ok, :none, @token_type_bearer}
    end
  end

  # The certificate-binding requirement (RFC 8705). Read defensively from the
  # configuration; fail open to "not required" only when the host has not
  # supplied the callback, since a deployment without mTLS policy never sets
  # it. (mTLS itself is off by default per `:mtls_enabled`.)
  defp client_requires_mtls?(config, client) do
    invoke_with_default(config_callback(config, :client_requires_mtls?), [client], false) == true
  end

  defp mtls_cert_present?(config, conn) do
    is_binary(RequestContext.cert_der(conn, config))
  end

  defp dpop_present?(conn), do: get_req_header(conn, @dpop_request_header) != []

  defp bind_dpop(config, conn) do
    [proof | _] = get_req_header(conn, @dpop_request_header)

    verify_opts =
      [
        http_method: @http_method_post,
        http_uri: RequestContext.canonical_url(conn, config)
      ]
      |> put_optional_kw(:nonce_check, nonce_check(config))

    case invoke_dpop_verify(proof, verify_opts) do
      {:ok, %{jkt: jkt}} ->
        {:ok, {:dpop, jkt}, @token_type_dpop}

      {:error, :use_dpop_nonce} ->
        # RFC 9449 §8/§9: hand the client a fresh nonce and demand a retry.
        {:error, dpop_nonce_required(config)}

      {:error, reason} ->
        {:error, error(@error_invalid_dpop_proof, "invalid DPoP proof: #{inspect(reason)}")}
    end
  end

  # The proof verifier is part of the `Attesto.DPoP` core; the replay-check
  # callback is host-supplied. Both are reached only through the configured
  # surface so this module hardcodes neither a store nor a clock.
  defp invoke_dpop_verify(proof, opts) do
    Attesto.DPoP.verify_proof(proof, opts)
  end

  defp bind_mtls(config, conn) do
    case RequestContext.cert_der(conn, config) do
      der when is_binary(der) ->
        case MTLS.compute_thumbprint(der) do
          {:ok, x5t} ->
            # RFC 8705 §3: the certificate thumbprint becomes the token's
            # `cnf.x5t#S256` (minted via `Attesto.Token`'s
            # `:mtls_cert_thumbprint` opt). mTLS-bound tokens keep the
            # `Bearer` type (RFC 8705 §3.1).
            {:ok, {:mtls, x5t}, @token_type_bearer}

          {:error, _reason} ->
            {:error, error(@error_invalid_client, "invalid client certificate")}
        end

      _ ->
        {:error, error(@error_invalid_client, "client certificate required")}
    end
  end

  # RFC 9449 §8/§9: when the deployment requires server-issued nonces
  # (`config.dpop_nonce_required`), hand `Attesto.DPoP.verify_proof/2` a
  # `:nonce_check` callback that validates the proof's `nonce` claim against
  # the configured `Attesto.DPoP.NonceStore`. The callback receives the
  # proof's `nonce` (which may be `nil` if the client sent none) and returns
  # `:ok` only for a currently-valid nonce, else `{:error, :use_dpop_nonce}`
  # so the controller answers with a fresh `DPoP-Nonce`. When nonces are not
  # required, no callback is supplied and the engine enforces none.
  defp nonce_check(%Config{dpop_nonce_required: true, nonce_store: store})
       when is_atom(store) and not is_nil(store) do
    fn nonce ->
      if store.valid?(nonce), do: :ok, else: {:error, :use_dpop_nonce}
    end
  end

  defp nonce_check(_config), do: nil

  # RFC 9449 §8: issue a fresh server nonce and return it so the client can
  # replay its proof with the `nonce` claim included.
  defp dpop_nonce_required(config) do
    nonce = issue_nonce(config)

    error(@error_use_dpop_nonce, "DPoP proof requires a server-issued nonce",
      status: 400,
      headers: [{@dpop_nonce_header, nonce}]
    )
  end

  defp issue_nonce(%Config{nonce_store: store}) when is_atom(store) and not is_nil(store) do
    store.issue()
  end

  defp issue_nonce(_config), do: ""

  # ── Configured-callback access ───────────────────────────────────────────

  # The client's identifier (RFC 6749 §2.2). The frozen `AttestoPhoenix.Config`
  # struct may not name this callback as a field yet; it is read defensively so
  # the controller works today and lights up when a host supplies it. When
  # absent the identifier is unknown (`nil`), which is correct for audit and is
  # never used as a credential.
  defp client_id(config, client) do
    invoke_with_default(config_callback(config, :client_id), [client], nil)
  end

  # The `Attesto.CodeStore` / `Attesto.RefreshStore` backing each stateful
  # grant. Resolved from the configuration so the host owns persistence; this
  # module hardcodes no store module.
  defp grant_store(config, key), do: config_callback(config, key)

  defp config_flag(config, key), do: Map.get(config, key) == true

  # Read a callback the frozen `AttestoPhoenix.Config` struct may not declare
  # as a named field yet: pull it from the struct map if present. This keeps
  # the controller working against the current configuration and lets a host
  # supply the grant-shaped callbacks without this module inventing struct
  # fields.
  defp config_callback(config, key), do: Map.get(config, key)

  # ── Request helpers ──────────────────────────────────────────────────────

  defp require_param(params, key) do
    case params[key] do
      value when is_binary(value) and value != "" -> {:ok, value}
      _ -> {:error, error(@error_invalid_request, "missing #{key}")}
    end
  end

  defp optional_param(params, key) do
    case params[key] do
      value when is_binary(value) and value != "" -> value
      _ -> nil
    end
  end

  defp put_optional(map, _key, nil), do: map
  defp put_optional(map, key, value), do: Map.put(map, key, value)

  defp put_optional_kw(kw, _key, nil), do: kw
  defp put_optional_kw(kw, _key, []), do: kw
  defp put_optional_kw(kw, key, value), do: Keyword.put(kw, key, value)

  # Callback invocation, mirroring the function/{m,f}/mfa forms the rest of the
  # library accepts (see `AttestoPhoenix.Config`).
  defp invoke(fun, args) when is_function(fun), do: apply(fun, args)

  defp invoke({module, fun}, args) when is_atom(module) and is_atom(fun),
    do: apply(module, fun, args)

  defp invoke({module, fun, extra}, args) when is_atom(module) and is_atom(fun),
    do: apply(module, fun, args ++ extra)

  defp invoke(nil, _args), do: :no_callback

  defp invoke_with_default(nil, _args, default), do: default
  defp invoke_with_default(callback, args, _default), do: invoke(callback, args)

  # ── Audit / telemetry ────────────────────────────────────────────────────

  defp emit(config, conn, name, client, scope, grant_type) do
    Event.emit(config, name, %{
      client_id: client_id(config, client),
      scope: Enum.join(List.wrap(scope), " "),
      grant_type: grant_type,
      metadata: %{client_ip: RequestContext.client_ip(conn, config)}
    })
  end

  defp emit_denied(config, conn, params, client, grant_type, %{error: code} = err) do
    Event.emit(config, :token_denied, %{
      client_id: denial_client_id(config, conn, params, client),
      scope: optional_param(params, "scope"),
      grant_type: grant_type || optional_param(params, "grant_type"),
      result: code,
      metadata:
        %{
          client_ip: RequestContext.client_ip(conn, config),
          error: code,
          error_description: Map.get(err, :description),
          http_status: Map.get(err, :status, 400),
          sender_constraint: sender_constraint_context(config, conn)
        }
        |> Enum.reject(fn {_key, value} -> is_nil(value) end)
        |> Map.new()
    })
  end

  defp denial_client_id(config, conn, params, client) when not is_nil(client) do
    client_id(config, client) || request_client_id(conn, params)
  end

  defp denial_client_id(_config, conn, params, _client) do
    request_client_id(conn, params)
  end

  defp request_client_id(conn, params),
    do: optional_param(params, "client_id") || basic_client_id(conn)

  defp basic_client_id(conn) do
    with ["Basic " <> encoded] <- get_req_header(conn, "authorization"),
         {:ok, decoded} <- Base.decode64(encoded),
         [client_id, _secret] <- String.split(decoded, ":", parts: 2) do
      URI.decode_www_form(client_id)
    else
      _ -> nil
    end
  end

  defp sender_constraint_context(config, conn) do
    %{
      dpop_present: dpop_present?(conn),
      mtls_cert_present: mtls_cert_present?(config, conn)
    }
  end

  # ── Rendering (RFC 6749 §5) ──────────────────────────────────────────────

  defp render_token_error(config, conn, params, client, grant_type, err) do
    emit_denied(config, conn, params, client, grant_type, err)
    render_error(conn, err)
  end

  defp render_error(conn, %{error: code} = err) do
    conn
    |> merge_resp_headers(Map.get(err, :headers, []))
    |> put_status(Map.get(err, :status, 400))
    |> json(error_body(code, Map.get(err, :description)))
  end

  # RFC 6749 §5.2 error response body.
  defp error_body(code, nil), do: %{error: code}
  defp error_body(code, description), do: %{error: code, error_description: description}

  defp error(code, description), do: %{error: code, description: description, status: 400}

  defp error(code, description, opts) do
    %{
      error: code,
      description: description,
      status: Keyword.get(opts, :status, 400),
      headers: Keyword.get(opts, :headers, [])
    }
  end

  # RFC 6749 §5.2: redemption/rotation failures all map to invalid_grant; the
  # specific internal reason is not exposed to the client. Reuse detection is
  # also invalid_grant on the wire (the family is already revoked in the
  # store), so a captured-token replay learns nothing.
  defp grant_error(:invalid_scope),
    do: error(@error_invalid_scope, "requested scope exceeds the grant")

  defp grant_error(_reason),
    do: error(@error_invalid_grant, "authorization grant is invalid or expired")

  defp put_no_store_headers(conn) do
    conn
    |> put_resp_header("cache-control", @cache_control_no_store)
    |> put_resp_header("pragma", @pragma_no_cache)
  end
end
