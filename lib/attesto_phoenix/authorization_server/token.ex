defmodule AttestoPhoenix.AuthorizationServer.Token do
  @moduledoc """
  Token-endpoint grant processing (RFC 6749 §3.2), as conn-free core.

  This is the single place that turns an authenticated client and a parsed
  token request into either an RFC 6749 §5.1 response body or an
  `AttestoPhoenix.OAuthError`, together with the list of audit events the
  exchange produced. It owns every grant-state and claim-level decision the
  token endpoint takes:

    * the grant dispatch (RFC 6749 §4) across `authorization_code`,
      `refresh_token`, `client_credentials`, and OAuth token exchange
      (RFC 8693);
    * authorization-code redemption and code-reuse family revocation
      (OAuth 2.0 Security BCP §4.13), via `Attesto.AuthorizationCode`;
    * refresh-token rotation and the initial offline-access refresh-token
      issuance gate (RFC 6749 §6 / OIDC Core §11), via `Attesto.RefreshToken`;
    * ID-Token minting with `at_hash`/`c_hash`/`nonce`/`auth_time`
      (OIDC Core §3.1.3.3 / §3.3.2.11), via `Attesto.IDToken`;
    * UserInfo / claims-parameter extra claims (OIDC Core §5.4 / §5.5);
    * scope resolution (RFC 6749 §3.3) and access-token claim assembly, via
      `Attesto.Token`.

  ## North star

  `AttestoPhoenix.Controller.TokenController` parses the request off the
  `Plug.Conn`, authenticates the client (RFC 6749 §2.3), lifts the conn facts
  into a `%Request{}` of plain data, and calls `issue/2`. This module reads only
  data, never touches a conn, and never emits an event: it returns the events as
  data and the controller emits them. Policy is carried on the
  `%AttestoPhoenix.Config{}` the caller passes in (host callbacks, stores, TTLs);
  nothing is hardcoded here.

  ## Return value

  `{:ok, response_map, events}` on success, where `response_map` is the
  RFC 6749 §5.1 body (atom keys) and `events` is a list of
  `%AttestoPhoenix.Event{}` the caller emits. `{:error, %OAuthError{}, events}`
  on failure, where `events` carries the RFC 6749 §5.2 `:token_denied` audit
  event (this module emits no event itself).

  Failures that are a server/config fault rather than a client error (a mint
  failure, a refresh-issuance failure) are surfaced as RFC 6749 §5.2
  `invalid_request` without leaking detail; the underlying reason is logged.
  """

  alias Attesto.{AuthorizationCode, IDToken, RefreshToken}
  alias AttestoPhoenix.AuthorizationServer.SenderConstraint
  alias AttestoPhoenix.AuthorizationServer.Token.Request
  alias AttestoPhoenix.{Callback, Config, Event, OAuthError}

  require Logger

  # RFC 6749 §5.2 error codes.
  @error_invalid_request "invalid_request"
  @error_invalid_grant "invalid_grant"
  @error_invalid_scope "invalid_scope"
  @error_unsupported_grant_type "unsupported_grant_type"

  # RFC 8693 token exchange.
  @grant_token_exchange "urn:ietf:params:oauth:grant-type:token-exchange"
  @subject_token_type_access_token "urn:ietf:params:oauth:token-type:access_token"

  # OIDC Core §3.1.2.1 / §11: the scope values that trigger ID-Token issuance
  # and initial refresh-token issuance respectively.
  @openid_scope "openid"
  @offline_access_scope "offline_access"

  @typedoc "The RFC 6749 §5.1 token response body (atom keys)."
  @type response :: %{required(atom()) => term()}

  @doc """
  Process a token request, returning the response (or error) and the audit
  events the exchange produced.

  `config` is the validated `%AttestoPhoenix.Config{}` (also carried on the
  `request` for the conn-free helpers); `request` is the
  `AttestoPhoenix.AuthorizationServer.Token.Request` the controller built from
  the request and the conn facts. See the module docs for the return shape.
  This module emits no event itself: the caller emits the returned `events`.
  """
  @spec issue(Config.t(), Request.t()) ::
          {:ok, response(), [Event.t()]} | {:error, OAuthError.t(), [Event.t()]}
  def issue(%Config{} = _config, %Request{} = request) do
    case run(request) do
      {:ok, response, events} ->
        {:ok, response, events}

      {:error, %OAuthError{} = err} ->
        {:error, err, [denied_event(request, err)]}
    end
  end

  defp run(%Request{} = request) do
    case require_registered_grant_type(request) do
      :ok -> dispatch(request)
      {:error, %OAuthError{}} = err -> err
    end
  end

  # RFC 6749 §4: a client may be registered for only a subset of grant types.
  # When the host supplies `:client_grant_types`, a grant the client is not
  # registered for is rejected (RFC 6749 §5.2 unsupported_grant_type); when the
  # callback is unset every grant is allowed (the dispatch's own
  # unsupported-grant clause remains the backstop).
  defp require_registered_grant_type(%Request{} = request) do
    %{config: config, client: client, grant_type: grant_type} = request

    case Callback.invoke(Config.client_grant_types_fun(config), [client], nil) do
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

  # ── Grant dispatch (RFC 6749 §4) ─────────────────────────────────────────

  # RFC 6749 §4.1.3 + RFC 7636: authorization-code grant. Public clients must
  # present PKCE; confidential clients do too by default, unless the host has
  # explicitly relaxed `:require_pkce` for Basic-profile compatibility.
  defp dispatch(%Request{grant_type: "authorization_code"} = request) do
    %{config: config, client: client, params: params} = request

    with {:ok, code} <- require_param(params, "code"),
         {:ok, verifier} <- fetch_code_verifier(config, client, params),
         {:ok, redirect_uri} <- require_param(params, "redirect_uri"),
         {:ok, binding, token_type} <- resolve_sender_constraint(request),
         {:ok, grant} <-
           redeem_code(
             config,
             client,
             code,
             verifier,
             redirect_uri,
             SenderConstraint.binding_jkt(binding)
           ),
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
      issued = token_issued_event(request, scope, "authorization_code")
      # RFC 6749 §4.1.4 / §6: optionally issue an initial refresh token so the
      # client can refresh without re-running the authorization flow. The
      # initial token is minted into the code's `family_id` (OAuth 2.0 Security
      # BCP §4.13) so a later replay of the same code, surfaced as
      # `{:error, {:reuse, meta}}` by `Attesto.AuthorizationCode.redeem/4`,
      # carries the `family_id` needed to revoke this exact descendant family.
      maybe_issue_refresh_token(request, grant, scope, binding, response, [issued])
    end
  end

  # RFC 6749 §6 + §10.4: refresh-token rotation with reuse detection.
  defp dispatch(%Request{grant_type: "refresh_token"} = request) do
    %{config: config, client: client, params: params} = request

    with {:ok, presented} <- require_param(params, "refresh_token"),
         requested = parse_requested_scope(params),
         {:ok, binding, token_type} <- resolve_sender_constraint(request),
         {:ok, rotated} <-
           rotate_refresh(
             config,
             client,
             presented,
             requested,
             SenderConstraint.refresh_binding_jkt(config, client, binding)
           ),
         {:ok, scope} <- authorize_scope(config, client, rotated.context.scope),
         {:ok, response} <-
           mint(config, client, rotated.context.subject, scope, token_type, binding) do
      response = Map.put(response, :refresh_token, rotated.token)
      {:ok, response, [refresh_rotated_event(request, scope, "refresh_token")]}
    end
  end

  # RFC 6749 §4.4: client-credentials grant. No resource owner is involved, so
  # no refresh token is issued (RFC 6749 §4.4.3).
  defp dispatch(%Request{grant_type: "client_credentials"} = request) do
    %{config: config, client: client, params: params} = request

    with {:ok, binding, token_type} <- resolve_sender_constraint(request),
         subject = client_id(config, client),
         {:ok, scope} <- authorize_scope(config, client, parse_requested_scope(params)),
         {:ok, response} <- mint(config, client, subject, scope, token_type, binding) do
      {:ok, response, [token_issued_event(request, scope, "client_credentials")]}
    end
  end

  # RFC 8693: exchange a valid Attesto access token for a new, host-authorized
  # access token. Scope policy still belongs to `:authorize_scope`; when no
  # `scope` is requested the subject token's existing scope is carried forward.
  defp dispatch(%Request{grant_type: @grant_token_exchange} = request) do
    %{config: config, client: client, params: params} = request

    with {:ok, subject_token} <- require_param(params, "subject_token"),
         :ok <- require_subject_token_type(params),
         {:ok, binding, token_type} <- resolve_sender_constraint(request),
         {:ok, claims} <- verify_subject_token(config, subject_token, binding),
         requested = requested_exchange_scope(params, claims),
         {:ok, scope} <- authorize_scope(config, client, requested),
         {:ok, response} <- mint_exchanged_token(config, claims, scope, token_type, binding) do
      response = Map.put(response, :issued_token_type, @subject_token_type_access_token)
      {:ok, response, [token_issued_event(request, scope, "token_exchange")]}
    else
      {:error, %OAuthError{} = err} -> {:error, err}
      {:error, _reason} -> {:error, error(@error_invalid_grant, "subject token is invalid")}
    end
  end

  # RFC 6749 §5.2.
  defp dispatch(%Request{grant_type: grant_type}) do
    {:error, error(@error_unsupported_grant_type, "unsupported grant_type: #{grant_type}")}
  end

  # ── Grant-state delegation (Attesto core) ────────────────────────────────

  # PKCE enforcement is challenge-based and belongs to the code, not the request:
  # the authorization/PAR endpoint already requires a `code_challenge`
  # (RequestPolicy.require_pkce?/2) for clients that must use PKCE, so the issued
  # code carries one. `Attesto.AuthorizationCode.redeem/4` then requires a
  # matching `code_verifier` and collapses a missing OR mismatched verifier to
  # `invalid_grant` (RFC 7636 §4.6). So the verifier is passed through optionally
  # rather than short-circuited here as `invalid_request`.
  defp fetch_code_verifier(_config, _client, params) do
    {:ok, optional_param(params, "code_verifier")}
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
      |> Keyword.put(:rotation_grace_seconds, config.refresh_token_rotation_grace_seconds)

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
  # RFC 9449 §8 requires DPoP-bound refresh tokens for public clients. For
  # confidential clients, the refresh token remains bound to the authenticated
  # client_id (RFC 6749 §6 / §10.4) rather than to one DPoP proof key; this
  # lets a confidential client rotate or recover its DPoP key while each newly
  # minted access token is still sender-constrained to the proof presented on
  # that token request. An mTLS-bound request issues no DPoP binding on the
  # refresh token. The plaintext token is added to the RFC 6749 §5.1 body;
  # only its hash is persisted (see `Attesto.RefreshToken`).
  defp maybe_issue_refresh_token(request, grant, scope, binding, response, events) do
    %{config: config, client: client} = request

    if refresh_store = grant_store(config, :refresh_store) do
      if issue_refresh_token?(config, client, scope) do
        issue_initial_refresh_token(
          request,
          grant,
          scope,
          binding,
          refresh_store,
          response,
          events
        )
      else
        {:ok, response, events}
      end
    else
      {:ok, response, events}
    end
  end

  defp issue_initial_refresh_token(request, grant, scope, binding, refresh_store, response, events) do
    %{config: config, client: client} = request

    context =
      %{subject: grant.subject, scope: scope}
      |> put_optional(:client_id, client_id(config, client))
      |> put_optional(:dpop_jkt, SenderConstraint.refresh_binding_jkt(config, client, binding))

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
        response = Map.put(response, :refresh_token, token)
        issued = refresh_issued_event(request, scope, "authorization_code")
        {:ok, response, events ++ [issued]}

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
    case Callback.config_callback(config, :issue_refresh_token?) do
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
    |> put_optional_kw(:extra_claims, id_token_extra_claims(config, client, grant, scope))
  end

  # OIDC Core §5.4 / §5.5: the additional identity claims an ID Token may
  # carry (e.g. `email`, `name`) are the host's to source - this library knows
  # no user store. The host's `:build_id_token_claims` callback is given the
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
  defp id_token_extra_claims(config, client, grant, scope) do
    case Config.build_id_token_claims_fun(config) do
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
    Attesto.Token.verify(attesto_config(config), token, expected_typ: "access")
  end

  defp verify_subject_token(config, token, {:dpop, jkt}) do
    Attesto.Token.verify(attesto_config(config), token, expected_typ: "access", dpop_jkt: jkt)
  end

  defp verify_subject_token(config, token, {:mtls, thumb}) do
    Attesto.Token.verify(attesto_config(config), token,
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
    case invoke(Config.authorize_scope_fun(config), [client, requested]) do
      {:ok, scope} when is_list(scope) -> {:ok, scope}
      {:error, _reason} -> {:error, error(@error_invalid_scope, "scope not permitted")}
      _ -> {:error, error(@error_invalid_request, "scope policy unavailable")}
    end
  end

  # ── Token minting (Attesto.Token) ────────────────────────────────────────

  defp mint(config, client, subject, scope, token_type, binding, extra_claims \\ %{}) do
    with {:ok, principal} <- build_principal(config, client, subject, scope),
         principal = merge_principal_claims(principal, extra_claims),
         {:ok, minted} <-
           Attesto.Token.mint(
             attesto_config(config),
             principal,
             SenderConstraint.mint_opts(binding)
           ) do
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

    with {:ok, minted} <-
           Attesto.Token.mint(attesto_config, principal, SenderConstraint.mint_opts(binding)) do
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

  defp build_principal(config, client, subject, scope) do
    case invoke(Config.build_principal_fun(config), [client, subject, scope]) do
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

  defp merge_principal_claims(principal, extra_claims) when map_size(extra_claims) == 0, do: principal

  defp merge_principal_claims(principal, extra_claims) do
    claims =
      case Map.get(principal, :claims) do
        claims when is_map(claims) -> Map.merge(claims, extra_claims)
        _ -> extra_claims
      end

    Map.put(principal, :claims, claims)
  end

  # ── Sender-constraint resolution (RFC 9449 / RFC 8705) ───────────────────

  # Delegate to the conn-free `SenderConstraint` core, passing the input the
  # controller lifted off the conn. A required-but-absent DPoP nonce surfaces
  # as a `use_dpop_nonce` error whose `:headers` carry the fresh `DPoP-Nonce`,
  # rendered verbatim by the controller.
  defp resolve_sender_constraint(%Request{} = request) do
    SenderConstraint.resolve(request.config, request.sender_constraint_input, request.client)
  end

  # ── Configuration / protocol-config derivation ───────────────────────────

  # The `Attesto.Config` consumed by `Attesto.Token`. Derived from the same
  # `%AttestoPhoenix.Config{}`; the principal-kind declarations are host policy
  # carried alongside the config and passed through as the protocol `extra`.
  defp attesto_config(config) do
    Config.to_attesto_config(config, principal_kinds_extra(config))
  end

  # Read the field directly: it is declared `[PrincipalKind.t()] | callback() |
  # nil`, so the list branch is reachable. (`config_callback/2` narrows its
  # return to `callback() | nil`, under which the `is_list` guard cannot hold.)
  defp principal_kinds_extra(%Config{principal_kinds: principal_kinds}) do
    case principal_kinds do
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

  # ── Configured-callback access ───────────────────────────────────────────

  # The client's identifier (RFC 6749 §2.2). Read defensively so this module
  # works today and lights up when a host supplies `:client_id`. When absent
  # the identifier is unknown (`nil`), which is correct for audit and is never
  # used as a credential.
  defp client_id(config, client) do
    Callback.invoke(Config.client_id_fun(config), [client], nil)
  end

  # The `Attesto.CodeStore` / `Attesto.RefreshStore` backing each stateful
  # grant. Resolved from the configuration so the host owns persistence; this
  # module hardcodes no store module.
  defp grant_store(config, key), do: Callback.config_callback(config, key)

  # ── Audit events (returned as data; the controller emits) ────────────────

  defp token_issued_event(request, scope, grant_type) do
    issued_like_event(request, :token_issued, scope, grant_type)
  end

  defp refresh_rotated_event(request, scope, grant_type) do
    issued_like_event(request, :refresh_rotated, scope, grant_type)
  end

  defp refresh_issued_event(request, scope, grant_type) do
    issued_like_event(request, :refresh_issued, scope, grant_type)
  end

  defp issued_like_event(request, name, scope, grant_type) do
    Event.new(name, %{
      client_id: client_id(request.config, request.client),
      scope: Enum.join(List.wrap(scope), " "),
      grant_type: grant_type,
      metadata: %{client_ip: request.client_ip}
    })
  end

  # RFC 6749 §5.2: the audit event for a denied grant. The error code is the
  # atom `err.error`; it rides as its wire string. The `:scope` and
  # `:grant_type` are the requested values off the request (not a resolved
  # grant), and the `client_id` prefers the host's `:client_id` callback over
  # the request-supplied fallback.
  defp denied_event(request, %OAuthError{} = err) do
    code = Atom.to_string(err.error)

    Event.new(:token_denied, %{
      client_id: denial_client_id(request),
      scope: optional_param(request.params, "scope"),
      grant_type: request.grant_type,
      result: code,
      metadata:
        %{
          client_ip: request.client_ip,
          error: code,
          error_description: err.error_description,
          http_status: err.status,
          sender_constraint: sender_constraint_context(request)
        }
        |> Enum.reject(fn {_key, value} -> is_nil(value) end)
        |> Map.new()
    })
  end

  defp denial_client_id(request) do
    client_id(request.config, request.client) || request.request_client_id
  end

  defp sender_constraint_context(%Request{sender_constraint_input: input}) do
    %{
      dpop_present: is_binary(Map.get(input, :dpop_proof)),
      mtls_cert_present: is_binary(Map.get(input, :mtls_cert_der))
    }
  end

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

  # Callback invocation delegates to `AttestoPhoenix.Callback`, except that an
  # absent (`nil`) callback becomes the `:no_callback` sentinel its callers
  # branch on (rather than raising a FunctionClauseError).
  defp invoke(nil, _args), do: :no_callback
  defp invoke(callback, args), do: Callback.invoke(callback, args)

  # ── Errors (RFC 6749 §5.2) ───────────────────────────────────────────────

  defp error(code, description), do: OAuthError.new(error_code(code), description, status: 400)

  defp error_code(code) when is_binary(code), do: String.to_existing_atom(code)

  # RFC 6749 §5.2: redemption/rotation failures all map to invalid_grant; the
  # specific internal reason is not exposed to the client. Reuse detection is
  # also invalid_grant on the wire (the family is already revoked in the
  # store), so a captured-token replay learns nothing.
  defp grant_error(:invalid_scope), do: error(@error_invalid_scope, "requested scope exceeds the grant")

  defp grant_error(_reason), do: error(@error_invalid_grant, "authorization grant is invalid or expired")
end
