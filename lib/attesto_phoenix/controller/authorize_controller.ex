defmodule AttestoPhoenix.Controller.AuthorizeController do
  @moduledoc """
  OAuth 2.0 / OpenID Connect authorization endpoint (RFC 6749 §3.1,
  OIDC Core §3.1.2).

  Handles `GET /oauth/authorize`, the front-channel browser flow that ends in
  an authorization code (RFC 6749 §4.1). This module owns only the HTTP and
  protocol-framing concerns: it parses and validates the request through
  `Attesto.AuthorizationRequest`, classifies failures by where they may be
  reported (OIDC Core §3.1.2.6), and on success mints a single-use code through
  `Attesto.AuthorizationCode.issue/3` and redirects back to the client. Every
  identity decision - who the resource owner is, and whether they consent - is
  delegated to host callbacks on `AttestoPhoenix.Config`. No login or consent
  UI lives here.

  ## Error disposition (OIDC Core §3.1.2.6, RFC 6749 §4.1.2.1)

  The `client_id` and `redirect_uri` are validated BEFORE anything is rendered
  or redirected. A request whose `client_id` is unknown, or whose
  `redirect_uri` does not exactly match the client's registered set, is
  untrusted: the server MUST NOT redirect back to the supplied URI (that would
  be an open redirect), so it renders a direct error page to the user agent.
  Only once the `client_id`/`redirect_uri` pair is established as trusted is any
  further error (bad `response_type`, `scope`, PKCE, `max_age`) reported by
  redirecting back to the validated `redirect_uri` with an `error` (and
  `error_description`/`state`) query parameter. `Attesto.AuthorizationRequest`
  performs this classification; this controller turns each class into the
  correct HTTP response.

  ## PKCE is mandatory (RFC 7636)

  `Attesto.AuthorizationRequest` requires a valid S256 `code_challenge`; there
  is no PKCE-less path. The challenge is carried into the issued code so the
  token endpoint can verify the matching verifier on redemption.

  ## Resource-owner authentication and consent (host policy)

  Authenticating the end user and obtaining consent are host policy, not
  protocol, so they are delegated to two `AttestoPhoenix.Config` callbacks:

    * `:authenticate_resource_owner` - `(conn, request, auth_opts ->
      {:authenticated, subject} | {:halt, conn} | {:none} | {:error,
      :login_required | :consent_required | :interaction_required})`. Returns
      `{:authenticated, subject}` once a resource owner is established for this
      request, `{:halt, conn}` to take over the connection (e.g. redirect to a
      login page that, after login, re-enters this endpoint with the same
      authorization parameters), `{:none}` when no subject can be established
      without UI, or an `{:error, _}` to explicitly classify why interaction is
      required (OIDC Core §3.1.2.6). The `subject` is a map carrying at least
      `:subject` (the subject identifier, OIDC Core §2 `sub`) and optionally
      `:auth_time`, `:acr`, and `:amr` (OIDC Core §2), threaded into the code's
      claims so the token endpoint can mint the ID token.

      `auth_opts` is a map carrying the OIDC Core §3.1.2.1 authentication
      directives the host MUST honour: `:prompt` (the parsed `prompt` list),
      `:force_reauth` (`true` for `prompt=login`: reauthenticate even if a
      session exists, returning a fresh `auth_time`), `:interactive` (`false`
      for `prompt=none`: the host MUST NOT render any UI, returning
      `{:authenticated, subject}` only if it can be established silently, else
      `{:none}`), and `:max_age` (when present, the host MUST reauthenticate if
      the existing authentication is older and return the resulting
      `auth_time`). Under `prompt=none` the controller converts a `{:halt,
      conn}` or `{:none}` into a `login_required` redirect rather than letting
      any UI run; a `{:halt, conn}` consent screen becomes `consent_required`
      (OIDC Core §3.1.2.6).

    * `:consent` - `(conn, request, subject -> {:consented, subject} |
      {:halt, conn} | {:denied, reason})`. Returns `{:consented, subject}` once
      the resource owner has authorized the request (the returned `subject` may
      carry consent-derived claims), `{:halt, conn}` to take over the
      connection (e.g. render a consent screen that re-enters this endpoint), or
      `{:denied, _reason}` to refuse, which is reported back to the client as
      the RFC 6749 §4.1.2.1 `access_denied` error by redirect. When the host
      does not supply `:consent`, consent is treated as implicitly granted for
      the authenticated subject.

  Both callbacks may hand control back to a host-rendered page; the controller
  only proceeds to mint a code when both yield a subject. The actual login and
  consent UI lives in the host application, never in this library.

  ## Configuration contract

  All host policy is resolved through `AttestoPhoenix.Config`; nothing is
  hardcoded here. This controller reads (see `AttestoPhoenix.Config` for the
  authoritative definitions and defaults):

    * `:load_client` - client lookup and revocation gate (RFC 6749 §2.2). An
      unknown or revoked client is a direct (non-redirectable) error.
    * `:client_redirect_uris` - `(client -> [String.t()])` the client's
      registered redirect URIs, the trusted set the request `redirect_uri` is
      exact-matched against (RFC 6749 §3.1.2.3).
    * `:client_id` - `(client -> String.t())` the client's identifier, carried
      into the issued code.
    * `:authenticate_resource_owner`, `:consent` - the host login/consent hooks
      described above.
    * `:code_store` - the `Attesto.CodeStore` backing the issued code.
    * `:authorization_code_ttl` - the code lifetime, seconds.
    * `:on_event` - the optional audit/telemetry hook (via
      `AttestoPhoenix.Event`).
  """

  use Phoenix.Controller, formats: [:json]

  import Plug.Conn

  alias Attesto.AuthorizationCode
  alias Attesto.AuthorizationRequest
  alias Attesto.JARM
  alias Attesto.Secret
  alias AttestoPhoenix.AuthorizationServer.RequestPolicy
  alias AttestoPhoenix.{Callback, Config, Event, RequestContext}

  require Logger

  # RFC 6749 §4.1.2.1 error codes reported by redirect.
  @error_access_denied "access_denied"
  @error_server_error "server_error"

  # OIDC Core §3.1.2.6 error codes reported by redirect when prompt=none cannot
  # be satisfied without interaction.
  @error_login_required "login_required"
  @error_consent_required "consent_required"
  @error_interaction_required "interaction_required"

  # OIDC Core §3.1.2.1: the two `prompt` values this controller acts on.
  @prompt_none "none"
  @prompt_login "login"

  @doc """
  Authorization endpoint action (RFC 6749 §3.1, OIDC Core §3.1.2).

  Validates the request, authenticates and obtains consent from the resource
  owner via host callbacks, issues a single-use authorization code, and
  302-redirects back to the client's `redirect_uri` with `code` (and `state`,
  when present). Failures are dispatched to a direct error page or a redirected
  error per the classification in the moduledoc.
  """
  @spec authorize(Plug.Conn.t(), map()) :: Plug.Conn.t()
  def authorize(conn, params) do
    config = resolve_config()

    with :ok <- RequestContext.check_https(conn, config),
         {:ok, params, par_resolved?} <- resolve_request_uri(config, params),
         {:ok, client} <- load_client(config, params),
         {:ok, request} <- validate_request(config, client, params, par_resolved?) do
      run_flow(conn, config, client, request, dpop_jkt_from_params(params))
    else
      {:error, :insecure_transport} ->
        # RFC 6749 §3.1 / §10.1: the authorization endpoint requires TLS. The
        # request is untrusted, so this is a direct error, never a redirect.
        render_direct_error(conn, config, :insecure_transport)

      {:error, {:direct, reason}} ->
        # OIDC Core §3.1.2.6: bad client_id / redirect_uri is non-redirectable.
        emit_failure(conn, config, reason)
        render_direct_error(conn, config, reason)

      {:error, {:redirect, error}} ->
        # RFC 6749 §4.1.2.1: the client_id/redirect_uri pair is trusted, so the
        # error is reported by redirecting back to the validated redirect_uri.
        emit_failure(conn, config, error.error)
        emit_redirect_error(conn, config, error)
    end
  end

  # ── Client lookup (RFC 6749 §2.2 / OIDC Core §3.1.2.6) ───────────────────

  # The client must be resolved BEFORE validating the request, because its
  # registered redirect-URI set is the trusted set the request `redirect_uri`
  # is matched against. An unknown or revoked client is non-redirectable: the
  # supplied redirect_uri cannot be trusted (OIDC Core §3.1.2.6), so it is
  # reported as a direct error. A request without a usable `client_id` is the
  # same class; `Attesto.AuthorizationRequest` would classify it identically,
  # but it is caught here too so a missing `client_id` never reaches
  # `:load_client`.
  defp load_client(config, params) do
    case params["client_id"] do
      client_id when is_binary(client_id) and client_id != "" ->
        case Callback.invoke(Config.load_client_fun(config), [client_id]) do
          {:ok, client} -> {:ok, client}
          _other -> {:error, {:direct, :invalid_client_id}}
        end

      _ ->
        {:error, {:direct, :invalid_client_id}}
    end
  end

  # ── Request validation (Attesto.AuthorizationRequest) ────────────────────

  # The registered redirect-URI set is a fact the host supplies via
  # `:client_redirect_uris`; the exact-match check is protocol and is performed
  # by `Attesto.AuthorizationRequest` (RFC 6749 §3.1.2.3). A host that does not
  # supply the callback exposes no registered URIs, so every request is rejected
  # with `{:direct, :redirect_uri_not_registered}` (fail closed) rather than
  # silently trusting the supplied URI.
  #
  # OIDC Core §3.1.2.1: the `nonce` is OPTIONAL for the code flow by default, but
  # an OpenID Provider MAY require it. When the host sets `:require_nonce`, a
  # request whose scope contains `openid` (an OpenID Connect Authentication
  # Request) must carry a `nonce`; the core rejects a missing one with a
  # redirectable `invalid_request`. A plain OAuth 2.0 request (no `openid` scope)
  # is never subject to the requirement (RFC 6749 keeps the code at SHOULD), so
  # the flag is scoped to OIDC requests via `openid_request?/1`.
  defp validate_request(config, client, params, par_resolved?) do
    with {:ok, request} <-
           AuthorizationRequest.validate(params,
             registered_redirect_uris: RequestPolicy.registered_redirect_uris(config, client),
             require_nonce: RequestPolicy.require_nonce?(config),
             require_pkce: RequestPolicy.require_pkce?(config, client),
             request_object_jwks: client_jwks(config, client),
             request_object_audience: config.issuer,
             request_object_policy: config.request_object_policy
           ),
         :ok <- require_par_if_configured(config, request, par_resolved?) do
      {:ok, request}
    end
  end

  defp resolve_request_uri(config, %{"request_uri" => request_uri} = params)
       when is_binary(request_uri) and request_uri != "" do
    case par_store(config) do
      nil ->
        {:ok, params, false}

      store ->
        case fetch_par_request(store, request_uri) do
          {:ok, stored} -> resolve_stored_request(params, stored)
          :error -> resolve_missing_request_uri(request_uri, params)
        end
    end
  end

  defp resolve_request_uri(_config, params), do: {:ok, params, false}

  # A `request_uri` the store does not hold.
  #
  # RFC 9126 §2.2: an unknown or EXPIRED PAR `request_uri` (the
  # `urn:ietf:params:oauth:request_uri:` reference this AS issues) is
  # `invalid_request_uri` - it MUST NOT fall through to treating the opaque URN
  # as a by-value parameter (which would surface the wrong error);
  # non-redirectable, since the reference carried no trusted redirect_uri for
  # this caller. An external (non-PAR) reference is left for validation to
  # reject as `request_uri_not_supported` (OpenID Connect Core §6.2), as this AS
  # does not fetch external request objects.
  defp resolve_missing_request_uri(request_uri, params) do
    if par_request_uri?(request_uri) do
      {:error, {:direct, :invalid_request_uri}}
    else
      {:ok, params, false}
    end
  end

  # The `request_uri` reference scheme this AS issues from its PAR endpoint
  # (RFC 9126 §2.2); a store miss on one of these is an expired/unknown PAR
  # reference, distinct from an unsupported external request_uri.
  defp par_request_uri?(request_uri),
    do: String.starts_with?(request_uri, "urn:ietf:params:oauth:request_uri:")

  # RFC 9126 §2.2: the `request_uri` is bound to the client that pushed it. The
  # stored, verified PAR parameters are authoritative (front-channel parameters
  # outside the pushed request, such as `state`, must not augment the request),
  # but a front-channel `client_id` that disagrees with the bound one is a
  # different client replaying the reference and is rejected (non-redirectable:
  # the bound redirect_uri cannot be trusted for the mismatched caller). An
  # absent front-channel `client_id` defers to the bound one.
  defp resolve_stored_request(params, stored) do
    presented = params["client_id"]

    if is_binary(presented) and presented != "" and presented != stored["client_id"] do
      {:error, {:direct, :request_uri_client_mismatch}}
    else
      {:ok, stored, true}
    end
  end

  defp fetch_par_request(store, request_uri) do
    cond do
      function_exported?(store, :fetch, 1) -> store.fetch(request_uri)
      function_exported?(store, :take, 1) -> store.take(request_uri)
      true -> :error
    end
  end

  defp require_par_if_configured(config, request, false) do
    if Callback.config_flag(config, :require_pushed_authorization_requests) do
      {:error,
       {:redirect,
        %{
          redirect_uri: request.redirect_uri,
          error: "invalid_request",
          state: request.state
        }}}
    else
      :ok
    end
  end

  defp require_par_if_configured(_config, _request, true), do: :ok

  defp par_store(config), do: config_field(config, :par_store, AttestoPhoenix.Store.PAR.ETS)

  defp client_jwks(config, client) do
    case Config.client_jwks_fun(config) do
      nil ->
        nil

      callback ->
        case Callback.invoke(callback, [client]) do
          {:ok, jwks} -> jwks
          jwks when is_map(jwks) or is_list(jwks) -> jwks
          _other -> nil
        end
    end
  end

  # The per-request validation policy (registered redirect URIs, PKCE, nonce) is
  # resolved by the conn-free `AttestoPhoenix.AuthorizationServer.RequestPolicy`,
  # shared with the PAR endpoint so both validate an authorization request the
  # same way (RFC 9126 §2.1).

  # ── Authenticate, consent, issue (RFC 6749 §4.1.1 / OIDC Core §3.1.2.3) ───

  # The request is now trusted: the client exists and the redirect_uri is
  # registered. From here every further error is reported by redirecting back
  # to the validated redirect_uri (RFC 6749 §4.1.2.1).
  #
  # OIDC Core §3.1.2.1 / §3.1.2.6: `prompt` constrains how the resource owner is
  # established. `prompt=none` means the OP MUST NOT display any authentication
  # or consent UI: if it cannot reuse an already-established session it MUST
  # return one of `login_required` / `consent_required` / `interaction_required`
  # by redirect (never render). `prompt=login` means the OP MUST reauthenticate
  # the resource owner even if a session exists. Both intents are passed to the
  # host's authentication hook as `auth_opts`; the host owns the session, the
  # controller owns the protocol disposition.
  defp run_flow(conn, config, client, request, dpop_jkt) do
    prompt_none? = @prompt_none in request.prompt

    case authenticate_resource_owner(conn, config, request) do
      {:authenticated, subject} ->
        run_consent(conn, config, client, request, subject, prompt_none?, dpop_jkt)

      {:none} ->
        # OIDC Core §3.1.2.6: the host has no already-authenticated subject it
        # can return without UI. Under `prompt=none` that is `login_required`
        # (never a UI render); otherwise the host should have halted to its
        # login page, so a bare `{:none}` here is a host/config fault.
        if prompt_none? do
          emit_failure(conn, config, @error_login_required)
          emit_error(conn, config, request, @error_login_required)
        else
          Logger.error("authenticate_resource_owner returned {:none} without prompt=none")
          emit_error(conn, config, request, @error_server_error)
        end

      {:halt, halted_conn} ->
        # The host took over the connection (e.g. a redirect to a login page
        # that re-enters this endpoint after authentication). Under
        # `prompt=none` that is forbidden: the host MUST NOT show UI, so a halt
        # is converted to the `login_required` redirect instead of letting the
        # host's interactive page run (OIDC Core §3.1.2.6). A conformant host
        # honours `auth_opts.interactive == false` and returns `{:none}` rather
        # than halting; the conversion here is the defensive backstop, built on
        # the ORIGINAL `conn` (never the host's, which may already have a body
        # under a buggy host) so the redirect is always well-formed.
        if prompt_none? do
          emit_failure(conn, config, @error_login_required)
          emit_error(conn, config, request, @error_login_required)
        else
          halted_conn
        end

      {:error, reason}
      when reason in [:login_required, :consent_required, :interaction_required] ->
        # OIDC Core §3.1.2.6: the host explicitly classifies why it cannot
        # establish the resource owner without interaction. This is the only
        # path that surfaces `interaction_required` (the catch-all when the
        # blocker is neither specifically login nor consent), and it is reported
        # by redirect like the prompt=none conversions above.
        error_code = interaction_error_code(reason)
        emit_failure(conn, config, error_code)
        emit_error(conn, config, request, error_code)

      other ->
        # A callback that returns no known shape is a host/config fault, not a
        # client error. Fail closed with the §4.1.2.1 server_error rather than
        # crash, and do not issue a code.
        Logger.error("authenticate_resource_owner returned #{inspect(other)}")
        emit_error(conn, config, request, @error_server_error)
    end
  end

  # OIDC Core §3.1.2.6: map the host's interaction-blocked reason to its error
  # code. Reported by redirect to the (already trusted) redirect_uri.
  defp interaction_error_code(:login_required), do: @error_login_required
  defp interaction_error_code(:consent_required), do: @error_consent_required
  defp interaction_error_code(:interaction_required), do: @error_interaction_required

  defp run_consent(conn, config, client, request, subject, prompt_none?, dpop_jkt) do
    case consent(conn, config, request, subject) do
      {:consented, subject} ->
        issue_and_redirect(conn, config, client, request, subject, dpop_jkt)

      {:halt, halted_conn} ->
        # OIDC Core §3.1.2.6: a consent screen is interactive UI, forbidden
        # under `prompt=none`; convert the halt to `consent_required`, built on
        # the ORIGINAL `conn` (never the host's halted one, which may already
        # carry a body) so the redirect is always well-formed.
        if prompt_none? do
          emit_failure(conn, config, @error_consent_required)
          emit_error(conn, config, request, @error_consent_required)
        else
          halted_conn
        end

      {:denied, _reason} ->
        # RFC 6749 §4.1.2.1: the resource owner refused. Report access_denied
        # by redirect (the redirect_uri is already trusted). Under prompt=none
        # the equivalent disposition is consent_required (OIDC Core §3.1.2.6):
        # consent could not be obtained without interaction.
        emit_denied(conn, config, client)

        error_code = if prompt_none?, do: @error_consent_required, else: @error_access_denied
        emit_error(conn, config, request, error_code)

      other ->
        Logger.error("consent returned #{inspect(other)}")
        emit_error(conn, config, request, @error_server_error)
    end
  end

  # RFC 6749 §4.1.2 / OIDC Core §3.1.3.1: mint a single-use code bound to the
  # validated request and carry the OIDC `nonce` and the authentication context
  # (`auth_time`, `acr`, `amr`) into the code's claims so the token endpoint can
  # mint the ID token from the code alone (OIDC Core §2, §3.1.3.6). A fresh
  # per-code `family_id` is generated and threaded into the code (and onto the
  # redeemed grant) so the token endpoint can link any refresh token it issues
  # to a revocation family for code-reuse / refresh-reuse revocation
  # (OAuth 2.0 Security BCP §4.13, §4.14). On success, redirect back to the
  # client with `code` (and `state`).
  defp issue_and_redirect(conn, config, client, request, subject, dpop_jkt) do
    attrs =
      %{
        client_id: client_id(config, client),
        redirect_uri: request.redirect_uri,
        code_challenge: request.code_challenge,
        code_challenge_method: request.code_challenge_method,
        subject: subject_id(subject),
        scope: request.scope,
        family_id: generate_family_id(),
        claims: code_claims(request, subject)
      }
      |> put_optional(:dpop_jkt, dpop_jkt)

    case AuthorizationCode.issue(code_store(config), attrs, ttl: config.authorization_code_ttl) do
      {:ok, code} ->
        emit_code_issued(conn, config, client, request.scope)
        emit_success(conn, config, request, code)

      {:error, reason} ->
        # Issuance failing on a validated request is a server/config fault, not
        # a client error (RFC 6749 §4.1.2.1 server_error). Do not leak detail.
        Logger.error("authorization code issuance failed: #{inspect(reason)}")
        emit_error(conn, config, request, @error_server_error)
    end
  end

  # OAuth 2.0 Security BCP §4.13 / §4.14: a fresh, unguessable family identifier
  # generated per issued code. `Attesto.AuthorizationCode` rides it onto the
  # redeemed grant so the token endpoint mints the refresh-token family under
  # this id, and code-reuse detection replays it to revoke the descendant
  # family. Generated with the same secret generator the codes themselves use.
  defp generate_family_id, do: Secret.generate()

  # RFC 9449 §10 / FAPI2 Security Profile: a DPoP proof at PAR establishes the
  # key thumbprint the authorization code must later be redeemed with. PAR
  # stores that verified thumbprint in the pushed request params as `dpop_jkt`;
  # direct authorization requests may also carry the extension parameter. The
  # core code grant validates the thumbprint format and enforces the match at
  # token redemption.
  defp dpop_jkt_from_params(%{"dpop_jkt" => jkt}) when is_binary(jkt) and jkt != "", do: jkt
  defp dpop_jkt_from_params(_params), do: nil

  # OIDC Core §3.1.3.6 / §2: the claims the token endpoint needs to mint the ID
  # token. The request `nonce` (OIDC Core §3.1.2.1) MUST be reflected into the
  # ID token unchanged; the authentication context (`auth_time`, `acr`, `amr`)
  # is whatever the host's authentication/consent callbacks established. When the
  # request carried `max_age` (OIDC Core §3.1.2.1), `auth_time` is REQUIRED in
  # the ID Token, so the host's freshly-established `auth_time` (after any
  # re-authentication it performed to satisfy `max_age`) is carried here; a host
  # that satisfied `max_age` but returned no `auth_time` is a host fault, logged
  # so the misconfiguration is visible rather than silently dropping the claim.
  # Only the keys the host actually supplied are carried, so the token endpoint
  # can distinguish "absent" from a value.
  defp code_claims(request, subject) do
    auth_time = Map.get(subject, :auth_time)

    if not is_nil(request.max_age) and is_nil(auth_time) do
      Logger.error("max_age was requested but the host returned no auth_time")
    end

    %{}
    |> put_optional("nonce", request.nonce)
    |> put_optional("claims", request.claims)
    |> put_optional("auth_time", auth_time)
    |> put_optional("acr", Map.get(subject, :acr))
    |> put_optional("amr", Map.get(subject, :amr))
  end

  # ── Host callbacks (login / consent) ─────────────────────────────────────

  # The host login hook. Read defensively from the configuration; when a host
  # has not supplied it there is no way to establish a resource owner, so fail
  # closed with a server_error-classed result rather than minting a code for an
  # unauthenticated subject.
  #
  # The callback is invoked with `[conn, request, auth_opts]`, where `auth_opts`
  # is a map carrying the OIDC Core §3.1.2.1 authentication directives the host
  # must honour:
  #
  #   * `:prompt` - the parsed `prompt` list (OIDC Core §3.1.2.1).
  #   * `:force_reauth` - `true` when `prompt=login`: the host MUST
  #     reauthenticate the resource owner even if a session exists, and reflect
  #     a fresh `auth_time` in the returned subject.
  #   * `:max_age` - the request `max_age` (seconds) when present, else `nil`:
  #     the host MUST reauthenticate if the existing authentication is older than
  #     this, and MUST return the resulting `auth_time` (OIDC Core §3.1.2.1).
  #   * `:interactive` - `false` when `prompt=none`: the host MUST NOT render any
  #     UI; it returns `{:authenticated, subject}` only if a subject can be
  #     established silently, else `{:none}`.
  #
  # The host returns `{:authenticated, subject}`, `{:halt, conn}` (it took over
  # the connection to render login UI), or `{:none}` (no subject can be
  # established without UI - used under `prompt=none`).
  defp authenticate_resource_owner(conn, config, request) do
    case Config.authenticate_resource_owner_fun(config) do
      nil ->
        Logger.error(":authenticate_resource_owner callback is not configured")

        {:halt, emit_error(conn, config, request, @error_server_error)}

      callback ->
        Callback.invoke(callback, [conn, request, auth_opts(request)])
    end
  end

  # OIDC Core §3.1.2.1: assemble the authentication directives the host hook
  # must honour from the validated request. `prompt=login` forces reauth;
  # `prompt=none` forbids UI; `max_age` bounds the age of an acceptable existing
  # authentication.
  defp auth_opts(request) do
    %{
      prompt: request.prompt,
      force_reauth: @prompt_login in request.prompt,
      interactive: @prompt_none not in request.prompt,
      max_age: request.max_age
    }
  end

  # The host consent hook. Optional: when unset, consent is implicitly granted
  # for the authenticated subject (a deployment that wants an explicit consent
  # screen supplies the callback).
  defp consent(conn, config, request, subject) do
    case Config.consent_fun(config) do
      nil -> {:consented, subject}
      callback -> Callback.invoke(callback, [conn, request, subject])
    end
  end

  # OIDC Core §2: the subject identifier (`sub`) the code is issued for. A
  # subject without a usable identifier is a host/config fault; it surfaces as
  # an issuance error from `Attesto.AuthorizationCode.issue/3`
  # (`:invalid_subject`), which is reported as server_error.
  defp subject_id(subject) when is_map(subject), do: Map.get(subject, :subject)
  defp subject_id(_subject), do: nil

  defp client_id(config, client) do
    Callback.invoke(Config.client_id_fun(config), [client], nil)
  end

  defp code_store(config), do: Callback.config_callback(config, :code_store)

  # ── Redirect responses (RFC 6749 §4.1.2 / §4.1.2.1) ──────────────────────

  # ── Authorization response emission (query or JARM, JARM §2.3 / FAPI 2.0
  # Message Signing §5.4) ──────────────────────────────────────────────────
  #
  # Every authorization response - success or error - flows through
  # emit_response/6, which honours the request's `response_mode`: the RFC 6749
  # default `query`, or a JARM JWT mode that returns the response as a single
  # signed `response` JWT. The JARM audience is the request `client_id`.

  # RFC 6749 §4.1.2: success. The code and (when present) `state` are the
  # response parameters; under JARM `iss` rides inside the JWT (JARM §2.1), under
  # the query mode it is the RFC 9207 `iss` parameter (added in emit_response/6).
  defp emit_success(conn, config, request, code) do
    emit_response(
      conn,
      config,
      request.redirect_uri,
      request.response_mode,
      request.client_id,
      drop_nil(%{"code" => code, "state" => request.state})
    )
  end

  # RFC 6749 §4.1.2.1: error reported once the client/redirect_uri is trusted,
  # where the validated request (and so its response_mode) is known.
  defp emit_error(conn, config, request, error_code) do
    emit_response(
      conn,
      config,
      request.redirect_uri,
      request.response_mode,
      request.client_id,
      drop_nil(%{"error" => error_code, "state" => request.state})
    )
  end

  # RFC 6749 §4.1.2.1: error surfaced from Attesto.AuthorizationRequest as a
  # redirectable failure. The core enriches it with the requested response_mode
  # and the client_id (JARM audience) when the client is trusted; absent those,
  # effective_response_mode/1 falls back to the query encoding.
  defp emit_redirect_error(conn, config, error) do
    emit_response(
      conn,
      config,
      error.redirect_uri,
      Map.get(error, :response_mode),
      Map.get(error, :client_id),
      drop_nil(%{
        "error" => error.error,
        "error_description" => Map.get(error, :error_description),
        "state" => error.state
      })
    )
  end

  defp emit_response(conn, config, redirect_uri, response_mode, client_id, params) do
    case effective_response_mode(response_mode) do
      "query" ->
        do_redirect(conn, redirect_uri, Map.to_list(params) ++ iss_param(config))

      jwt_mode ->
        {:ok, response} =
          JARM.response_jwt(Config.to_attesto_config(config), client_id, params)

        deliver_jarm(conn, redirect_uri, jwt_mode, response)
    end
  end

  # JARM §2.3.2: `jwt` is shorthand for the response_type's default JWT mode,
  # which for the code flow is `query.jwt`. An absent response_mode is the
  # RFC 6749 default, `query`.
  defp effective_response_mode(nil), do: "query"
  defp effective_response_mode("jwt"), do: "query.jwt"
  defp effective_response_mode(mode), do: mode

  # JARM §2.3.1: deliver the signed response JWT per the requested mode.
  defp deliver_jarm(conn, redirect_uri, "query.jwt", response) do
    do_redirect(conn, redirect_uri, [{"response", response}])
  end

  defp deliver_jarm(conn, redirect_uri, "fragment.jwt", response) do
    location = redirect_uri <> "#" <> URI.encode_query([{"response", response}])

    conn
    |> put_resp_header("location", location)
    |> send_resp(:found, "")
  end

  defp deliver_jarm(conn, redirect_uri, "form_post.jwt", response) do
    conn
    |> put_resp_header("content-type", "text/html; charset=utf-8")
    |> send_resp(:ok, form_post_html(redirect_uri, response))
  end

  # OAuth 2.0 Form Post Response Mode: a minimal auto-submitting form that POSTs
  # the signed `response` to the redirect_uri. The action and value are HTML-
  # attribute-escaped; a noscript fallback keeps it usable without scripting.
  defp form_post_html(redirect_uri, response) do
    action = Plug.HTML.html_escape(redirect_uri)
    value = Plug.HTML.html_escape(response)

    """
    <!DOCTYPE html>
    <html>
    <head><title>Submitting…</title></head>
    <body onload="document.forms[0].submit()">
    <form method="post" action="#{action}">
    <input type="hidden" name="response" value="#{value}"/>
    <noscript><button type="submit">Continue</button></noscript>
    </form>
    </body>
    </html>
    """
  end

  defp drop_nil(params), do: :maps.filter(fn _key, value -> not is_nil(value) end, params)

  # RFC 9207: the authorization server's issuer identifier as the `iss` response
  # parameter for the query response mode (under JARM it is the JWT `iss` claim).
  defp iss_param(config) do
    if Callback.config_flag(config, :authorization_response_iss),
      do: [{"iss", config.issuer}],
      else: []
  end

  # RFC 6749 §3.1.2: parameters are appended to the redirect_uri's query
  # component, preserving any query already present in the registered URI.
  defp do_redirect(conn, redirect_uri, params) do
    location = append_query(redirect_uri, params)

    conn
    |> put_resp_header("location", location)
    |> send_resp(:found, "")
  end

  defp append_query(uri, params) do
    encoded = URI.encode_query(params)
    parsed = URI.parse(uri)

    new_query =
      case parsed.query do
        nil -> encoded
        existing -> existing <> "&" <> encoded
      end

    URI.to_string(%{parsed | query: new_query})
  end

  # ── Direct (non-redirectable) error page (OIDC Core §3.1.2.6) ─────────────

  # The request is untrusted (bad client_id / redirect_uri / transport), so the
  # error MUST NOT be redirected (open-redirect protection). It is rendered
  # directly to the user agent as a 400 body (OIDC Core §3.1.2.6). The response
  # is content-negotiated on the request's `Accept`: an `Accept: text/html`
  # request gets minimal HTML for a human reviewing it in a browser; other
  # callers keep the JSON body. The body is encoded and sent directly (not
  # through Phoenix content negotiation) so a user agent that arrived without an
  # `Accept` header still receives the error rather than a 406.
  defp render_direct_error(conn, _config, reason) do
    description = direct_error_description(reason)

    if accepts_html?(conn) do
      conn
      |> put_resp_content_type("text/html")
      |> send_resp(:bad_request, direct_error_html(description))
    else
      body =
        JSON.encode!(%{
          error: direct_error_code(reason),
          error_description: description
        })

      conn
      |> put_resp_content_type("application/json")
      |> send_resp(:bad_request, body)
    end
  end

  defp accepts_html?(conn) do
    conn
    |> get_req_header("accept")
    |> Enum.any?(fn value -> String.contains?(String.downcase(value), "text/html") end)
  end

  defp direct_error_html(description) do
    escaped_description = html_escape(description)

    """
    <!doctype html>
    <html lang="en">
      <head>
        <meta charset="utf-8">
        <meta name="viewport" content="width=device-width, initial-scale=1">
        <title>Authorization request error</title>
        <style>
          body {
            margin: 0;
            min-height: 100vh;
            display: grid;
            place-items: center;
            font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif;
            background: #f7f8fa;
            color: #1f2933;
          }

          main {
            width: min(560px, calc(100vw - 32px));
            padding: 32px;
            border: 1px solid #d8dee6;
            border-radius: 8px;
            background: white;
            box-shadow: 0 12px 32px rgba(15, 23, 42, 0.08);
          }

          h1 {
            margin: 0 0 12px;
            font-size: 24px;
            line-height: 1.2;
          }

          p {
            margin: 0;
            line-height: 1.5;
          }

          code {
            display: inline-block;
            margin-bottom: 16px;
            padding: 4px 8px;
            border-radius: 4px;
            background: #eef2f7;
            font-size: 14px;
          }
        </style>
      </head>
      <body>
        <main>
          <code>invalid_request</code>
          <h1>Authorization request error</h1>
          <p>#{escaped_description}</p>
        </main>
      </body>
    </html>
    """
  end

  defp html_escape(value) do
    value
    |> to_string()
    |> String.replace("&", "&amp;")
    |> String.replace("<", "&lt;")
    |> String.replace(">", "&gt;")
    |> String.replace("\"", "&quot;")
    |> String.replace("'", "&#39;")
  end

  defp direct_error_description(:insecure_transport), do: "TLS required"
  defp direct_error_description(:invalid_client_id), do: "client_id is invalid"
  defp direct_error_description(:missing_redirect_uri), do: "redirect_uri is required"
  defp direct_error_description(:invalid_redirect_uri), do: "redirect_uri is invalid"

  defp direct_error_description(:redirect_uri_not_registered),
    do: "redirect_uri is not registered for this client"

  defp direct_error_description(:invalid_request_uri),
    do: "the request_uri is unknown or has expired"

  defp direct_error_description(:request_uri_client_mismatch),
    do: "the request_uri was not issued to this client"

  defp direct_error_description(_), do: "invalid authorization request"

  # The OAuth error code rendered for a non-redirectable failure. RFC 9126 §2.2:
  # an unknown/expired `request_uri` is `invalid_request_uri`; a `request_uri`
  # replayed by a different client is reported as `invalid_request`. Everything
  # else (bad/absent client_id or redirect_uri) is the `invalid_request`
  # catch-all (OIDC Core §3.1.2.6).
  defp direct_error_code(:invalid_request_uri), do: "invalid_request_uri"
  defp direct_error_code(_reason), do: "invalid_request"

  # ── Audit / telemetry ────────────────────────────────────────────────────

  defp emit_code_issued(conn, config, client, scope) do
    Event.emit(config, :code_issued, %{
      client_id: client_id(config, client),
      scope: Enum.join(List.wrap(scope), " "),
      grant_type: "authorization_code",
      metadata: %{client_ip: RequestContext.client_ip(conn, config)}
    })
  end

  defp emit_denied(conn, config, client) do
    Event.emit(config, :authorization_denied, %{
      client_id: client_id(config, client),
      metadata: %{client_ip: RequestContext.client_ip(conn, config)}
    })
  end

  defp emit_failure(conn, config, reason) do
    Event.emit(config, :authorization_failed, %{
      result: reason,
      metadata: %{client_ip: RequestContext.client_ip(conn, config)}
    })
  end

  # ── Configuration resolution ─────────────────────────────────────────────

  defp resolve_config do
    otp_app = Application.get_env(:attesto_phoenix, :otp_app)
    Config.from_otp_app(otp_app, Config)
  end

  defp config_field(config, key, default) do
    case Map.get(config, key) do
      nil -> default
      value -> value
    end
  end

  # ── Helpers ──────────────────────────────────────────────────────────────

  defp put_optional(map, _key, nil), do: map
  defp put_optional(map, key, value), do: Map.put(map, key, value)
end
