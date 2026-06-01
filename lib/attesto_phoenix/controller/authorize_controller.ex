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
  alias Attesto.Secret
  alias AttestoPhoenix.{Config, Event, RequestContext}

  require Logger

  # RFC 6749 §4.1.2.1 error codes reported by redirect.
  @error_access_denied "access_denied"
  @error_server_error "server_error"

  # OIDC Core §3.1.2.6 error codes reported by redirect when prompt=none cannot
  # be satisfied without interaction.
  @error_login_required "login_required"
  @error_consent_required "consent_required"
  @error_interaction_required "interaction_required"

  # OIDC Core §3.1.2.1: the reserved scope value marking an OpenID Connect
  # Authentication Request, and the two `prompt` values this controller acts on.
  @openid_scope "openid"
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
         {:ok, client} <- load_client(config, params),
         {:ok, request} <- validate_request(config, client, params) do
      run_flow(conn, config, client, request)
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
        redirect_with_error(conn, error.redirect_uri, error.error, error.state)
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
        case invoke(config.load_client, [client_id]) do
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
  defp validate_request(config, client, params) do
    {params, par_resolved?} = resolve_request_uri(config, params)
    registered = registered_redirect_uris(config, client)

    with {:ok, request} <-
           AuthorizationRequest.validate(params,
             registered_redirect_uris: registered,
             require_nonce: require_nonce?(config, params),
             require_pkce: require_pkce?(config, client),
             request_object_jwks: client_jwks(config, client),
             request_object_audience: config.issuer
           ),
         :ok <- require_par_if_configured(config, request, par_resolved?) do
      {:ok, request}
    end
  end

  defp resolve_request_uri(config, %{"request_uri" => request_uri} = params)
       when is_binary(request_uri) and request_uri != "" do
    case par_store(config) do
      nil ->
        {params, false}

      store ->
        case fetch_par_request(store, request_uri) do
          {:ok, stored} -> {Map.merge(params, stored) |> Map.delete("request_uri"), true}
          :error -> {params, false}
        end
    end
  end

  defp resolve_request_uri(_config, params), do: {params, false}

  defp fetch_par_request(store, request_uri) do
    cond do
      function_exported?(store, :fetch, 1) -> store.fetch(request_uri)
      function_exported?(store, :take, 1) -> store.take(request_uri)
      true -> :error
    end
  end

  defp require_par_if_configured(config, request, false) do
    if config_flag(config, :require_pushed_authorization_requests) do
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
    case config_callback(config, :client_jwks) do
      nil ->
        nil

      callback ->
        case invoke(callback, [client]) do
          {:ok, jwks} -> jwks
          jwks when is_map(jwks) or is_list(jwks) -> jwks
          _other -> nil
        end
    end
  end

  # RFC 7636 / RFC 9700 §2.1.1: PKCE is required by default. A public client MUST
  # always use PKCE; a confidential client MAY be exempted, but only when the
  # host explicitly opts out via `require_pkce: false` (e.g. for an OIDC Basic
  # profile flow). Fail closed: absent the opt-out, PKCE is required.
  defp require_pkce?(config, client) do
    # Public clients MUST use PKCE (RFC 9700 §2.1.1) - `client_public?` forces it
    # regardless of config. For a confidential client the global `:require_pkce`
    # policy applies (default `true`); a host relaxes it for confidential clients
    # only by setting `require_pkce: false` on `AttestoPhoenix.Config`.
    client_public?(config, client) or config_flag(config, :require_pkce)
  end

  # The host's `:client_public?` callback classifies the client. Absent the
  # callback, fail closed by treating the client as public, so PKCE stays
  # required (a confidential exemption demands a deliberate host classification).
  defp client_public?(config, client) do
    case config_callback(config, :client_public?) do
      nil -> true
      callback -> invoke(callback, [client]) == true
    end
  end

  # OIDC Core §3.1.2.1: only an OpenID Connect Authentication Request (one whose
  # `scope` contains the reserved `openid` value) can be subject to the nonce
  # requirement. The scope is re-derived from the raw params here because the
  # normalized request does not exist yet (it is the output of `validate/2`);
  # `Attesto.Scope.valid_token?/1`-level validation is the core's job, so this
  # only splits on whitespace to look for `openid`.
  defp require_nonce?(config, params) do
    config_flag(config, :require_nonce) and openid_request?(params)
  end

  defp openid_request?(params) do
    case Map.get(params, "scope") do
      value when is_binary(value) -> @openid_scope in String.split(value, " ", trim: true)
      _ -> false
    end
  end

  defp registered_redirect_uris(config, client) do
    case invoke_with_default(config_callback(config, :client_redirect_uris), [client], []) do
      uris when is_list(uris) -> uris
      _ -> []
    end
  end

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
  defp run_flow(conn, config, client, request) do
    prompt_none? = @prompt_none in request.prompt

    case authenticate_resource_owner(conn, config, request) do
      {:authenticated, subject} ->
        run_consent(conn, config, client, request, subject, prompt_none?)

      {:none} ->
        # OIDC Core §3.1.2.6: the host has no already-authenticated subject it
        # can return without UI. Under `prompt=none` that is `login_required`
        # (never a UI render); otherwise the host should have halted to its
        # login page, so a bare `{:none}` here is a host/config fault.
        if prompt_none? do
          emit_failure(conn, config, @error_login_required)
          redirect_with_error(conn, request.redirect_uri, @error_login_required, request.state)
        else
          Logger.error("authenticate_resource_owner returned {:none} without prompt=none")
          redirect_with_error(conn, request.redirect_uri, @error_server_error, request.state)
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
          redirect_with_error(conn, request.redirect_uri, @error_login_required, request.state)
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
        redirect_with_error(conn, request.redirect_uri, error_code, request.state)

      other ->
        # A callback that returns no known shape is a host/config fault, not a
        # client error. Fail closed with the §4.1.2.1 server_error rather than
        # crash, and do not issue a code.
        Logger.error("authenticate_resource_owner returned #{inspect(other)}")
        redirect_with_error(conn, request.redirect_uri, @error_server_error, request.state)
    end
  end

  # OIDC Core §3.1.2.6: map the host's interaction-blocked reason to its error
  # code. Reported by redirect to the (already trusted) redirect_uri.
  defp interaction_error_code(:login_required), do: @error_login_required
  defp interaction_error_code(:consent_required), do: @error_consent_required
  defp interaction_error_code(:interaction_required), do: @error_interaction_required

  defp run_consent(conn, config, client, request, subject, prompt_none?) do
    case consent(conn, config, request, subject) do
      {:consented, subject} ->
        issue_and_redirect(conn, config, client, request, subject)

      {:halt, halted_conn} ->
        # OIDC Core §3.1.2.6: a consent screen is interactive UI, forbidden
        # under `prompt=none`; convert the halt to `consent_required`, built on
        # the ORIGINAL `conn` (never the host's halted one, which may already
        # carry a body) so the redirect is always well-formed.
        if prompt_none? do
          emit_failure(conn, config, @error_consent_required)
          redirect_with_error(conn, request.redirect_uri, @error_consent_required, request.state)
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
        redirect_with_error(conn, request.redirect_uri, error_code, request.state)

      other ->
        Logger.error("consent returned #{inspect(other)}")
        redirect_with_error(conn, request.redirect_uri, @error_server_error, request.state)
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
  defp issue_and_redirect(conn, config, client, request, subject) do
    attrs = %{
      client_id: client_id(config, client),
      redirect_uri: request.redirect_uri,
      code_challenge: request.code_challenge,
      code_challenge_method: request.code_challenge_method,
      subject: subject_id(subject),
      scope: request.scope,
      family_id: generate_family_id(),
      claims: code_claims(request, subject)
    }

    case AuthorizationCode.issue(code_store(config), attrs, ttl: config.authorization_code_ttl) do
      {:ok, code} ->
        emit_code_issued(conn, config, client, request.scope)
        redirect_with_code(conn, request.redirect_uri, code, request.state)

      {:error, reason} ->
        # Issuance failing on a validated request is a server/config fault, not
        # a client error (RFC 6749 §4.1.2.1 server_error). Do not leak detail.
        Logger.error("authorization code issuance failed: #{inspect(reason)}")
        redirect_with_error(conn, request.redirect_uri, @error_server_error, request.state)
    end
  end

  # OAuth 2.0 Security BCP §4.13 / §4.14: a fresh, unguessable family identifier
  # generated per issued code. `Attesto.AuthorizationCode` rides it onto the
  # redeemed grant so the token endpoint mints the refresh-token family under
  # this id, and code-reuse detection replays it to revoke the descendant
  # family. Generated with the same secret generator the codes themselves use.
  defp generate_family_id, do: Secret.generate()

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
    case config_callback(config, :authenticate_resource_owner) do
      nil ->
        Logger.error(":authenticate_resource_owner callback is not configured")

        {:halt,
         redirect_with_error(conn, request.redirect_uri, @error_server_error, request.state)}

      callback ->
        invoke(callback, [conn, request, auth_opts(request)])
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
    case config_callback(config, :consent) do
      nil -> {:consented, subject}
      callback -> invoke(callback, [conn, request, subject])
    end
  end

  # OIDC Core §2: the subject identifier (`sub`) the code is issued for. A
  # subject without a usable identifier is a host/config fault; it surfaces as
  # an issuance error from `Attesto.AuthorizationCode.issue/3`
  # (`:invalid_subject`), which is reported as server_error.
  defp subject_id(subject) when is_map(subject), do: Map.get(subject, :subject)
  defp subject_id(_subject), do: nil

  defp client_id(config, client) do
    invoke_with_default(config_callback(config, :client_id), [client], nil)
  end

  defp code_store(config), do: config_callback(config, :code_store)

  # ── Redirect responses (RFC 6749 §4.1.2 / §4.1.2.1) ──────────────────────

  # RFC 6749 §4.1.2: success redirect. The authorization code and (when present)
  # the request `state` are appended to the redirect_uri as query parameters.
  defp redirect_with_code(conn, redirect_uri, code, state) do
    params = [{"code", code}] ++ state_param(state) ++ iss_param()
    do_redirect(conn, redirect_uri, params)
  end

  # RFC 6749 §4.1.2.1: error redirect, echoing `state` when present.
  defp redirect_with_error(conn, redirect_uri, error_code, state) do
    params = [{"error", error_code}] ++ state_param(state) ++ iss_param()
    do_redirect(conn, redirect_uri, params)
  end

  defp state_param(nil), do: []
  defp state_param(state), do: [{"state", state}]

  defp iss_param do
    config = resolve_config()

    if config_flag(config, :authorization_response_iss),
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
  # directly to the user agent as a 400 body. Browser-driven conformance tests
  # need a visible page for manual review, so an `Accept: text/html` request gets
  # minimal HTML; non-browser callers keep the JSON body. The body is encoded and
  # sent directly (not through Phoenix content negotiation) so a user agent that
  # arrived without an `Accept` header still receives the error rather than a
  # 406.
  defp render_direct_error(conn, _config, reason) do
    description = direct_error_description(reason)

    if accepts_html?(conn) do
      conn
      |> put_resp_content_type("text/html")
      |> send_resp(:bad_request, direct_error_html(description))
    else
      body =
        JSON.encode!(%{
          error: "invalid_request",
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

  defp direct_error_description(_), do: "invalid authorization request"

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

  # Read a callback the frozen `AttestoPhoenix.Config` struct may not declare
  # as a named field yet (e.g. `:client_redirect_uris`,
  # `:authenticate_resource_owner`, `:consent`): pull it from the struct map.
  defp config_callback(config, key), do: Map.get(config, key)

  defp config_field(config, key, default) do
    case Map.get(config, key) do
      nil -> default
      value -> value
    end
  end

  # Read a boolean policy flag from the config struct, treating an absent or
  # non-boolean value as `false` (fail closed: a flag the host did not set never
  # turns a control on).
  defp config_flag(config, key), do: Map.get(config, key) == true

  # ── Helpers ──────────────────────────────────────────────────────────────

  defp put_optional(map, _key, nil), do: map
  defp put_optional(map, key, value), do: Map.put(map, key, value)

  # Callback invocation, mirroring the function/{m,f}/mfa forms the rest of the
  # library accepts (see `AttestoPhoenix.Config`).
  defp invoke(fun, args) when is_function(fun), do: apply(fun, args)

  defp invoke({module, fun}, args) when is_atom(module) and is_atom(fun),
    do: apply(module, fun, args)

  defp invoke({module, fun, extra}, args) when is_atom(module) and is_atom(fun),
    do: apply(module, fun, args ++ extra)

  defp invoke_with_default(nil, _args, default), do: default
  defp invoke_with_default(callback, args, _default), do: invoke(callback, args)
end
