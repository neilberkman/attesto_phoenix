defmodule AttestoPhoenix.Controller.TokenController do
  @moduledoc """
  OAuth 2.0 token endpoint (RFC 6749 §3.2).

  Handles `POST /oauth/token`. This module owns the HTTP and protocol-framing
  concerns only: it resolves the host `%AttestoPhoenix.Config{}`, applies the
  no-store cache headers (RFC 7234 §5.2), authenticates the client (RFC 6749
  §2.3), lifts the request and the relevant conn facts into a plain
  `AttestoPhoenix.AuthorizationServer.Token.Request`, calls the conn-free core
  `AttestoPhoenix.AuthorizationServer.Token.issue/1`, emits the audit events the
  core returns as data, and renders the RFC 6749 §5.1 success body or the
  RFC 6749 §5.2 error body. It carries no business-domain logic; every grant,
  claim, and policy decision lives in the core or behind a
  `AttestoPhoenix.Config` callback.

  ## Grant types

    * `authorization_code` (RFC 6749 §4.1.3) with mandatory PKCE (RFC 7636).
    * `refresh_token` (RFC 6749 §6) with rotation and reuse detection
      (RFC 6749 §10.4, OAuth 2.0 Security BCP).
    * `client_credentials` (RFC 6749 §4.4).
    * OAuth token exchange (RFC 8693).

  ## Client authentication

  Accepts HTTP Basic credentials (RFC 6749 §2.3.1, RFC 7617), request-body
  credentials (RFC 6749 §2.3.1), and `private_key_jwt` assertions (RFC 7523 /
  OIDC Core §9). Presenting more than one client-authentication method is
  rejected (RFC 6749 §2.3). Confidential clients must authenticate; a client
  identified without a secret/assertion is admitted only when the host's
  `:client_public?` callback marks it public, in which case it relies on PKCE
  (RFC 7636) instead.

  ## Responses

  Success renders the RFC 6749 §5.1 body; failure renders the RFC 6749 §5.2
  error body. Both carry no-store cache headers (RFC 7234 §5.2) so credentials
  are never cached by an intermediary. A `use_dpop_nonce` error carries the
  fresh `DPoP-Nonce` header (RFC 9449 §8) verbatim in its `:headers`.

  ## Configuration

  All host policy is resolved through `AttestoPhoenix.Config`; nothing is
  hardcoded here. See `AttestoPhoenix.AuthorizationServer.Token` for the
  grant/claim policy callbacks the core reads, and `AttestoPhoenix.Config` for
  the authoritative definitions and defaults.
  """

  use Phoenix.Controller, formats: [:json]

  import Plug.Conn

  alias AttestoPhoenix.AuthorizationServer.Token
  alias AttestoPhoenix.AuthorizationServer.Token.Request
  alias AttestoPhoenix.{Callback, ClientAuthentication, Config, Event, OAuthError, RequestContext}
  alias AttestoPhoenix.ClientAuthentication.Policy

  # RFC 7234 §5.2: token responses and errors must never be cached.
  @cache_control_no_store "no-store"
  @pragma_no_cache "no-cache"

  # RFC 6749 §5.2 error codes the framing layer raises before the core runs.
  @error_invalid_request "invalid_request"

  # RFC 9449 §4.1: the DPoP proof request header read off the conn and passed
  # to the core as data.
  @dpop_request_header "dpop"

  # RFC 9449 §4.2: the token endpoint is reached by POST, so the proof's `htm`
  # claim must equal this.
  @http_method_post "POST"

  # RFC 7523 / OIDC Core §9: client assertions are short-lived JWTs whose `jti`
  # is consumed once by the authorization server.
  @client_assertion_max_lifetime 300

  @doc """
  Token endpoint action (RFC 6749 §3.2).

  Authenticates the client, delegates the grant to the core, emits the returned
  audit events, and renders either the RFC 6749 §5.1 success body or an
  RFC 6749 §5.2 error. Every response carries no-store cache headers
  (RFC 7234 §5.2).
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
        deny(config, conn, params, nil, error(@error_invalid_request, "TLS required"))
    end
  end

  defp create_checked(config, conn, params) do
    case authenticate_client(config, conn, params) do
      {:ok, client} ->
        create_authenticated(config, conn, params, client)

      {:error, %OAuthError{} = err} ->
        deny(config, conn, params, nil, err)
    end
  end

  defp create_authenticated(config, conn, params, client) do
    case fetch_grant_type(params) do
      {:ok, grant_type} ->
        issue(config, conn, params, client, grant_type)

      {:error, %OAuthError{} = err} ->
        # A valid client without a grant_type: the core never runs, so the
        # framing layer emits the denial event (the resolved client's id is
        # known, but no grant_type was parsed).
        deny(config, conn, params, client, err)
    end
  end

  defp issue(config, conn, params, client, grant_type) do
    request = build_request(config, conn, params, client, grant_type)

    case Token.issue(config, request) do
      {:ok, response, events} ->
        emit_all(config, events)

        conn
        |> put_status(:ok)
        |> json(response)

      {:error, %OAuthError{} = err, events} ->
        emit_all(config, events)
        render_error(conn, err)
    end
  end

  # ── Request building (conn -> data) ──────────────────────────────────────

  # Lift the request and the conn facts the core needs into a plain
  # `Token.Request`. The sender-constraint input (RFC 9449 / RFC 8705) is parsed
  # off the conn here; the core reads only this data. `client_ip` and the
  # request-derived `client_id` are carried for the audit events the core builds.
  defp build_request(config, conn, params, client, grant_type) do
    %Request{
      config: config,
      client: client,
      grant_type: grant_type,
      params: params,
      sender_constraint_input: sender_constraint_input(config, conn),
      client_ip: RequestContext.client_ip(conn, config),
      request_client_id: request_client_id(conn, params)
    }
  end

  defp sender_constraint_input(config, conn) do
    %{
      dpop_proof: first_dpop_proof(conn),
      mtls_cert_der: RequestContext.cert_der(conn, config),
      http_uri: RequestContext.canonical_url(conn, config),
      http_method: @http_method_post
    }
  end

  defp first_dpop_proof(conn) do
    case get_req_header(conn, @dpop_request_header) do
      [proof | _] -> proof
      _ -> nil
    end
  end

  # ── Configuration resolution ─────────────────────────────────────────────

  # The validated `%AttestoPhoenix.Config{}` is resolved from the host's
  # `:otp_app` configuration so the controller holds no policy of its own.
  defp resolve_config do
    otp_app = Application.get_env(:attesto_phoenix, :otp_app)
    Config.from_otp_app(otp_app, Config)
  end

  # ── Client authentication (RFC 6749 §2.3) ────────────────────────────────

  # RFC 6749 §2.3: client authentication is delegated to the conn-free core
  # `AttestoPhoenix.ClientAuthentication`, shared with the PAR endpoint. The
  # token endpoint's policy: a body `client_id` without a secret is the
  # public-client path (RFC 6749 §2.1), so `allow_public: true`; the client
  # assertion MUST be audienced to the issuer identifier (FAPI 2.0 Security
  # Profile §5.3.2.1), derived from trusted `Config` (never the request `Host`) -
  # the concrete endpoint URL is NOT accepted as `aud`, so a confused-deputy
  # assertion minted for a different endpoint is rejected. The assertion lives at
  # most `@client_assertion_max_lifetime` seconds (RFC 7523 §3).
  defp authenticate_client(config, conn, params) do
    policy = %Policy{
      allow_public: true,
      assertion_audiences: [config.issuer],
      assertion_max_lifetime: @client_assertion_max_lifetime,
      assertion_signing_algs: config.client_auth_signing_algs
    }

    case ClientAuthentication.authenticate(
           get_req_header(conn, "authorization"),
           params,
           config,
           policy
         ) do
      {:ok, %ClientAuthentication.Result{client: client}} -> {:ok, client}
      {:error, %OAuthError{}} = err -> err
    end
  end

  defp fetch_grant_type(%{"grant_type" => gt}) when is_binary(gt) and gt != "",
    do: {:ok, gt}

  defp fetch_grant_type(_params),
    do: {:error, error(@error_invalid_request, "missing grant_type")}

  # ── Audit / telemetry ────────────────────────────────────────────────────

  # The core returns audit events as data; the controller emits them. A
  # framing-layer denial (TLS, client auth, missing grant_type) never reaches
  # the core, so the controller builds that one denial event itself.
  defp emit_all(config, events) do
    Enum.each(events, &Event.dispatch(Config.on_event_fun(config), &1))
  end

  # Build and emit the RFC 6749 §5.2 denial event for a framing-layer failure,
  # then render the error. Mirrors the core's denial event for the fields a
  # pre-core failure can know: there is no resolved grant_type for a missing-
  # grant or client-auth failure, and the client may be unauthenticated.
  defp deny(config, conn, params, client, %OAuthError{} = err) do
    code = Atom.to_string(err.error)

    Event.emit(config, :token_denied, %{
      client_id: denial_client_id(config, conn, params, client),
      scope: optional_param(params, "scope"),
      grant_type: optional_param(params, "grant_type"),
      result: code,
      metadata:
        %{
          client_ip: RequestContext.client_ip(conn, config),
          error: code,
          error_description: err.error_description,
          http_status: err.status,
          sender_constraint: sender_constraint_context(config, conn)
        }
        |> Enum.reject(fn {_key, value} -> is_nil(value) end)
        |> Map.new()
    })

    render_error(conn, err)
  end

  defp denial_client_id(config, conn, params, client) when not is_nil(client) do
    client_id(config, client) || request_client_id(conn, params)
  end

  defp denial_client_id(_config, conn, params, _client) do
    request_client_id(conn, params)
  end

  defp client_id(config, client) do
    Callback.invoke(Config.client_id_fun(config), [client], nil)
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
      dpop_present: get_req_header(conn, @dpop_request_header) != [],
      mtls_cert_present: is_binary(RequestContext.cert_der(conn, config))
    }
  end

  # ── Rendering (RFC 6749 §5.2) ────────────────────────────────────────────

  defp render_error(conn, %OAuthError{} = err) do
    conn
    |> merge_resp_headers(err.headers)
    |> put_status(err.status)
    |> json(error_body(err.error, err.error_description))
  end

  # RFC 6749 §5.2 error response body.
  defp error_body(code, nil), do: %{error: code}
  defp error_body(code, description), do: %{error: code, error_description: description}

  # The single error value the controller raises at the framing edge is an
  # `%AttestoPhoenix.OAuthError{}` (the shape the core and the
  # `ClientAuthentication` core also return). The string `@error_*` codes are
  # the RFC 6749 §5.2 wire values; they convert to the matching atom code here.
  defp error(code, description), do: OAuthError.new(error_code(code), description, status: 400)

  defp error_code(code) when is_binary(code), do: String.to_existing_atom(code)

  defp optional_param(params, key) do
    case params[key] do
      value when is_binary(value) and value != "" -> value
      _ -> nil
    end
  end

  defp put_no_store_headers(conn) do
    conn
    |> put_resp_header("cache-control", @cache_control_no_store)
    |> put_resp_header("pragma", @pragma_no_cache)
  end
end
