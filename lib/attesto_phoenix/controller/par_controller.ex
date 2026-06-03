defmodule AttestoPhoenix.Controller.PARController do
  @moduledoc """
  Pushed Authorization Request endpoint (RFC 9126).

  The endpoint authenticates the client, stores the submitted authorization
  request parameters behind a `request_uri`, and returns that reference to be
  used at `/oauth/authorize`. The authorization endpoint still performs the
  normal client/redirect/scope/PKCE validation when the reference is resolved.

  This controller is a thin adapter: it parses the request off the `Plug.Conn`,
  authenticates the client via `AttestoPhoenix.ClientAuthentication`
  (RFC 6749 §2.3), lifts the DPoP facts into a `%PAR.Request{}` of plain data,
  and calls `AttestoPhoenix.AuthorizationServer.PAR.store/2`. Every storage,
  credential-stripping, and DPoP-binding decision lives in that conn-free core.
  """

  use Phoenix.Controller, formats: [:json]

  import Plug.Conn

  alias AttestoPhoenix.AuthorizationServer.PAR
  alias AttestoPhoenix.{ClientAuthentication, Config, OAuthError, RequestContext}
  alias AttestoPhoenix.ClientAuthentication.Policy

  @cache_control_no_store "no-store"
  @pragma_no_cache "no-cache"
  @error_invalid_request "invalid_request"
  @dpop_request_header "dpop"
  @client_assertion_max_lifetime 300

  @spec create(Plug.Conn.t(), map()) :: Plug.Conn.t()
  def create(conn, params) do
    config = resolve_config()
    conn = put_no_store(conn)

    with :ok <- RequestContext.check_https(conn, config),
         {:ok, client} <- authenticate_client(config, conn, params),
         {:ok, stored} <- PAR.store(config, par_request(config, conn, client, params)) do
      conn
      |> put_status(:created)
      |> json(stored)
    else
      {:error, :insecure_transport} ->
        render_error(conn, @error_invalid_request, "TLS required")

      {:error, %OAuthError{} = err} ->
        render_error(conn, Atom.to_string(err.error), err.error_description)
    end
  end

  defp resolve_config do
    otp_app = Application.get_env(:attesto_phoenix, :otp_app)
    Config.from_otp_app(otp_app, Config)
  end

  # RFC 6749 §2.3: client authentication is delegated to the conn-free core
  # `AttestoPhoenix.ClientAuthentication`, shared with the token endpoint. The
  # PAR endpoint's policy: a request reference established without proof of
  # possession of the client secret would let anyone who knows a confidential
  # client's `client_id` push requests in its name, so the secretless
  # public-client path is refused here (`allow_public: false`); a client
  # assertion may be audienced to either the issuer identifier or the concrete
  # endpoint URL it is presented at (RFC 7523 §3 / OIDC Core §9), both derived
  # from trusted `Config` (never the request `Host`), and lives at most
  # `@client_assertion_max_lifetime` seconds (RFC 7523 §3).
  defp authenticate_client(config, conn, params) do
    policy = %Policy{
      allow_public: false,
      assertion_audiences: [config.issuer, Config.par_endpoint_url(config)],
      assertion_max_lifetime: @client_assertion_max_lifetime
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

  # Lift the conn facts the PAR core needs into a `%PAR.Request{}` of plain
  # data: the authenticated client, the request body, and the conn-free DPoP
  # facts (RFC 9449 §4.1 / §4.2 / §4.3 - the `DPoP` request-header values and
  # the canonical request URL/method the proof is bound to). The core reads
  # only this data; it never touches the conn.
  defp par_request(config, conn, client, params) do
    %PAR.Request{
      client: client,
      params: params,
      dpop_input: %{
        proofs: get_req_header(conn, @dpop_request_header),
        http_uri: RequestContext.canonical_url(conn, config),
        http_method: RequestContext.http_method(conn)
      }
    }
  end

  defp put_no_store(conn) do
    conn
    |> put_resp_header("cache-control", @cache_control_no_store)
    |> put_resp_header("pragma", @pragma_no_cache)
  end

  defp render_error(conn, code, desc) do
    conn
    |> put_status(:bad_request)
    |> json(%{error: code, error_description: desc})
  end
end
