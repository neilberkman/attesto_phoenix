defmodule AttestoPhoenix.Controller.IntrospectionController do
  @moduledoc """
  `POST /oauth/introspect` - OAuth 2.0 Token Introspection (RFC 7662), with the
  signed-JWT response of RFC 9701 (FAPI 2.0 Message Signing §5.5).

  This is the thin interface over the conn-free core `Attesto.Introspection`:
  it authenticates the calling client, lifts the `token` (and optional
  `token_type_hint`) off the request, asks the core whether the token is active,
  and renders the response - negotiating, by the `Accept` header, between the
  plain JSON response (RFC 7662 §2.2) and a signed JWT
  (`Attesto.SignedIntrospection`, `application/token-introspection+jwt`,
  RFC 9701). No introspection policy lives here; activeness, claim selection,
  and the no-existence-oracle discipline are all the core's (`Attesto.Token`
  signature/temporal/audience verification for access tokens, the
  `Attesto.RefreshStore` for refresh tokens).

  ## Client authentication (RFC 7662 §2.1)

  The endpoint authenticates the caller exactly as the token endpoint does,
  through the shared `AttestoPhoenix.ClientAuthentication` core
  (`client_secret_basic` / `client_secret_post` / `private_key_jwt`). Failure
  is fail-closed `invalid_client` (as the token and PAR endpoints, the shared
  `ClientAuthentication` core returns these with HTTP 400). The authenticated
  `client_id` is the audience of a signed response (RFC 9701 §5).

  ## Caching (RFC 6749 §5.1)

  Every response carries `Cache-Control: no-store` and `Pragma: no-cache`.

  ## Configuration

  Reads `AttestoPhoenix.Config` from the application environment (the same
  source the token endpoint uses): `:load_client` / `:verify_client_secret`
  (client authentication), `:keystore` / `:issuer` (signing the RFC 9701
  response), and `:refresh_store` (consulted for opaque refresh tokens).
  """

  use Phoenix.Controller, formats: [:json]

  import Plug.Conn

  alias Attesto.Introspection
  alias Attesto.SignedIntrospection
  alias AttestoPhoenix.{Callback, ClientAuthentication, Config, OAuthError, RequestContext}
  alias AttestoPhoenix.ClientAuthentication.Policy

  # RFC 9701 §4: the media type a caller requests (via Accept) to receive the
  # introspection response as a signed JWT, and the type of that response.
  @signed_media_type "application/token-introspection+jwt"

  # RFC 7523 §3: the maximum client-assertion lifetime, matching the token
  # endpoint.
  @client_assertion_max_lifetime 300

  # The Attesto.RefreshStore consulted for opaque refresh tokens, defaulting to
  # the package's Ecto-backed store when the host configures none.
  @default_refresh_store AttestoPhoenix.Store.EctoRefreshStore

  @cache_control_no_store "no-store"
  @pragma_no_cache "no-cache"

  @error_invalid_request "invalid_request"

  @doc """
  Handle `POST /oauth/introspect` (RFC 7662 §2.1).

  Authenticates the client, introspects the presented token, and renders the
  RFC 7662 response - as JSON, or as an RFC 9701 signed JWT when the caller's
  `Accept` requests `#{@signed_media_type}`.
  """
  @spec create(Plug.Conn.t(), map()) :: Plug.Conn.t()
  def create(conn, params) when is_map(params) do
    config = resolve_config()
    conn = put_no_store_headers(conn)

    with :ok <- check_https(conn, config),
         {:ok, client} <- authenticate_client(config, conn, params),
         {:ok, token} <- fetch_token(params) do
      respond(conn, config, client, token, params)
    else
      {:error, %OAuthError{} = err} -> render_error(conn, err)
    end
  end

  defp respond(conn, config, client, token, params) do
    protocol_config = Config.to_attesto_config(config)

    response =
      Introspection.introspect(protocol_config, token,
        refresh_store: refresh_store(config),
        token_type_hint: token_type_hint(params)
      )

    if signed_response_requested?(conn) do
      {:ok, jwt} =
        SignedIntrospection.response_jwt(protocol_config, client_id(config, client), response)

      conn
      |> put_resp_header("content-type", @signed_media_type)
      |> send_resp(:ok, jwt)
    else
      json(conn, response)
    end
  end

  # RFC 9701 §4: the signed response is returned only when the caller asks for
  # it via the Accept header; otherwise the plain JSON response is returned.
  defp signed_response_requested?(conn) do
    conn
    |> get_req_header("accept")
    |> Enum.any?(&String.contains?(&1, @signed_media_type))
  end

  defp fetch_token(%{"token" => token}) when is_binary(token) and token != "", do: {:ok, token}

  defp fetch_token(_params),
    do:
      {:error,
       error(@error_invalid_request, "the request is missing the required \"token\" parameter")}

  defp token_type_hint(%{"token_type_hint" => hint}) when is_binary(hint) and hint != "", do: hint
  defp token_type_hint(_params), do: nil

  defp refresh_store(%Config{refresh_store: store}) when is_atom(store) and not is_nil(store),
    do: store

  defp refresh_store(%Config{}), do: @default_refresh_store

  defp check_https(conn, config) do
    case RequestContext.check_https(conn, config) do
      :ok -> :ok
      {:error, :insecure_transport} -> {:error, error(@error_invalid_request, "TLS required")}
    end
  end

  # RFC 6749 §2.3 / RFC 7662 §2.1: authenticate the caller through the shared
  # ClientAuthentication core, the same policy as the token endpoint. A client
  # assertion may be audienced to the issuer or the introspection endpoint URL
  # (RFC 7523 §3), both derived from trusted Config (never the request Host).
  defp authenticate_client(config, conn, params) do
    policy = %Policy{
      allow_public: false,
      assertion_audiences: [config.issuer, Config.introspection_endpoint_url(config)],
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

  defp client_id(config, client), do: Callback.invoke(Config.client_id_fun(config), [client], nil)

  defp render_error(conn, %OAuthError{} = err) do
    conn
    |> merge_resp_headers(err.headers)
    |> put_status(err.status)
    |> json(error_body(err.error, err.error_description))
  end

  defp error_body(code, nil), do: %{error: code}
  defp error_body(code, description), do: %{error: code, error_description: description}

  defp error(code, description),
    do: OAuthError.new(String.to_existing_atom(code), description, status: 400)

  defp put_no_store_headers(conn) do
    conn
    |> put_resp_header("cache-control", @cache_control_no_store)
    |> put_resp_header("pragma", @pragma_no_cache)
  end

  defp resolve_config do
    otp_app = Application.get_env(:attesto_phoenix, :otp_app)
    Config.from_otp_app(otp_app, Config)
  end
end
