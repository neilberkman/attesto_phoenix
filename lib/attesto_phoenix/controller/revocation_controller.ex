defmodule AttestoPhoenix.Controller.RevocationController do
  @moduledoc """
  `POST /oauth/revoke` - OAuth 2.0 Token Revocation (RFC 7009).

  A client presents a credential it issued and asks the authorization
  server to invalidate it. This endpoint revokes the *refresh* credential:
  revoking one refresh token tears down its whole family (every token
  descended from the same authorization), via the configured
  `Attesto.RefreshStore`. Access tokens are stateless, short-lived JWTs
  with no server-side state to drop, so a hint pointing at one is honored
  as a no-op success rather than an error (RFC 7009 §2.2).

  ## Client authentication (RFC 7009 §2.1, RFC 6749 §2.3)

  The revocation endpoint requires the same client authentication as the
  token endpoint. A confidential client authenticates with
  `client_secret_basic` (HTTP Basic) or `client_secret_post` (form
  parameters). Authentication is fail-closed: a request that names a
  client but does not prove the secret is rejected `invalid_client`
  (HTTP 401, RFC 6749 §5.2), and a request that names no client at all is
  likewise rejected, since this endpoint serves confidential clients. The
  authenticated `client_id` is then threaded into revocation so one client
  cannot revoke another client's tokens (RFC 7009 §2.1).

  Client lookup and secret comparison are delegated to the host through the
  `:load_client` and `:verify_client_secret` configuration callbacks; this
  controller owns no client registry.

  ## No-existence oracle (RFC 7009 §2.2)

  Once the client is authenticated, the response is always `HTTP 200` with
  an empty body, whether or not the presented token existed, was expired,
  or was already revoked. A revocation endpoint must not let a caller probe
  which tokens are live. The only non-200 outcomes are a malformed request
  (`invalid_request`, missing the required `token` parameter) and failed
  client authentication (`invalid_client`).

  ## Caching (RFC 6749 §5.1)

  Every response carries `Cache-Control: no-store` and `Pragma: no-cache`,
  so an intermediary never caches a revocation result.

  ## Configuration

  Built on `AttestoPhoenix.Config`. The callbacks this controller reads:

    * `:load_client` - resolve an OAuth client by `client_id`.
    * `:verify_client_secret` - constant-time client-secret comparison.
    * `:on_event` (optional) - audit/telemetry hook; receives a
      `:token_revoked` `AttestoPhoenix.Event` after a successful revocation
      request.

  The configured `AttestoPhoenix.Config` is read from
  `conn.private[:attesto_phoenix_config]`, placed there by the host's
  router pipeline. The `Attesto.RefreshStore` revocation runs over defaults
  to the package's Ecto-backed store; a host pipeline may override it by
  putting a module under `conn.private[:attesto_phoenix_refresh_store]`.
  """

  use Phoenix.Controller, formats: [:json]

  import Plug.Conn

  alias Attesto.Revocation
  alias AttestoPhoenix.Callback
  alias AttestoPhoenix.Config
  alias AttestoPhoenix.Event

  # Dispatch through the action plug so the module is a complete `Plug`
  # (`init/1` + `call/2`): the router invokes it as a plug, selecting the
  # action from `conn.private[:phoenix_action]` set by `init/1`.
  alias AttestoPhoenix.Store.EctoRefreshStore

  plug :action

  # RFC 7009 §2.2: a successful revocation request returns HTTP 200 with an
  # empty body.
  @http_ok 200

  # RFC 6749 §5.2: a malformed request is `400 invalid_request`; failed
  # client authentication is `401 invalid_client`.
  @http_bad_request 400
  @http_unauthorized 401

  # RFC 6749 §5.2 error codes.
  @error_invalid_request "invalid_request"
  @error_invalid_client "invalid_client"

  # RFC 6749 §5.1: every response from a token-family endpoint must be marked
  # uncacheable.
  @no_store_headers [{"cache-control", "no-store"}, {"pragma", "no-cache"}]

  # RFC 6749 §2.3.1: HTTP Basic credentials are the userid:password (here
  # client_id:client_secret) joined by a single colon.
  @basic_credentials_separator ":"

  # RFC 7009 §2.1: the form parameter carrying the credential to revoke, and
  # the optional hint about its type (RFC 7009 §2.1).
  @token_param "token"
  @token_type_hint_param "token_type_hint"

  # RFC 6749 §2.3.1: client_secret_post form parameters.
  @client_id_param "client_id"
  @client_secret_param "client_secret"

  # The configured AttestoPhoenix.Config is threaded through the connection's
  # private storage by the host pipeline.
  @config_key :attesto_phoenix_config

  # The Attesto.RefreshStore module revocation runs over. The package ships
  # an Ecto-backed implementation (parameterized by the configured repo) as
  # the default; the host pipeline may override it through conn.private to
  # select a different Attesto.RefreshStore (e.g. the single-node ETS store).
  @refresh_store_key :attesto_phoenix_refresh_store
  @default_refresh_store EctoRefreshStore

  @doc """
  Handle `POST /oauth/revoke` (RFC 7009 §2.1).

  Authenticates the client, then revokes the presented refresh token and
  its family. Always responds `200` once the client is authenticated,
  regardless of whether the token existed.
  """
  @spec create(Plug.Conn.t(), map()) :: Plug.Conn.t()
  def create(conn, params) when is_map(params) do
    config = fetch_config!(conn)
    # RFC 6749 §5.1: success and error responses alike carry no-store.
    conn = put_no_store_headers(conn)

    with {:ok, client_id, client_secret} <- client_credentials(conn, params),
         {:ok, _client} <- authenticate_client(config, client_id, client_secret),
         {:ok, token} <- fetch_token(params) do
      revoke_token(conn, config, client_id, token, params)
    else
      {:error, :invalid_request} ->
        # RFC 7009 §2.1 / RFC 6749 §5.2: the required `token` parameter is
        # missing or otherwise malformed.
        send_oauth_error(
          conn,
          @http_bad_request,
          @error_invalid_request,
          "the request is missing the required \"token\" parameter"
        )

      {:error, :invalid_client} ->
        # RFC 6749 §5.2: client authentication failed. This endpoint serves
        # confidential clients authenticating with HTTP Basic, so the 401
        # carries a Basic `WWW-Authenticate` challenge.
        conn
        |> put_resp_header("www-authenticate", "Basic")
        |> send_oauth_error(
          @http_unauthorized,
          @error_invalid_client,
          "client authentication failed"
        )
    end
  end

  defp revoke_token(conn, config, client_id, token, params) do
    # RFC 7009 §2.1: bind the revocation to the authenticated client so a
    # client cannot revoke another client's tokens. `Attesto.Revocation`
    # returns `:ok` for an unknown, expired, or already-revoked token
    # (no-existence oracle, RFC 7009 §2.2), and `{:error,
    # :unauthorized_client}` when the token is bound to a different client.
    case Revocation.revoke(refresh_store(conn), token, client_id: client_id) do
      :ok ->
        # The token was unknown to this client OR was revoked; either way the
        # response is an indistinguishable empty 200 (no-existence oracle).
        # The audit event is emitted only on this authenticated, accepted
        # revocation request.
        emit_revoked(config, client_id, params)

      {:error, :unauthorized_client} ->
        # RFC 7009 §2.2: the authenticated client does not own this token, so
        # nothing is revoked. The endpoint must NOT reveal that the token
        # exists under another client, so it still answers an empty 200
        # rather than an error, and emits no revocation event.
        :ok
    end

    conn
    |> send_resp(@http_ok, "")
    |> halt()
  end

  # RFC 6749 §2.3.1: a confidential client authenticates with either HTTP
  # Basic (client_secret_basic) or request-body parameters
  # (client_secret_post). Basic takes precedence when present. A request
  # that carries neither is treated as failed client authentication, since
  # this endpoint serves confidential clients (fail-closed).
  defp client_credentials(conn, params) do
    case basic_credentials(conn) do
      {:ok, client_id, client_secret} ->
        {:ok, client_id, client_secret}

      # RFC 6749 §2.3.1: a present-but-malformed Basic credential fails
      # authentication; it does not fall back to body parameters.
      {:error, :invalid_client} = error ->
        error

      :none ->
        post_credentials(params)
    end
  end

  defp basic_credentials(conn) do
    case get_req_header(conn, "authorization") do
      ["Basic " <> encoded | _rest] ->
        decode_basic(encoded)

      _absent ->
        :none
    end
  end

  defp decode_basic(encoded) do
    with {:ok, decoded} <- Base.decode64(encoded),
         [client_id, client_secret] <-
           String.split(decoded, @basic_credentials_separator, parts: 2) do
      {:ok, URI.decode_www_form(client_id), URI.decode_www_form(client_secret)}
    else
      # RFC 6749 §2.3.1: a malformed Basic credential is a failed
      # authentication, not a free pass.
      _malformed -> {:error, :invalid_client}
    end
  end

  defp post_credentials(params) do
    case {Map.get(params, @client_id_param), Map.get(params, @client_secret_param)} do
      {client_id, client_secret}
      when is_binary(client_id) and is_binary(client_secret) ->
        {:ok, client_id, client_secret}

      _absent ->
        # No client_secret_basic and no usable client_secret_post: this
        # confidential-client endpoint rejects the request.
        {:error, :invalid_client}
    end
  end

  defp authenticate_client(config, client_id, client_secret) when is_binary(client_id) and is_binary(client_secret) do
    # RFC 6749 §5.2: an unknown or revoked client, and a wrong secret, all
    # surface to the caller as the same `invalid_client` so the endpoint is
    # not an existence oracle for client ids.
    with {:ok, client} <- Callback.invoke(Config.load_client_fun(config), [client_id]),
         true <- Callback.invoke(Config.verify_client_secret_fun(config), [client, client_secret]) do
      {:ok, client}
    else
      _failed -> {:error, :invalid_client}
    end
  end

  defp fetch_token(params) do
    case Map.get(params, @token_param) do
      token when is_binary(token) and token != "" ->
        {:ok, token}

      # RFC 7009 §2.1: `token` is REQUIRED.
      _missing ->
        {:error, :invalid_request}
    end
  end

  # Audit/telemetry hook (RFC 7009 leaves auditing to the deployment). The
  # `:on_event` callback is optional, so a config without one is a silent
  # no-op. The event is emitted only after a successful, authenticated
  # revocation request; its metadata carries the optional `token_type_hint`
  # for context but never the token value.
  defp emit_revoked(%Config{on_event: nil}, _client_id, _params), do: :ok

  defp emit_revoked(%Config{on_event: on_event}, client_id, params) do
    event =
      Event.new(:token_revoked,
        client_id: client_id,
        metadata: %{token_type_hint: Map.get(params, @token_type_hint_param)}
      )

    Callback.invoke(on_event, [event])
    :ok
  end

  defp put_no_store_headers(conn) do
    Enum.reduce(@no_store_headers, conn, fn {key, value}, acc ->
      put_resp_header(acc, key, value)
    end)
  end

  # RFC 6749 §5.2: an error response is `application/json` carrying the
  # `error` code and a human-readable `error_description`.
  defp send_oauth_error(conn, status, error, description) do
    body = JSON.encode!(%{"error" => error, "error_description" => description})

    conn
    |> put_resp_content_type("application/json")
    |> send_resp(status, body)
    |> halt()
  end

  defp refresh_store(conn) do
    Map.get(conn.private, @refresh_store_key, @default_refresh_store)
  end

  defp fetch_config!(conn) do
    case conn.private do
      %{@config_key => %Config{} = config} ->
        config

      _missing ->
        raise ArgumentError,
              "AttestoPhoenix.Controller.RevocationController: no %AttestoPhoenix.Config{} " <>
                "in conn.private[#{inspect(@config_key)}]; wire the host pipeline that assigns it"
    end
  end
end
