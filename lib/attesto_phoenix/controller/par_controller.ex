defmodule AttestoPhoenix.Controller.PARController do
  @moduledoc """
  Pushed Authorization Request endpoint (RFC 9126).

  The endpoint authenticates the client, stores the submitted authorization
  request parameters behind a `request_uri`, and returns that reference to be
  used at `/oauth/authorize`. The authorization endpoint still performs the
  normal client/redirect/scope/PKCE validation when the reference is resolved.
  """

  use Phoenix.Controller, formats: [:json]

  import Plug.Conn

  alias Attesto.ClientAssertion
  alias Attesto.DPoP.ReplayCache
  alias AttestoPhoenix.{Config, RequestContext}

  @cache_control_no_store "no-store"
  @pragma_no_cache "no-cache"
  @error_invalid_client "invalid_client"
  @error_invalid_request "invalid_request"
  @client_assertion_max_lifetime 300

  @spec create(Plug.Conn.t(), map()) :: Plug.Conn.t()
  def create(conn, params) do
    config = resolve_config()
    conn = put_no_store(conn)

    with :ok <- RequestContext.check_https(conn, config),
         {:ok, client} <- authenticate_client(config, conn, params),
         {:ok, stored} <- store_request(config, client, params) do
      conn
      |> put_status(:created)
      |> json(stored)
    else
      {:error, :insecure_transport} ->
        render_error(conn, @error_invalid_request, "TLS required")

      {:error, {code, desc}} ->
        render_error(conn, code, desc)
    end
  end

  defp resolve_config do
    otp_app = Application.get_env(:attesto_phoenix, :otp_app)
    Config.from_otp_app(otp_app, Config)
  end

  defp authenticate_client(config, conn, params) do
    with {:ok, method} <- client_auth_method(conn, params) do
      verify_client_auth(config, method)
    end
  end

  defp client_auth_method(
         conn,
         %{"client_assertion_type" => type, "client_assertion" => assertion} = params
       )
       when is_binary(assertion) and assertion != "" do
    if get_req_header(conn, "authorization") == [] and not is_map_key(params, "client_secret") do
      if type == ClientAssertion.assertion_type() do
        {:ok, {:private_key_jwt, assertion}}
      else
        {:error, {@error_invalid_client, "client authentication failed"}}
      end
    else
      {:error, {@error_invalid_request, "multiple client authentication methods"}}
    end
  end

  defp client_auth_method(conn, params) do
    case get_req_header(conn, "authorization") do
      ["Basic " <> encoded] when not is_map_key(params, "client_secret") ->
        with {:ok, client_id, secret} <- decode_basic(encoded),
             true <- not is_map_key(params, "client_assertion") do
          {:ok, {:client_secret_basic, client_id, secret}}
        else
          false -> {:error, {@error_invalid_request, "multiple client authentication methods"}}
          {:error, _} = error -> error
        end

      ["Basic " <> _] ->
        {:error, {@error_invalid_request, "multiple client authentication methods"}}

      [] ->
        with client_id when is_binary(client_id) and client_id != "" <- params["client_id"],
             secret when is_binary(secret) and secret != "" <- params["client_secret"] do
          {:ok, {:client_secret_post, client_id, secret}}
        else
          _ -> {:error, {@error_invalid_client, "client authentication failed"}}
        end

      _ ->
        {:error, {@error_invalid_client, "unsupported client authentication scheme"}}
    end
  end

  defp verify_client_auth(config, {:client_secret_basic, client_id, secret}) do
    with :ok <- require_client_auth_method(config, "client_secret_basic") do
      load_and_verify(config, client_id, secret)
    end
  end

  defp verify_client_auth(config, {:client_secret_post, client_id, secret}) do
    with :ok <- require_client_auth_method(config, "client_secret_post") do
      load_and_verify(config, client_id, secret)
    end
  end

  defp verify_client_auth(config, {:private_key_jwt, assertion}) do
    with :ok <- require_client_auth_method(config, "private_key_jwt"),
         {:ok, client_id} <- ClientAssertion.peek_client_id(assertion),
         {:ok, client} <- load_existing_client(config, client_id),
         {:ok, jwks} <- client_jwks(config, client),
         {:ok, claims} <-
           ClientAssertion.verify(assertion, client_id, client_assertion_audiences(config), jwks,
             max_lifetime: @client_assertion_max_lifetime
           ),
         :ok <- consume_client_assertion_jti(config, client_id, claims) do
      {:ok, client}
    else
      _ -> {:error, {@error_invalid_client, "client authentication failed"}}
    end
  end

  defp require_client_auth_method(config, method) do
    case Map.get(config, :token_endpoint_auth_methods_supported) do
      methods when is_list(methods) and methods != [] ->
        if method in methods,
          do: :ok,
          else: {:error, {@error_invalid_client, "client authentication failed"}}

      _ ->
        :ok
    end
  end

  defp decode_basic(encoded) do
    with {:ok, decoded} <- Base.decode64(encoded),
         [client_id, secret] <- String.split(decoded, ":", parts: 2) do
      {:ok, URI.decode_www_form(client_id), URI.decode_www_form(secret)}
    else
      _ -> {:error, {@error_invalid_client, "client authentication failed"}}
    end
  end

  defp load_and_verify(config, client_id, secret) do
    case invoke(config.load_client, [client_id]) do
      {:ok, client} ->
        if invoke(config.verify_client_secret, [client, secret]) == true,
          do: {:ok, client},
          else: {:error, {@error_invalid_client, "client authentication failed"}}

      _ ->
        _ = invoke(config.verify_client_secret, [:unknown_client, secret])
        {:error, {@error_invalid_client, "client authentication failed"}}
    end
  end

  defp load_existing_client(config, client_id) do
    case invoke(config.load_client, [client_id]) do
      {:ok, client} -> {:ok, client}
      _ -> {:error, :invalid_client}
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
          _ -> {:error, :missing_client_jwks}
        end
    end
  end

  defp client_assertion_audiences(config) do
    [config.issuer, Config.par_endpoint_url(config)]
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

  defp store_request(config, client, params) do
    ttl = config_field(config, :par_ttl, 90)
    request_uri = "urn:ietf:params:oauth:request_uri:" <> random()

    stored =
      params
      |> Map.drop(["client_secret", "client_assertion", "client_assertion_type"])
      |> Map.put("client_id", client_id(config, client))

    case par_store(config).put(request_uri, stored, ttl) do
      :ok -> {:ok, %{request_uri: request_uri, expires_in: ttl}}
      _ -> {:error, {@error_invalid_request, "could not store pushed authorization request"}}
    end
  end

  defp client_id(config, client) do
    case config_callback(config, :client_id) do
      nil -> Map.get(client, :id) || Map.get(client, "id")
      callback -> invoke(callback, [client])
    end
  end

  defp par_store(config), do: config_field(config, :par_store, AttestoPhoenix.Store.PAR.ETS)

  defp random, do: 32 |> :crypto.strong_rand_bytes() |> Base.url_encode64(padding: false)

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

  defp config_field(config, field, default) do
    case Map.get(config, field) do
      nil -> default
      value -> value
    end
  end

  defp config_callback(config, field) do
    case Map.fetch(config, field) do
      {:ok, fun} -> fun
      :error -> nil
    end
  end

  defp invoke(fun, args) when is_function(fun), do: apply(fun, args)
  defp invoke({mod, fun}, args), do: apply(mod, fun, args)
  defp invoke({mod, fun, extra}, args) when is_list(extra), do: apply(mod, fun, args ++ extra)
end
