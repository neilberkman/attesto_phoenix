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

  alias Attesto.DPoP
  alias Attesto.DPoP.ReplayCache
  alias AttestoPhoenix.{Callback, ClientAuthentication, Config, OAuthError, RequestContext}
  alias AttestoPhoenix.ClientAuthentication.Policy

  @cache_control_no_store "no-store"
  @pragma_no_cache "no-cache"
  @error_invalid_dpop_proof "invalid_dpop_proof"
  @error_invalid_request "invalid_request"
  @dpop_request_header "dpop"
  @client_assertion_max_lifetime 300

  @spec create(Plug.Conn.t(), map()) :: Plug.Conn.t()
  def create(conn, params) do
    config = resolve_config()
    conn = put_no_store(conn)

    with :ok <- RequestContext.check_https(conn, config),
         {:ok, client} <- authenticate_client(config, conn, params),
         {:ok, stored} <- store_request(config, conn, client, params) do
      conn
      |> put_status(:created)
      |> json(stored)
    else
      {:error, :insecure_transport} ->
        render_error(conn, @error_invalid_request, "TLS required")

      {:error, %OAuthError{} = err} ->
        render_error(conn, Atom.to_string(err.error), err.error_description)

      {:error, {code, desc}} ->
        render_error(conn, code, desc)
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
  # public-client path is refused here (`allow_public: false`); client
  # assertions are audienced to the issuer (FAPI 2 / RFC 7523 §3) and live at
  # most `@client_assertion_max_lifetime` seconds (RFC 7523 §3).
  defp authenticate_client(config, conn, params) do
    policy = %Policy{
      allow_public: false,
      assertion_audiences: [config.issuer],
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

  defp replay_check(%Config{replay_check: nil}), do: &ReplayCache.check_and_record/2
  defp replay_check(%Config{replay_check: callback}), do: callback

  defp store_request(config, conn, client, params) do
    ttl = config_field(config, :par_ttl, 90)
    request_uri = "urn:ietf:params:oauth:request_uri:" <> random()

    with {:ok, dpop_jkt} <- verify_dpop_binding(config, conn, params) do
      stored =
        params
        |> Map.drop(["client_secret", "client_assertion", "client_assertion_type"])
        |> put_verified_dpop_jkt(dpop_jkt)
        |> Map.put("client_id", client_id(config, client))

      case par_store(config).put(request_uri, stored, ttl) do
        :ok -> {:ok, %{request_uri: request_uri, expires_in: ttl}}
        _ -> {:error, {@error_invalid_request, "could not store pushed authorization request"}}
      end
    end
  end

  defp verify_dpop_binding(config, conn, params) do
    case get_req_header(conn, @dpop_request_header) do
      [] ->
        {:ok, submitted_dpop_jkt(params)}

      [proof] ->
        verify_dpop_proof(config, conn, params, proof)

      _multiple ->
        {:error, {@error_invalid_dpop_proof, "multiple DPoP proofs"}}
    end
  end

  defp verify_dpop_proof(config, conn, params, proof) do
    opts = [
      http_method: RequestContext.http_method(conn),
      http_uri: RequestContext.canonical_url(conn, config),
      replay_check: replay_check(config)
    ]

    with {:ok, %{jkt: verified_jkt}} <- DPoP.verify_proof(proof, opts),
         :ok <- check_submitted_dpop_jkt(Map.get(params, "dpop_jkt"), verified_jkt) do
      {:ok, verified_jkt}
    else
      {:error, reason} ->
        {:error, {@error_invalid_dpop_proof, "invalid DPoP proof: #{inspect(reason)}"}}
    end
  end

  defp check_submitted_dpop_jkt(nil, _verified_jkt), do: :ok
  defp check_submitted_dpop_jkt("", _verified_jkt), do: :ok
  defp check_submitted_dpop_jkt(verified_jkt, verified_jkt), do: :ok
  defp check_submitted_dpop_jkt(_submitted_jkt, _verified_jkt), do: {:error, :dpop_jkt_mismatch}

  defp put_verified_dpop_jkt(params, nil), do: params
  defp put_verified_dpop_jkt(params, dpop_jkt), do: Map.put(params, "dpop_jkt", dpop_jkt)

  defp submitted_dpop_jkt(%{"dpop_jkt" => jkt}) when is_binary(jkt) and jkt != "", do: jkt
  defp submitted_dpop_jkt(_params), do: nil

  # The client's identifier (RFC 6749 §2.2). Read defensively through the
  # host's `:client_id` callback; when none is configured the identifier is
  # unknown (`nil`), matching the resolution used everywhere else in the
  # library. (Previously this fell back to `client[:id]`/`client["id"]`, which
  # leaked an assumption about the opaque host client shape.)
  defp client_id(config, client) do
    Callback.invoke(config_callback(config, :client_id), [client], nil)
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
end
