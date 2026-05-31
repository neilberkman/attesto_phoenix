defmodule AttestoPhoenix.Plug.Authenticate do
  @moduledoc """
  Phoenix-friendly protected-resource authentication.

  This plug is a thin integration layer over `Attesto.Plug.Authenticate`. The
  core plug owns the protocol work: parsing Bearer/DPoP credentials, verifying
  the JWT access token, enforcing DPoP and mTLS sender-constraint bindings, and
  rendering RFC 6750 / RFC 9449 failures. This wrapper derives the core options
  from `AttestoPhoenix.Config`, resolves the verified subject through the
  host's `:load_principal` callback, and assigns neutral values for downstream
  Phoenix code.

  Defaults:

    * `:claims_key` - `:attesto_claims`
    * `:principal_key` - `:attesto_principal`
    * `:context_key` - `:attesto_context`

  The context assign is a map with `:subject`, `:client_id`, `:scope`, `:claims`,
  `:cnf`, and `:principal`. It is deliberately protocol-shaped; application
  policy such as accounts, roles, audit actors, and error envelopes belongs in
  the host application.
  """

  @behaviour Plug

  import Plug.Conn

  alias Attesto.DPoP.ReplayCache
  alias Attesto.Plug.Authenticate, as: CoreAuthenticate
  alias Attesto.Plug.OAuthError
  alias AttestoPhoenix.{Config, Event, RequestContext}

  @claims_key :attesto_claims
  @principal_key :attesto_principal
  @context_key :attesto_context

  @impl Plug
  def init(opts) when is_list(opts), do: opts

  @impl Plug
  def call(conn, opts) do
    config = resolve_config(opts)
    claims_key = Keyword.get(opts, :claims_key, @claims_key)

    case RequestContext.check_https(conn, config) do
      :ok ->
        conn =
          conn
          |> CoreAuthenticate.call(CoreAuthenticate.init(core_opts(config, claims_key, opts)))

        if conn.halted do
          emit_denied(config, conn, :invalid_token)
          conn
        else
          assign_principal(conn, config, claims_key, opts)
        end

      {:error, :insecure_transport} ->
        emit_denied(config, conn, :insecure_transport)

        OAuthError.unauthorized(
          conn,
          :bearer,
          "invalid_token",
          error_opts(config, description: "TLS required")
        )
    end
  end

  defp assign_principal(conn, config, claims_key, opts) do
    claims = conn.assigns[claims_key]
    subject = claims["sub"]

    case invoke(config.load_principal, [subject]) do
      {:ok, principal} ->
        principal_key = Keyword.get(opts, :principal_key, @principal_key)
        context_key = Keyword.get(opts, :context_key, @context_key)

        conn
        |> assign(principal_key, principal)
        |> assign(context_key, context(claims, principal))
        |> tap(fn _conn -> emit_succeeded(config, claims) end)

      {:error, _reason} ->
        emit_denied(config, conn, :invalid_token)
        OAuthError.unauthorized(conn, scheme_of(claims), "invalid_token", error_opts(config, []))
    end
  end

  defp context(claims, principal) do
    %{
      subject: claims["sub"],
      client_id: claims["client_id"],
      scope: scope(claims),
      claims: claims,
      cnf: Map.get(claims, "cnf"),
      principal: principal
    }
  end

  defp scope(%{"scope" => scope}) when is_binary(scope),
    do: String.split(scope, ~r/\s+/, trim: true)

  defp scope(_claims), do: []

  defp scheme_of(%{"cnf" => %{"jkt" => jkt}}) when is_binary(jkt), do: :dpop
  defp scheme_of(_claims), do: :bearer

  defp core_opts(config, claims_key, opts) do
    overrides =
      opts
      |> Keyword.drop([:config, :otp_app, :claims_key, :principal_key, :context_key])
      |> Keyword.put(:claims_key, claims_key)

    config
    |> configured_core_opts(claims_key)
    |> Keyword.merge(overrides)
  end

  defp configured_core_opts(config, claims_key) do
    [config: attesto_config(config), claims_key: claims_key]
    |> put_optional(:send_error, config.send_error)
    |> put_optional(:www_authenticate, config.www_authenticate)
    |> put_optional(:no_store, config.no_store)
    |> put_optional(:replay_check, replay_check(config))
    |> put_optional(:nonce_check, nonce_check(config))
    |> put_optional(:nonce_issue, nonce_issue(config))
    |> put_optional(:cert_der, cert_der(config))
    |> Keyword.put(:htu, fn conn -> RequestContext.canonical_url(conn, config) end)
  end

  defp attesto_config(config) do
    Config.to_attesto_config(config, principal_kinds_extra(config))
  end

  defp principal_kinds_extra(%Config{principal_kinds: kinds})
       when is_list(kinds) and kinds != [] do
    [principal_kinds: kinds]
  end

  defp principal_kinds_extra(%Config{principal_kinds: callback}) when not is_nil(callback) do
    case invoke(callback, []) do
      kinds when is_list(kinds) and kinds != [] -> [principal_kinds: kinds]
      _ -> []
    end
  end

  defp principal_kinds_extra(_config), do: []

  defp replay_check(%Config{dpop_enabled: false}), do: nil
  defp replay_check(%Config{replay_check: nil}), do: &ReplayCache.check_and_record/2
  defp replay_check(%Config{replay_check: callback}), do: callback

  defp nonce_check(%Config{dpop_nonce_required: true, nonce_store: store})
       when is_atom(store) and not is_nil(store) do
    fn nonce ->
      if store.valid?(nonce), do: :ok, else: {:error, :use_dpop_nonce}
    end
  end

  defp nonce_check(_config), do: nil

  defp nonce_issue(%Config{dpop_nonce_required: true, nonce_store: store})
       when is_atom(store) and not is_nil(store) do
    &store.issue/0
  end

  defp nonce_issue(_config), do: nil

  defp cert_der(%Config{mtls_enabled: true, cert_der: cert_der}) when not is_nil(cert_der),
    do: normalize_callback(cert_der)

  defp cert_der(_config), do: nil

  defp emit_succeeded(config, claims) do
    Event.emit(config, :auth_succeeded, %{
      subject: claims["sub"],
      client_id: claims["client_id"],
      scope: claims["scope"]
    })
  end

  defp emit_denied(config, conn, result) do
    Event.emit(config, :auth_denied, %{
      result: result,
      metadata: request_metadata(conn, config)
    })
  end

  defp request_metadata(conn, config) do
    %{
      method: conn.method,
      path: conn.request_path,
      client_ip: RequestContext.client_ip(conn, config)
    }
  end

  defp resolve_config(opts) do
    case Keyword.get(opts, :config) do
      %Config{} = config ->
        config

      fun when is_function(fun, 0) ->
        fun.()

      nil ->
        opts
        |> Keyword.get(:otp_app, Application.get_env(:attesto_phoenix, :otp_app))
        |> Config.from_otp_app(Config)
    end
  end

  defp put_optional(opts, _key, nil), do: opts
  defp put_optional(opts, key, value), do: Keyword.put(opts, key, value)

  defp error_opts(config, extra) do
    [
      send_error: config.send_error,
      www_authenticate: config.www_authenticate,
      no_store: config.no_store
    ]
    |> Enum.reject(fn {_key, value} -> is_nil(value) end)
    |> Keyword.merge(extra)
  end

  defp invoke(fun, args) when is_function(fun), do: apply(fun, args)

  defp invoke({module, fun}, args) when is_atom(module) and is_atom(fun),
    do: apply(module, fun, args)

  defp invoke({module, fun, extra}, args) when is_atom(module) and is_atom(fun),
    do: apply(module, fun, args ++ extra)

  defp normalize_callback(callback) when is_function(callback), do: callback

  defp normalize_callback({module, fun}) when is_atom(module) and is_atom(fun) do
    fn conn -> apply(module, fun, [conn]) end
  end

  defp normalize_callback({module, fun, extra}) when is_atom(module) and is_atom(fun) do
    fn conn -> apply(module, fun, [conn | extra]) end
  end
end
