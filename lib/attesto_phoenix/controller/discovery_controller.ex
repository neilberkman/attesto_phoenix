defmodule AttestoPhoenix.Controller.DiscoveryController do
  @moduledoc """
  RFC 8414 - OAuth 2.0 Authorization Server Metadata endpoint.

  Serves the discovery document at
  `/.well-known/oauth-authorization-server` (RFC 8414 §3) so that clients
  can discover the issuer, the endpoint URLs, and the capabilities the
  authorization server advertises.

  The document is assembled by `Attesto.Discovery.metadata/2`; this
  controller contributes transport concerns only and adds no policy of its
  own. Every protocol member - the issuer, the token endpoint
  (`token_endpoint`), the JWKS location (`jwks_uri`), the PKCE challenge
  methods (`code_challenge_methods_supported`, fixed to `S256` per RFC 7636
  §4.2), and the DPoP algorithms (`dpop_signing_alg_values_supported`, RFC
  9449) - is derived by the core builder from the protocol configuration.

  The capability members reflect exactly what the controllers wire, never
  an aspirational superset: `grant_types_supported` lists the grants the token
  endpoint dispatches (`authorization_code`, `refresh_token`,
  `client_credentials`, and OAuth token exchange);
  `token_endpoint_auth_methods_supported` lists the client-authentication
  methods it accepts (`client_secret_basic`, `client_secret_post`,
  `private_key_jwt`, and `none` for PKCE-using public clients). The PAR
  endpoint is advertised separately as `pushed_authorization_request_endpoint`.

  The host-specific members - the supported scopes (`scopes_supported`),
  the authorization endpoint, and the dynamic registration endpoint
  (`registration_endpoint`, RFC 7591, advertised only when registration is
  enabled) - are read from `AttestoPhoenix.Config` and passed through,
  never hardcoded here.

  The response carries no secrets and is identical for every caller, so it
  is served unauthenticated. RFC 8414 §3.1 permits caching of the metadata
  response, so a public, cacheable `Cache-Control` header is set.

  ## Wiring

  The router pipeline must place the `AttestoPhoenix.Config` under
  `conn.private[:attesto_phoenix_config]` (the same key the other endpoints
  read) and the derived `Attesto.Config` under
  `conn.private[:attesto_protocol_config]`. Both are required; a missing
  value raises rather than serving a partial document, because a partial
  discovery document would misdirect clients to endpoints that may not
  exist.
  """

  use Phoenix.Controller, formats: [:json]

  import Plug.Conn, only: [put_resp_header: 3]

  alias Attesto.Discovery
  alias AttestoPhoenix.Config

  # The router pipeline installs the AttestoPhoenix.Config here. This is the
  # same private key the token and revocation endpoints read.
  @config_key :attesto_phoenix_config

  # The router pipeline installs the derived Attesto.Config (the protocol
  # configuration the core metadata builder reads) here.
  @protocol_config_key :attesto_protocol_config

  # RFC 8414 §3: the metadata document is static for a given server
  # configuration, so it may be cached by clients and intermediaries. One
  # hour balances picking up configuration changes against request volume.
  @cache_max_age_seconds 3600

  # RFC 6749 §3.1.1 / §4.1: an authorization-code authorization server
  # supports the "code" response type. Fixed by protocol, not configured.
  @response_types_supported ["code"]

  # RFC 8414 §2 `response_modes_supported`: the Phoenix authorization-code
  # endpoint returns the code and state as redirect query parameters.
  @response_modes_supported ["query"]

  # RFC 8414 §2 `grant_types_supported`: the grant types the token endpoint
  # (`AttestoPhoenix.Controller.TokenController`) actually dispatches -
  # `authorization_code` (RFC 6749 §4.1), `refresh_token` (RFC 6749 §6), and
  # `client_credentials` (RFC 6749 §4.4). Any other `grant_type` is rejected
  # with `unsupported_grant_type`, so only these three are advertised. Fixed by
  # what the controller wires, not configured.
  @grant_types_supported [
    "authorization_code",
    "refresh_token",
    "client_credentials",
    "urn:ietf:params:oauth:grant-type:token-exchange"
  ]

  # RFC 8414 §2 `token_endpoint_auth_methods_supported`: the client
  # authentication methods the token endpoint actually accepts. The controller
  # reads a confidential client's secret from an HTTP Basic header
  # (`client_secret_basic`, RFC 6749 §2.3.1 / RFC 7617), from the request body
  # (`client_secret_post`, RFC 6749 §2.3.1), or from a signed client assertion
  # (`private_key_jwt`, RFC 7523 / OIDC Core §9). It also admits a public
  # client that presents only a `client_id` and relies on PKCE (`none`,
  # RFC 6749 §2.1 / RFC 7636). Fixed by what the controller wires.
  @token_endpoint_auth_methods_supported [
    "client_secret_basic",
    "client_secret_post",
    "private_key_jwt",
    "none"
  ]

  @doc """
  Render the RFC 8414 metadata document as JSON.

  Fails closed with `RuntimeError` when either required configuration value
  is absent from `conn.private`, since serving a document that omits
  required members would misdirect clients.
  """
  @spec show(Plug.Conn.t(), map()) :: Plug.Conn.t()
  def show(conn, _params) do
    config = fetch_config!(conn)
    protocol_config = fetch_protocol_config!(conn)

    metadata = Discovery.metadata(protocol_config, discovery_opts(config))

    conn
    |> put_cache_control()
    |> json(metadata)
  end

  # Fail closed: a missing config is a wiring error, not a runtime
  # condition to paper over. Raising surfaces the misconfiguration instead
  # of emitting a document that omits required members.
  @spec fetch_config!(Plug.Conn.t()) :: Config.t()
  defp fetch_config!(conn) do
    case conn.private do
      %{@config_key => %Config{} = config} ->
        config

      _ ->
        raise "#{inspect(__MODULE__)}: no %AttestoPhoenix.Config{} found in " <>
                "conn.private[#{inspect(@config_key)}]; wire the host pipeline that assigns it"
    end
  end

  @spec fetch_protocol_config!(Plug.Conn.t()) :: Attesto.Config.t()
  defp fetch_protocol_config!(conn) do
    case conn.private do
      %{@protocol_config_key => %Attesto.Config{} = config} ->
        config

      _ ->
        raise "#{inspect(__MODULE__)}: no %Attesto.Config{} found in " <>
                "conn.private[#{inspect(@protocol_config_key)}]; wire the host pipeline that assigns it"
    end
  end

  # Translate the configured host capabilities into the RFC 8414 §2 host
  # members understood by Attesto.Discovery.metadata/2. The core builder
  # drops nil-valued members, so the document advertises only what the
  # server actually implements.
  @spec discovery_opts(Config.t()) :: keyword()
  defp discovery_opts(%Config{} = config) do
    [
      response_types_supported: @response_types_supported,
      response_modes_supported: @response_modes_supported,
      grant_types_supported: @grant_types_supported,
      token_endpoint_auth_methods_supported: @token_endpoint_auth_methods_supported,
      scopes_supported: presence(config.scopes_supported),
      pushed_authorization_request_endpoint: pushed_authorization_request_endpoint(config),
      registration_endpoint: registration_endpoint(config)
    ]
  end

  defp pushed_authorization_request_endpoint(%Config{} = config),
    do: Config.par_endpoint_url(config)

  # RFC 7591 §3: advertise the dynamic client registration endpoint only
  # when registration is enabled; otherwise omit the member entirely. The URL
  # is resolved from the host's configured registration path (RFC 8414 §2
  # endpoint members are absolute URLs), so it reflects where the host mounted
  # the endpoint rather than a hardcoded `/oauth/register`.
  @spec registration_endpoint(Config.t()) :: String.t() | nil
  defp registration_endpoint(%Config{registration_enabled: true} = config),
    do: Config.registration_endpoint_url(config)

  defp registration_endpoint(%Config{registration_enabled: false}), do: nil

  # An empty list means "not advertised": collapse it to nil so the core
  # builder omits the member instead of publishing an empty array.
  @spec presence([term()]) :: [term()] | nil
  defp presence([]), do: nil
  defp presence(list) when is_list(list), do: list

  @spec put_cache_control(Plug.Conn.t()) :: Plug.Conn.t()
  defp put_cache_control(conn) do
    put_resp_header(
      conn,
      "cache-control",
      "public, max-age=#{@cache_max_age_seconds}"
    )
  end
end
