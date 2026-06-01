defmodule AttestoPhoenix.Controller.OpenIDConfigurationController do
  @moduledoc """
  OpenID Connect Discovery 1.0 - OpenID Provider Metadata endpoint.

  Serves the OpenID Provider configuration document at
  `/.well-known/openid-configuration` (OpenID Connect Discovery §4) so that
  Relying Parties can discover the OpenID Provider: the issuer, the endpoint
  URLs, the response/grant types it supports, the signing algorithms it uses
  for ID Tokens, and the scopes and claims it can return.

  The document is assembled by `Attesto.OpenIDDiscovery.metadata/2`; this
  controller contributes transport concerns only and adds no policy of its
  own. Every protocol member - the issuer, the token endpoint
  (`token_endpoint`), the JWKS location (`jwks_uri`), the PKCE challenge
  methods (`code_challenge_methods_supported`, fixed to `S256` per RFC 7636
  §4.2), the DPoP algorithms (`dpop_signing_alg_values_supported`, RFC 9449),
  and the OIDC-fixed members (`subject_types_supported`,
  `id_token_signing_alg_values_supported`, `claim_types_supported`) - is
  derived by the core builder from the protocol configuration.

  The capability members reflect exactly what the controllers wire, never an
  aspirational superset: `grant_types_supported` lists the grants the token
  endpoint dispatches (`authorization_code`, `refresh_token`,
  `client_credentials`, and OAuth token exchange); `token_endpoint_auth_methods_supported`
  lists the client-authentication methods it accepts (`client_secret_basic`,
  `client_secret_post`, `private_key_jwt`, and `none` for PKCE-using public
  clients). The OpenID Connect request-parameter flags
  (`request_parameter_supported`, `request_uri_parameter_supported`, both
  OpenID Connect Discovery §3) reflect the authorization endpoint precisely:
  signed request objects (`request`, JAR/RFC 9101) are consumed when the host
  supplies `:client_jwks`; arbitrary OIDC `request_uri` references are not
  advertised even though PAR request URNs are resolved through `/oauth/par`. The
  `claims_parameter_supported` flag (OpenID Connect Discovery §3 / OpenID
  Connect Core §5.5) is host-configurable and defaults to `false`, since the
  authorization endpoint does not consume the `claims` parameter unless the
  host wires it.

  The host-specific members - the `authorization_endpoint` (RFC 6749 §3.1)
  and `userinfo_endpoint` (OpenID Connect Core §5.3), both host-owned and
  hence not mounted by `AttestoPhoenix.Router`; the supported scopes
  (`scopes_supported`, to which the core builder adds the reserved `openid`
  scope per OpenID Connect Core §3.1.2.1); the supported claims
  (`claims_supported`); the supported ACR values (`acr_values_supported`,
  OpenID Connect Discovery §3) and UI locales (`ui_locales_supported`,
  OpenID Connect Discovery §3), each advertised only when the host configures
  a non-empty list; the `claims_parameter_supported` flag; and the dynamic
  registration endpoint (`registration_endpoint`, RFC 7591, advertised only
  when registration is enabled) - are read from `AttestoPhoenix.Config` and
  passed through, never hardcoded here.

  The response carries no secrets and is identical for every caller, so it is
  served unauthenticated. OpenID Connect Discovery §4 permits caching of the
  configuration response, so a public, cacheable `Cache-Control` header is
  set.

  ## Wiring

  The router pipeline must place the `AttestoPhoenix.Config` under
  `conn.private[:attesto_phoenix_config]` (the same key the other endpoints
  read) and the derived `Attesto.Config` under
  `conn.private[:attesto_protocol_config]`. Both are required; a missing value
  raises rather than serving a partial document, because a partial discovery
  document would misdirect Relying Parties to endpoints that may not exist.
  """

  use Phoenix.Controller, formats: [:json]

  import Plug.Conn, only: [put_resp_header: 3]

  alias Attesto.OpenIDDiscovery
  alias AttestoPhoenix.Config

  # The router pipeline installs the AttestoPhoenix.Config here. This is the
  # same private key the token and discovery endpoints read.
  @config_key :attesto_phoenix_config

  # The router pipeline installs the derived Attesto.Config (the protocol
  # configuration the core metadata builder reads) here.
  @protocol_config_key :attesto_protocol_config

  # OpenID Connect Discovery §4: the configuration document is static for a
  # given provider configuration, so it may be cached by Relying Parties and
  # intermediaries. One hour balances picking up configuration changes against
  # request volume, matching the RFC 8414 discovery endpoint.
  @cache_max_age_seconds 3600

  # RFC 6749 §3.1.1 / §4.1: an authorization-code provider supports the "code"
  # response type. Fixed by protocol, not configured. OpenID Connect Discovery
  # requires response_types_supported; the core builder defaults to this when
  # the host does not override it.
  @response_types_supported ["code"]

  # OpenID Connect Core §3.1.2.5 / RFC 8414 §2 `response_modes_supported`: the
  # authorization-code flow returns its parameters in the redirect query string,
  # so the provider supports the "query" response mode. Fixed by the flow this
  # provider implements, not configured.
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
  Render the OpenID Provider Metadata document as JSON.

  Fails closed with `RuntimeError` when either required configuration value is
  absent from `conn.private`, since serving a document that omits required
  members would misdirect Relying Parties.
  """
  @spec show(Plug.Conn.t(), map()) :: Plug.Conn.t()
  def show(conn, _params) do
    config = fetch_config!(conn)
    protocol_config = fetch_protocol_config!(conn)

    metadata = OpenIDDiscovery.metadata(protocol_config, discovery_opts(config))

    conn
    |> put_cache_control()
    |> json(metadata)
  end

  # Fail closed: a missing config is a wiring error, not a runtime condition to
  # paper over. Raising surfaces the misconfiguration instead of emitting a
  # document that omits required members.
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

  # OpenID Connect Discovery §3 `request_parameter_supported` /
  # `request_uri_parameter_supported`: the authorization endpoint consumes
  # signed request objects (`request`, JAR/RFC 9101) when the host supplies a
  # `:client_jwks` callback. It resolves PAR `request_uri` URNs issued by this
  # server, but still does not advertise arbitrary OIDC request_uri fetching.
  @request_parameter_supported true
  @request_uri_parameter_supported false

  # Translate the configured host capabilities into the OpenID Connect
  # Discovery §3 host members understood by Attesto.OpenIDDiscovery.metadata/2.
  # The core builder drops nil-valued members, so optional members advertise
  # only what the provider actually implements. `scopes_supported` is always
  # passed (never collapsed to nil): an OpenID Provider MUST support the
  # reserved `openid` scope (OpenID Connect Core §3.1.2.1), so the core builder
  # adds it to the host's catalog, yielding `["openid"]` even when the host
  # configures no other scopes.
  @spec discovery_opts(Config.t()) :: keyword()
  defp discovery_opts(%Config{} = config) do
    [
      response_types_supported: @response_types_supported,
      response_modes_supported: @response_modes_supported,
      grant_types_supported: @grant_types_supported,
      token_endpoint_auth_methods_supported: @token_endpoint_auth_methods_supported,
      authorization_endpoint: config.authorization_endpoint,
      userinfo_endpoint: config.userinfo_endpoint,
      revocation_endpoint: revocation_endpoint(config),
      pushed_authorization_request_endpoint: pushed_authorization_request_endpoint(config),
      scopes_supported: config.scopes_supported,
      claims_supported: presence(config.claims_supported),
      registration_endpoint: registration_endpoint(config),
      # OpenID Connect Discovery §3 capability flags reflecting what is wired.
      request_parameter_supported: @request_parameter_supported,
      request_uri_parameter_supported: @request_uri_parameter_supported,
      claims_parameter_supported: config.claims_parameter_supported,
      # Host catalogs: advertised only when the host configures a non-empty list
      # (the core builder drops the nil the helper returns for `[]`).
      acr_values_supported: presence(config.acr_values_supported),
      ui_locales_supported: presence(config.ui_locales_supported)
    ]
  end

  # RFC 7009 §2 / RFC 8414 §2 `revocation_endpoint`: the revocation endpoint
  # (`AttestoPhoenix.Controller.RevocationController`) is always mounted by the
  # router macro, so it is always advertised. The URL is resolved from the
  # host's configured revocation path (the endpoint members are absolute URLs),
  # so it reflects where the host mounted the endpoint.
  @spec revocation_endpoint(Config.t()) :: String.t()
  defp revocation_endpoint(%Config{} = config), do: Config.revocation_endpoint_url(config)

  defp pushed_authorization_request_endpoint(%Config{} = config),
    do: Config.par_endpoint_url(config)

  # RFC 7591 §3: advertise the dynamic client registration endpoint only when
  # registration is enabled; otherwise omit the member entirely. The URL is
  # resolved from the host's configured registration path (the endpoint members
  # are absolute URLs), so it reflects where the host mounted the endpoint.
  @spec registration_endpoint(Config.t()) :: String.t() | nil
  defp registration_endpoint(%Config{registration_enabled: true} = config),
    do: Config.registration_endpoint_url(config)

  defp registration_endpoint(%Config{registration_enabled: false}), do: nil

  # An empty list means "not advertised": collapse it to nil so the core
  # builder omits the member instead of publishing an empty array. Used for the
  # optional `claims_supported` catalog, not for `scopes_supported` (which is
  # always advertised; see discovery_opts/1).
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
