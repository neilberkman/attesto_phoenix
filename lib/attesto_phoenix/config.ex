defmodule AttestoPhoenix.Config do
  @moduledoc """
  Configuration for the `attesto_phoenix` authorization-server layer.

  This is the single source of truth consumed by every controller and plug in
  the library. It reads the host's configuration (from a host-chosen
  `otp_app`/config key), validates the required keys, applies neutral defaults,
  and derives the `Attesto.Config` the protocol layer needs.

  Build one with `new/1` (from a keyword list or map) or `from_otp_app/2` (to
  read `Application.get_env/2`). Validation raises `ArgumentError` on a missing
  required key so misconfiguration fails fast at boot.

  ## Keys

  ### Required

    * `:issuer` - issuer URL (string) used as the JWT `iss`, the discovery
      issuer, and the base for endpoint URLs.
    * `:keystore` - module implementing `Attesto.Keystore` providing the
      signing key and the verification keys published via JWKS. Use a static
      keystore or a host KMS/HSM/Vault-backed implementation; per-key `alg`
      metadata is supported by the core keystore behaviour.
    * `:repo` - `Ecto.Repo` module used by the Ecto-backed code, refresh,
      nonce, and replay stores.
    * `:load_client` - `(client_id -> {:ok, client} | {:error, :not_found} |
      {:error, :revoked})`. Resolves an OAuth client. The host owns the client
      registry and revocation policy.
    * `:verify_client_secret` - `(client, presented_secret -> boolean)`.
      Constant-time client-secret verification (e.g. via
      `Attesto.SecureCompare`). The host owns secret hashing.
    * `:load_principal` - `(subject_id -> {:ok, principal} | {:error,
      :not_found})`. Resolves the subject/principal during protected-resource
      authentication.

  ### Optional callbacks

    * `:authorize_scope` - `(client, requested_scope -> {:ok, granted_scope} |
      {:error, :invalid_scope})`. Validates/narrows requested scope using
      `Attesto.Scope` algebra. Defaults to "subset of `:scopes_supported`".
    * `:on_event` - `(%AttestoPhoenix.Event{} -> any)`. Audit/telemetry hook.
      No-op by default; the library never stores events itself.
    * `:send_error` - `(conn, status, body_map -> conn)`. Optional transport
      hook used by `AttestoPhoenix.OAuthError` to serialize OAuth/OIDC errors
      into the host's API envelope while preserving the RFC status, challenge,
      and cache-control semantics.
    * `:no_store` - `(conn -> conn)`. Optional transport hook used by
      `AttestoPhoenix.OAuthError` to apply no-store headers.
    * `:www_authenticate` - `(conn, challenge_string -> conn)`. Optional
      transport hook used by `AttestoPhoenix.OAuthError` to write the
      `WWW-Authenticate` challenge header.
    * `:basic_realm` - realm string for token-endpoint Basic auth challenges.
      Default `"OAuth"`.
    * `:htu` - `(conn -> canonical_url_string)`. Overrides how the DPoP `htu`
      is computed behind proxies. Defaults to derivation from `:trusted_proxies`.
    * `:cert_der` - `(conn -> der_binary | nil)`. Extracts the client mTLS
      certificate DER. Required only when `:mtls_enabled`.
    * `:register_client` - `(metadata -> {:ok, client} | {:error, reason})`.
      Persists a dynamically registered client. Required only when
      `:registration_enabled`.
    * `:unregister_client` - `(client -> :ok | {:ok, client} | {:error, reason})`.
      Deletes a dynamically registered client for registration management
      cleanup (RFC 7592). Optional; when unset, DELETE requests to the
      registration management endpoint fail closed.
    * `:client_registration_access_token_hash` - `(client -> String.t() | nil)`.
      Extracts the stored hash of the registration access token issued with a
      dynamic client (RFC 7592). Optional; when unset, DELETE requests fail
      closed.
    * `:principal_kinds` - non-empty list of `Attesto.PrincipalKind` values
      or a zero-arity callback returning that list, passed into the core token
      configuration.
    * `:build_principal` - `(client, subject, scope -> map)`. Builds the
      principal map passed to `Attesto.Token.mint/3`.
    * `:build_userinfo_claims` - `(subject, granted_scopes, requested_claims ->
      claims_map)`. Produces the claim values the UserInfo endpoint
      (OpenID Connect Core §5.3) returns for the authenticated subject. The
      host owns the claim source (its user store); the library owns only the
      scope-to-claim shaping (OpenID Connect Core §5.4) and the guarantee that
      `sub` is present (OpenID Connect Core §5.3.2). `granted_scopes` is the
      list of scopes on the access token; `requested_claims` is the per-claim
      request map from the OpenID Connect `claims` parameter (`%{}` when none).
      Required only when the UserInfo endpoint is mounted.
    * `:build_id_token_claims` - `(client, subject, granted_scopes,
      requested_claims -> claims_map)`. Produces the host claims merged into an
      ID Token (OpenID Connect Core §3.1.3.6 / §5.5 `id_token` member). Distinct
      from `:build_userinfo_claims`: it receives the resolved `client`, draws
      from the `claims` parameter's `id_token` member, and MUST NOT carry `sub`
      (the library sets the verified subject; a host-supplied `sub` is rejected
      by `Attesto.IDToken`). Optional - when unset the ID Token carries only the
      protocol claims.
    * `:client_id` - `(client -> String.t())`. Extracts the OAuth client
      identifier from the host's client struct.
    * `:client_jwks` - `(client -> jwks)`. Returns the client's trusted public
      JWK Set for `private_key_jwt` client authentication. Required only for
      clients that authenticate with `private_key_jwt`.
    * `:client_redirect_uris` - `(client -> [String.t()])`. Returns the
      client's registered redirect URIs (RFC 6749 §3.1.2.2). The authorization
      endpoint exact-matches the request `redirect_uri` against this set
      (RFC 6749 §3.1.2.3); a client exposing none rejects every authorization
      request (fail closed).
    * `:authenticate_resource_owner` - `(conn, request, auth_opts ->
      {:authenticated, subject} | {:halt, conn} | {:none} | {:error,
      :login_required | :consent_required | :interaction_required})`.
      Establishes the resource owner for an authorization request (RFC 6749
      §3.1, OIDC Core §3.1.2.3). Returns `{:authenticated, subject}` once a
      resource owner is known (a map carrying at least `:subject`, the OIDC
      `sub`, and optionally `:auth_time`, `:acr`, `:amr`), `{:halt, conn}` to
      take over the connection (e.g. redirect to a host login page that
      re-enters the authorization endpoint), `{:none}` when no subject can be
      established without UI, or an `{:error, _}` classifying why interaction is
      required (OIDC Core §3.1.2.6). `auth_opts` is a map carrying the OIDC Core
      §3.1.2.1 `prompt`/`max_age` directives the host must honour: `:prompt`,
      `:force_reauth` (`prompt=login`), `:interactive` (`false` for
      `prompt=none`, forbidding UI), and `:max_age`. The host owns all login
      UI; the library only invokes this hook. Required only when the
      authorization endpoint is mounted.
    * `:consent` - `(conn, request, subject -> {:consented, subject} |
      {:halt, conn} | {:denied, reason})`. Obtains the resource owner's consent
      for an authorization request (RFC 6749 §4.1.1). Returns
      `{:consented, subject}` to proceed (the returned subject may carry
      consent-derived claims), `{:halt, conn}` to take over the connection (e.g.
      render a consent screen that re-enters the authorization endpoint), or
      `{:denied, reason}` to refuse (reported to the client as `access_denied`,
      RFC 6749 §4.1.2.1). When unset, consent is implicitly granted for the
      authenticated subject.
    * `:client_public?` - `(client -> boolean())`. Returns whether a client
      may authenticate without a secret and rely on PKCE.
    * `:client_requires_mtls?` - `(client -> boolean())`. Returns whether a
      client requires mTLS-bound token issuance.
    * `:client_requires_dpop?` - `(client -> boolean())`. Returns whether a
      client requires DPoP-bound token issuance.
    * `:client_grant_types` - `(client -> [String.t()] | nil)`. Returns the
      grant types registered for this client (RFC 7591 §2). When set, the
      token endpoint rejects a requested grant type not in the returned list.
    * `:issue_refresh_token?` - `(client, granted_scope -> boolean())`.
      Returns whether the authorization-code grant should issue an initial
      refresh token (RFC 6749 §6). When unset, the token controller issues one
      iff the granted scope contains `offline_access` (OIDC Core §11) and a
      `:refresh_store` is configured.
    * `:code_store` - module implementing `Attesto.CodeStore`.
    * `:refresh_store` - module implementing `Attesto.RefreshStore`.
    * `:par_store` - module implementing `AttestoPhoenix.PARStore`.
    * `:grant_types_supported` - grant types advertised/accepted by dynamic
      client registration.
    * `:token_endpoint_auth_methods_supported` - client authentication methods
      advertised/accepted by dynamic client registration and by the token/PAR
      endpoints when configured. When unset, all package-supported methods are
      accepted.

  ### Optional values (with defaults)

    * `:audience` - default access-token audience (string or list).
    * `:client_auth_signing_algs` - the JOSE algorithms accepted for
      `private_key_jwt` client-assertion signatures, and the set advertised as
      `token_endpoint_auth_signing_alg_values_supported` in discovery. Defaults
      to `Attesto.SigningAlg.fapi_algs/0` (PS256, ES256, EdDSA). A non-FAPI
      deployment can widen it; verification and the advertised metadata stay in
      lockstep because both read this one value.
    * `:request_object_policy` - an `Attesto.RequestObject.Policy` controlling
      verification of signed authorization request objects (JAR, RFC 9101).
      Defaults to `%Attesto.RequestObject.Policy{}` (generic OpenID Connect §6.1:
      `nbf`/`exp`/`typ` not required). For FAPI 2.0 Message Signing §5.3.1 set
      `Attesto.RequestObject.Policy.fapi_message_signing()`; the policy is then
      enforced both at the PAR endpoint and at `/authorize`.
    * `:scopes_supported` - list of supported scope strings (concrete and
      wildcard) advertised in discovery and used as the default scope catalog.
      For an OpenID Provider the reserved `openid` scope (OpenID Connect Core
      §3.1.2.1) is added to the OpenID Provider Metadata automatically by the
      core builder; it need not be listed here.
    * `:authorization_endpoint` - absolute URL of the host-owned authorization
      endpoint (RFC 6749 §3.1 / OpenID Connect Discovery §3). The authorization
      endpoint runs the host's login/consent UI, so the library does not mount
      it; the host supplies the URL where it serves it. Advertised in the
      OpenID Provider Metadata; omitted when unset.
    * `:userinfo_endpoint` - absolute URL of the host-owned UserInfo endpoint
      (OpenID Connect Core §5.3). The host owns the claim source, so the
      library does not mount it; the host supplies the URL. Advertised in the
      OpenID Provider Metadata; omitted when unset.
    * `:claims_supported` - list of claim names the host's UserInfo endpoint
      and ID Tokens can return (OpenID Connect Discovery §3). Advertised in the
      OpenID Provider Metadata; omitted when unset.
    * `:claims_parameter_supported` - whether the provider accepts the OpenID
      Connect `claims` request parameter (OpenID Connect Discovery §3 /
      OpenID Connect Core §5.5). Default `false`: the authorization endpoint
      does not consume a `claims` parameter unless the host wires it, so the
      provider does not claim support for it. Advertised in the OpenID Provider
      Metadata only when set to `true` (the core builder treats absence as
      `false` per OpenID Connect Discovery §3).
    * `:acr_values_supported` - list of Authentication Context Class Reference
      values the provider can satisfy (OpenID Connect Discovery §3 /
      OpenID Connect Core §2). Advertised only when the host configures a
      non-empty list; omitted otherwise.
    * `:ui_locales_supported` - list of BCP47 (RFC 5646) language tags the
      provider's UI supports (OpenID Connect Discovery §3). Advertised only
      when the host configures a non-empty list; omitted otherwise.
    * `:require_nonce` - require the OpenID Connect `nonce` parameter on
      OpenID Connect Authentication Requests (OpenID Connect Core §3.1.2.1).
      Default `false`. When `true`, the authorization endpoint passes
      `require_nonce: true` to `Attesto.AuthorizationRequest.validate/2` for a
      request whose scope contains `openid`, so a missing `nonce` on an OIDC
      request is rejected with a redirectable `invalid_request` error. A
      non-OpenID OAuth 2.0 request is never affected (RFC 6749 keeps the
      authorization code at SHOULD, never requiring a `nonce`). The host sets
      this per its own OpenID Provider policy.
    * `:require_pushed_authorization_requests` - require front-channel
      authorization requests to use a PAR `request_uri` issued by this server
      (RFC 9126). Default `false`.
    * `:authorization_response_iss` - include the RFC 9207 `iss` authorization
      response parameter on success and error redirects. Default `false`.
    * `:require_https` - enforce HTTPS on the endpoints. Default `true`.
    * `:trusted_proxies` - list of trusted proxy CIDRs/IPs controlling whether
      `X-Forwarded-*` headers are honored. Default `[]` (no forwarded trust).
    * `:access_token_ttl` - access-token lifetime, seconds. Default `900`.
    * `:refresh_token_ttl` - refresh-token lifetime, seconds. Default `1_209_600`.
    * `:refresh_token_rotation_grace_seconds` - idempotency window, in
      seconds, during which a just-rotated refresh token can be retried and
      receive the same successor refresh token instead of being treated as a
      reuse attack. Default `60`; set `0` for strict immediate reuse
      revocation. A non-zero window is important for clients that lose the
      first rotation response and retry the previous token (OAuth 2.0 Security
      BCP §4.13; FAPI 2.0 Security Profile §5.3.2.1).
    * `:authorization_code_ttl` - authorization-code lifetime, seconds. Default `60`.
    * `:dpop_enabled` - enable DPoP sender-constraint support. Default `true`.
    * `:dpop_nonce_required` - require server-issued DPoP nonces. Default `false`.
    * `:mtls_enabled` - enable mTLS (RFC 8705) `cnf` binding. Default `false`.
    * `:registration_enabled` - enable `/oauth/register`. Default `false`.
    * `:replay_check` - DPoP `jti` replay check (module or `{module, fun}`).
      Defaults to the single-node ETS replay cache.
    * `:nonce_store` - `Attesto.DPoP.NonceStore` implementation. Defaults to
      the single-node ETS nonce store.
    * `:sweep_interval_ms` - interval for `AttestoPhoenix.Store.Sweeper`. The
      sweeper is not started if unset.
    * `:table_prefix` - optional Ecto schema/table prefix for the generated
      tables.

  ### Endpoint paths advertised in metadata

  The discovery documents (RFC 8414 §3, OpenID Connect Discovery §4) and the
  RFC 7591 §3.2.1 registration response advertise absolute endpoint URLs built
  from the `:issuer` and the request path each endpoint is mounted at. By
  default the OAuth endpoints live under `/oauth/*` (the historic surface), but
  a host that mounts them elsewhere (for example under `/mcp/oauth/*` to avoid
  colliding with a legacy provider) MUST advertise the paths it actually serves
  or clients are misdirected. These keys control that, all additive with
  defaults that reproduce the historic `/oauth/*` surface exactly:

    * `:oauth_path_prefix` - path segment prepended to every OAuth endpoint
      tail. Default `"/oauth"`, yielding the historic `/oauth/token`,
      `/oauth/par`, etc. A host mounting under `/mcp/oauth` sets
      `oauth_path_prefix: "/mcp/oauth"` to advertise `/mcp/oauth/token` and so
      on. This is the FULL client-visible mount prefix, since the controllers
      cannot see the surrounding Phoenix `scope`. The well-known documents
      (RFC 8615) and the JWKS document stay anchored at the host root and are
      NOT relocated by this prefix.
    * `:authorize_path`, `:token_path`, `:par_path`, `:revocation_path`,
      `:introspection_path`, `:registration_path`, `:userinfo_path` - explicit per-endpoint path
      overrides. When set, the override wins over `:oauth_path_prefix` for that
      one endpoint (the integrator's "explicit endpoint overrides plus sane
      defaults"). Each defaults to `nil`, meaning "derive from
      `:oauth_path_prefix`". An override is an absolute path reference
      (`"/custom/token"`), advertised verbatim merged onto the issuer.

  Use the resolver helpers (`token_endpoint_url/1`, `par_endpoint_url/1`,
  `revocation_endpoint_url/1`, `registration_endpoint_url/1`,
  `userinfo_endpoint_url/1`, `authorize_endpoint_url/1`, `jwks_uri/1`, and the
  resolved-path helpers `token_path/1` and friends) rather than re-deriving the
  URLs in callers; the router macro derives its mounted-route tails from the
  same source so the mounted routes and the advertised routes cannot drift.

  ## Recommended production callback contracts

  The loose `*_client`, `*_principal`, `authorize_scope`, consent, registration,
  and event callbacks above are grouped into named behaviours that document the
  full contract (with the governing RFC for each callback) and serve as the
  recommended production shape: `AttestoPhoenix.ClientStore`,
  `AttestoPhoenix.PrincipalStore`, `AttestoPhoenix.ScopePolicy`,
  `AttestoPhoenix.ConsentPolicy`, `AttestoPhoenix.RegistrationStore`, and
  `AttestoPhoenix.EventSink`. Wiring stays identical: pass an anonymous
  function, a `{module, function}` pair, or a `{module, function, extra_args}`
  triple per key as documented above. The behaviours are the contract; the
  Config keys are how a host installs an implementation.

  ## Behaviour-module Config keys

  Rather than wiring every host callback as an individual flat key, a host may
  install one behaviour module per concern and let the library resolve each
  callback from it:

    * `:client_store` - a module implementing `AttestoPhoenix.ClientStore`.
    * `:principal_store` - a module implementing `AttestoPhoenix.PrincipalStore`.
    * `:consent_policy` - a module implementing `AttestoPhoenix.ConsentPolicy`.
    * `:scope_policy` - a module implementing `AttestoPhoenix.ScopePolicy`.
    * `:event_sink` - a module implementing `AttestoPhoenix.EventSink`.
    * `:registration` - a module implementing `AttestoPhoenix.RegistrationStore`.
    * `:claims_provider` - a module implementing `AttestoPhoenix.ClaimsProvider`.

  Each per-callback value is resolved through the matching resolver fun on this
  module (`client_id_fun/1`, `load_principal_fun/1`, `consent_fun/1`, and so on)
  with a single precedence: the explicit flat key wins when set; otherwise, when
  a behaviour module is installed and exports the corresponding behaviour
  callback (after `Code.ensure_loaded/1`), the `{module, function}` pair is used;
  otherwise the resolution is `nil` (and the consumer's existing fail-closed
  default applies). Flat keys therefore never break: a host that wires the
  individual callbacks keeps the exact behaviour it had. `new/1` validates at
  boot that any installed behaviour module is loadable and exports the callbacks
  it claims, so a typo'd or partial module fails fast rather than silently
  resolving to `nil` at request time.
  """

  alias AttestoPhoenix.Callback

  # Only the plain required *values* are enforced by `struct!/2`. The required
  # *capabilities* (`:load_client`, `:verify_client_secret`, `:load_principal`)
  # are NOT enforced here, because a host may supply them via an installed
  # behaviour module (`:client_store` / `:principal_store`) instead of a flat
  # callback. They are validated by resolution in `validate!/1` so the
  # behaviour-module install path actually works.
  @enforce_keys [
    :issuer,
    :keystore,
    :repo
  ]
  defstruct [
    :issuer,
    :keystore,
    :repo,
    :load_client,
    :verify_client_secret,
    :load_principal,
    :client_store,
    :principal_store,
    :consent_policy,
    :scope_policy,
    :event_sink,
    :registration,
    :claims_provider,
    :client_auth_signing_algs,
    :request_object_policy,
    :audience,
    :authorize_scope,
    :on_event,
    :send_error,
    :no_store,
    :www_authenticate,
    :htu,
    :cert_der,
    :register_client,
    :unregister_client,
    :client_registration_access_token_hash,
    :principal_kinds,
    :build_principal,
    :build_userinfo_claims,
    :build_id_token_claims,
    :client_id,
    :client_jwks,
    :client_redirect_uris,
    :authenticate_resource_owner,
    :consent,
    :client_public?,
    :client_requires_mtls?,
    :client_requires_dpop?,
    :client_grant_types,
    :issue_refresh_token?,
    :code_store,
    :refresh_store,
    :par_store,
    :grant_types_supported,
    :token_endpoint_auth_methods_supported,
    :authorization_endpoint,
    :userinfo_endpoint,
    :replay_check,
    :nonce_store,
    :sweep_interval_ms,
    :table_prefix,
    :authorize_path,
    :token_path,
    :par_path,
    :revocation_path,
    :introspection_path,
    :registration_path,
    :userinfo_path,
    oauth_path_prefix: "/oauth",
    scopes_supported: [],
    claims_supported: [],
    acr_values_supported: [],
    ui_locales_supported: [],
    claims_parameter_supported: false,
    require_nonce: false,
    require_pkce: true,
    require_pushed_authorization_requests: false,
    authorization_response_iss: false,
    require_https: true,
    trusted_proxies: [],
    access_token_ttl: 900,
    refresh_token_ttl: 1_209_600,
    refresh_token_rotation_grace_seconds: 60,
    authorization_code_ttl: 60,
    par_ttl: 90,
    dpop_enabled: true,
    dpop_nonce_required: false,
    mtls_enabled: false,
    registration_enabled: false,
    basic_realm: "OAuth"
  ]

  # A host callback is an anonymous function, a `{module, function}` pair, or a
  # `{module, function, extra_args}` triple. The triple is NOT `mfa()`: its third
  # element is a list of extra arguments appended after the call arguments
  # (`apply(module, function, args ++ extra)`), not an arity. Spelling it `mfa()`
  # would type that element as `arity()` (`0..255`), which contradicts the
  # `is_list/1` dispatch in every `invoke/2` helper that consumes this type.
  @type callback :: function() | {module(), atom()} | {module(), atom(), [any()]}

  @type t :: %__MODULE__{
          issuer: String.t(),
          keystore: module(),
          repo: module(),
          load_client: callback(),
          verify_client_secret: callback(),
          load_principal: callback(),
          client_store: module() | nil,
          principal_store: module() | nil,
          consent_policy: module() | nil,
          scope_policy: module() | nil,
          event_sink: module() | nil,
          registration: module() | nil,
          claims_provider: module() | nil,
          client_auth_signing_algs: [String.t()] | nil,
          request_object_policy: Attesto.RequestObject.Policy.t() | nil,
          audience: String.t() | [String.t()] | nil,
          authorize_scope: callback() | nil,
          on_event: callback() | nil,
          send_error: callback() | nil,
          no_store: callback() | nil,
          www_authenticate: callback() | nil,
          basic_realm: String.t(),
          htu: callback() | nil,
          cert_der: callback() | nil,
          register_client: callback() | nil,
          unregister_client: callback() | nil,
          client_registration_access_token_hash: callback() | nil,
          principal_kinds: [Attesto.PrincipalKind.t()] | callback() | nil,
          build_principal: callback() | nil,
          build_userinfo_claims: callback() | nil,
          build_id_token_claims: callback() | nil,
          client_id: callback() | nil,
          client_jwks: callback() | nil,
          client_redirect_uris: callback() | nil,
          authenticate_resource_owner: callback() | nil,
          consent: callback() | nil,
          client_public?: callback() | nil,
          client_requires_mtls?: callback() | nil,
          client_requires_dpop?: callback() | nil,
          client_grant_types: callback() | nil,
          issue_refresh_token?: callback() | nil,
          code_store: module() | nil,
          refresh_store: module() | nil,
          par_store: module() | nil,
          grant_types_supported: [String.t()] | nil,
          token_endpoint_auth_methods_supported: [String.t()] | nil,
          require_pushed_authorization_requests: boolean(),
          authorization_response_iss: boolean(),
          authorization_endpoint: String.t() | nil,
          userinfo_endpoint: String.t() | nil,
          replay_check: callback() | module() | nil,
          nonce_store: module() | nil,
          sweep_interval_ms: pos_integer() | nil,
          table_prefix: String.t() | nil,
          oauth_path_prefix: String.t(),
          authorize_path: String.t() | nil,
          token_path: String.t() | nil,
          par_path: String.t() | nil,
          revocation_path: String.t() | nil,
          introspection_path: String.t() | nil,
          registration_path: String.t() | nil,
          userinfo_path: String.t() | nil,
          scopes_supported: [String.t()],
          claims_supported: [String.t()],
          acr_values_supported: [String.t()],
          ui_locales_supported: [String.t()],
          claims_parameter_supported: boolean(),
          require_nonce: boolean(),
          require_pkce: boolean(),
          require_https: boolean(),
          trusted_proxies: [String.t()],
          access_token_ttl: pos_integer(),
          refresh_token_ttl: pos_integer(),
          refresh_token_rotation_grace_seconds: non_neg_integer(),
          authorization_code_ttl: pos_integer(),
          par_ttl: pos_integer(),
          dpop_enabled: boolean(),
          dpop_nonce_required: boolean(),
          mtls_enabled: boolean(),
          registration_enabled: boolean()
        }

  # Required plain values: enforced for presence as struct fields.
  @required @enforce_keys

  # Required capabilities: each must RESOLVE (flat callback or installed
  # behaviour module), validated in `validate!/1` after construction.
  @required_capabilities [:load_client, :verify_client_secret, :load_principal]

  @doc """
  Builds and validates a config from a keyword list or map.

  Raises `ArgumentError` if a required key is missing or if a dependent key is
  absent for an enabled feature (e.g. `:register_client` when
  `:registration_enabled`, or `:cert_der` when `:mtls_enabled`).
  """
  @spec new(keyword() | map()) :: t()
  def new(opts) when is_list(opts), do: opts |> Map.new() |> new()

  def new(opts) when is_map(opts) do
    __MODULE__
    |> struct!(opts)
    |> apply_defaults()
    |> validate!()
  end

  # Defaults that cannot be static struct values (they call a function).
  defp apply_defaults(%__MODULE__{} = config) do
    %{
      config
      | client_auth_signing_algs:
          config.client_auth_signing_algs || Attesto.SigningAlg.fapi_algs(),
        request_object_policy: config.request_object_policy || %Attesto.RequestObject.Policy{}
    }
  end

  @doc """
  Reads the config for `otp_app` under `key` (default `AttestoPhoenix`) from the
  application environment and builds a validated config.
  """
  @spec from_otp_app(atom(), atom()) :: t()
  def from_otp_app(otp_app, key \\ __MODULE__) when is_atom(otp_app) do
    otp_app
    |> Application.get_env(key, [])
    |> new()
  end

  @doc """
  Derives the `Attesto.Config` consumed by the protocol layer from this config.

  The protocol layer owns only the claim-level policy (`:issuer`, `:audience`,
  `:keystore`, the principal kinds, and the default access-token lifetime). The
  refresh/code TTLs and the DPoP/mTLS feature toggles are read directly from
  this struct by the controllers and plugs, so they are not duplicated into the
  `Attesto.Config`.

  Pass `principal_kinds:` (a non-empty list of `Attesto.PrincipalKind`) and any
  other `Attesto.Config.new/1` option as `extra` to complete the protocol
  config; they are merged over the values derived here.
  """
  @spec to_attesto_config(t(), keyword()) :: Attesto.Config.t()
  def to_attesto_config(%__MODULE__{} = config, extra \\ []) do
    # The resolved token path is passed automatically so the core builder's
    # `token_endpoint` (and the DPoP `htu` it derives) reflect where the host
    # mounted the endpoint, without the consumer hand-passing
    # `token_endpoint_path`. `extra` still wins (it is merged last) so a host
    # can override it explicitly if it must.
    [
      issuer: config.issuer,
      audience: config.audience,
      keystore: config.keystore,
      default_lifetime_seconds: config.access_token_ttl,
      token_endpoint_path: token_path(config)
    ]
    |> Keyword.merge(resolved_principal_kinds(config))
    |> Keyword.merge(extra)
    |> Attesto.Config.new()
  end

  # Resolve the host's `:principal_kinds` (a list or a callback returning one)
  # so to_attesto_config/1 yields a complete Attesto.Config for callers that do
  # not pass principal_kinds explicitly (e.g. the authorization endpoint signing
  # JARM responses). An explicit `extra` still wins. Omitted when unresolved so
  # Attesto.Config.new/1 surfaces the missing required value.
  defp resolved_principal_kinds(%__MODULE__{} = config) do
    case Callback.config_callback(config, :principal_kinds) do
      kinds when is_list(kinds) and kinds != [] ->
        [principal_kinds: kinds]

      nil ->
        []

      callback ->
        case Callback.invoke(callback, []) do
          kinds when is_list(kinds) and kinds != [] -> [principal_kinds: kinds]
          _ -> []
        end
    end
  end

  # The default OAuth endpoint tails appended to the resolved
  # `:oauth_path_prefix` when no explicit per-endpoint override is set. These
  # reproduce the historic `/oauth/*` surface when the prefix is its default
  # `"/oauth"`.
  @authorize_tail "/authorize"
  @token_tail "/token"
  @par_tail "/par"
  @revocation_tail "/revoke"
  @introspection_tail "/introspect"
  @registration_tail "/register"
  @userinfo_tail "/userinfo"

  @doc false
  @spec authorize_tail() :: String.t()
  def authorize_tail, do: @authorize_tail

  @doc false
  @spec token_tail() :: String.t()
  def token_tail, do: @token_tail

  @doc false
  @spec par_tail() :: String.t()
  def par_tail, do: @par_tail

  @doc false
  @spec revocation_tail() :: String.t()
  def revocation_tail, do: @revocation_tail

  @doc false
  @spec introspection_tail() :: String.t()
  def introspection_tail, do: @introspection_tail

  @doc false
  @spec registration_tail() :: String.t()
  def registration_tail, do: @registration_tail

  @doc false
  @spec userinfo_tail() :: String.t()
  def userinfo_tail, do: @userinfo_tail

  @doc """
  The resolved request path of the authorization endpoint: the explicit
  `:authorize_path` override when set, otherwise `:oauth_path_prefix` joined
  with the conventional `#{@authorize_tail}` tail.
  """
  @spec authorize_path(t()) :: String.t()
  def authorize_path(%__MODULE__{authorize_path: override} = config),
    do: resolve_path(override, config, @authorize_tail)

  @doc """
  The resolved request path of the token endpoint. See `authorize_path/1`.
  """
  @spec token_path(t()) :: String.t()
  def token_path(%__MODULE__{token_path: override} = config),
    do: resolve_path(override, config, @token_tail)

  @doc """
  The resolved request path of the pushed-authorization-request endpoint
  (RFC 9126). See `authorize_path/1`.
  """
  @spec par_path(t()) :: String.t()
  def par_path(%__MODULE__{par_path: override} = config),
    do: resolve_path(override, config, @par_tail)

  @doc """
  The resolved request path of the revocation endpoint (RFC 7009). See
  `authorize_path/1`.
  """
  @spec revocation_path(t()) :: String.t()
  def revocation_path(%__MODULE__{revocation_path: override} = config),
    do: resolve_path(override, config, @revocation_tail)

  @doc """
  The resolved request path of the token introspection endpoint (RFC 7662). See
  `authorize_path/1`.
  """
  @spec introspection_path(t()) :: String.t()
  def introspection_path(%__MODULE__{introspection_path: override} = config),
    do: resolve_path(override, config, @introspection_tail)

  @doc """
  The resolved request path of the dynamic client registration endpoint
  (RFC 7591). See `authorize_path/1`.
  """
  @spec registration_path(t()) :: String.t()
  def registration_path(%__MODULE__{registration_path: override} = config),
    do: resolve_path(override, config, @registration_tail)

  @doc """
  The resolved request path of the UserInfo endpoint (OpenID Connect Core
  §5.3). See `authorize_path/1`.
  """
  @spec userinfo_path(t()) :: String.t()
  def userinfo_path(%__MODULE__{userinfo_path: override} = config),
    do: resolve_path(override, config, @userinfo_tail)

  # An explicit per-endpoint override wins over the prefix; otherwise the
  # endpoint path is the prefix joined with the conventional tail. The prefix
  # default `"/oauth"` reproduces the historic surface.
  defp resolve_path(override, _config, _tail) when is_binary(override) and override != "",
    do: override

  defp resolve_path(_override, %__MODULE__{oauth_path_prefix: prefix}, tail),
    do: join_path(prefix, tail)

  # Join a prefix and a tail into a single absolute path, collapsing the seam so
  # neither a trailing slash on the prefix nor the leading slash on the tail
  # doubles up.
  defp join_path(prefix, tail) do
    prefix = String.trim_trailing(to_string(prefix), "/")
    tail = "/" <> String.trim_leading(tail, "/")
    prefix <> tail
  end

  @doc """
  Absolute URL of the authorization endpoint: the issuer merged with
  `authorize_path/1`. Advertised in the OpenID Provider Metadata when the host
  does not supply a separate `:authorization_endpoint`.
  """
  @spec authorize_endpoint_url(t()) :: String.t()
  def authorize_endpoint_url(%__MODULE__{} = config),
    do: endpoint_url(config, authorize_path(config))

  @doc """
  Absolute URL of the token endpoint: the issuer merged with `token_path/1`.
  Advertised as `token_endpoint` (RFC 8414 §2).
  """
  @spec token_endpoint_url(t()) :: String.t()
  def token_endpoint_url(%__MODULE__{} = config),
    do: endpoint_url(config, token_path(config))

  @doc """
  Absolute URL of the pushed-authorization-request endpoint: the issuer merged
  with `par_path/1`. Advertised as `pushed_authorization_request_endpoint`
  (RFC 9126 §5).
  """
  @spec par_endpoint_url(t()) :: String.t()
  def par_endpoint_url(%__MODULE__{} = config),
    do: endpoint_url(config, par_path(config))

  @doc """
  Absolute URL of the revocation endpoint: the issuer merged with
  `revocation_path/1`. Advertised as `revocation_endpoint` (RFC 8414 §2,
  RFC 7009).
  """
  @spec revocation_endpoint_url(t()) :: String.t()
  def revocation_endpoint_url(%__MODULE__{} = config),
    do: endpoint_url(config, revocation_path(config))

  @doc """
  Absolute URL of the token introspection endpoint (RFC 7662): the issuer merged
  with `introspection_path/1`. Advertised as `introspection_endpoint`.
  """
  @spec introspection_endpoint_url(t()) :: String.t()
  def introspection_endpoint_url(%__MODULE__{} = config),
    do: endpoint_url(config, introspection_path(config))

  @doc """
  Absolute URL of the dynamic client registration endpoint: the issuer merged
  with `registration_path/1`. Advertised as `registration_endpoint` (RFC 7591
  §3) only when registration is enabled.
  """
  @spec registration_endpoint_url(t()) :: String.t()
  def registration_endpoint_url(%__MODULE__{} = config),
    do: endpoint_url(config, registration_path(config))

  @doc """
  Absolute URL of the UserInfo endpoint: the issuer merged with
  `userinfo_path/1`. Used when the host does not supply a separate
  `:userinfo_endpoint`.
  """
  @spec userinfo_endpoint_url(t()) :: String.t()
  def userinfo_endpoint_url(%__MODULE__{} = config),
    do: endpoint_url(config, userinfo_path(config))

  @doc """
  Absolute URL of an individual registered client's RFC 7592 management
  endpoint: the registration endpoint URL with the URL-encoded `client_id`
  appended. Returned as `registration_client_uri` in the RFC 7591 §3.2.1
  client information response.
  """
  @spec registration_client_uri(t(), String.t()) :: String.t()
  def registration_client_uri(%__MODULE__{} = config, client_id) when is_binary(client_id) do
    encoded = URI.encode(client_id, &URI.char_unreserved?/1)
    endpoint_url(config, join_path(registration_path(config), encoded))
  end

  @doc """
  Absolute URL of the JWK Set document (RFC 7517 §5; the `jwks_uri` per
  RFC 8414 §2). The JWKS document is anchored at the host root under RFC 8615,
  so it is NOT relocated by `:oauth_path_prefix`.
  """
  @spec jwks_uri(t()) :: String.t()
  def jwks_uri(%__MODULE__{} = config),
    do: endpoint_url(config, "/.well-known/jwks.json")

  defp endpoint_url(%__MODULE__{issuer: issuer}, path) do
    issuer
    |> URI.parse()
    |> URI.merge(path)
    |> URI.to_string()
  end

  # ── Behaviour-module callback resolution ─────────────────────────────────

  # The resolution table. Each flat callback key maps to the behaviour-module
  # Config key that owns it and the `{function, arity}` that module must export
  # for the `{module, function}` form to win. The precedence is fixed: an
  # explicit flat key wins; else the installed behaviour module if it exports
  # the callback; else `nil`. The arity is the behaviour callback's arity, used
  # only for the `function_exported?` conformance check - the resolved value is
  # the bare `{module, function}` pair, invoked by the caller through
  # `AttestoPhoenix.Callback.invoke/2,3` (which appends the per-call args).
  #
  # `:registration` carries the optional management callbacks too, so a host
  # that installs a single registration module gets RFC 7592 management for
  # free; the required `register_client/1` stays a flat-only required key.
  @resolution %{
    load_client: {:client_store, :load_client, 1},
    verify_client_secret: {:client_store, :verify_client_secret, 2},
    client_id: {:client_store, :client_id, 1},
    client_jwks: {:client_store, :client_jwks, 1},
    client_redirect_uris: {:client_store, :client_redirect_uris, 1},
    client_public?: {:client_store, :client_public?, 1},
    client_requires_mtls?: {:client_store, :client_requires_mtls?, 1},
    client_requires_dpop?: {:client_store, :client_requires_dpop?, 1},
    client_grant_types: {:client_store, :client_grant_types, 1},
    load_principal: {:principal_store, :load_principal, 1},
    build_principal: {:principal_store, :build_principal, 3},
    authenticate_resource_owner: {:consent_policy, :authenticate_resource_owner, 3},
    consent: {:consent_policy, :consent, 3},
    authorize_scope: {:scope_policy, :authorize_scope, 2},
    on_event: {:event_sink, :on_event, 1},
    register_client: {:registration, :register_client, 1},
    unregister_client: {:registration, :unregister_client, 1},
    client_registration_access_token_hash:
      {:registration, :client_registration_access_token_hash, 1},
    build_userinfo_claims: {:claims_provider, :build_userinfo_claims, 3},
    build_id_token_claims: {:claims_provider, :build_id_token_claims, 4}
  }

  # The behaviour-module Config keys, each paired with the behaviour module it
  # is expected to implement. Used for boot-time conformance validation.
  @behaviour_modules %{
    client_store: AttestoPhoenix.ClientStore,
    principal_store: AttestoPhoenix.PrincipalStore,
    consent_policy: AttestoPhoenix.ConsentPolicy,
    scope_policy: AttestoPhoenix.ScopePolicy,
    event_sink: AttestoPhoenix.EventSink,
    registration: AttestoPhoenix.RegistrationStore,
    claims_provider: AttestoPhoenix.ClaimsProvider
  }

  @doc """
  Resolve a configured callback by its flat `key`.

  Precedence (see the "Behaviour-module Config keys" section): the explicit
  flat key wins when set; otherwise the installed behaviour module wins when it
  exports the corresponding behaviour callback; otherwise `nil`. The result is a
  value an `AttestoPhoenix.Callback.invoke/2,3` caller can run (an anonymous
  function, a `{module, function}` pair, a `{module, function, extra_args}`
  triple), or `nil`.
  """
  @spec resolve_callback(t(), atom()) :: callback() | nil
  def resolve_callback(%__MODULE__{} = config, key) when is_atom(key) do
    case Map.get(config, key) do
      nil -> resolve_from_store(config, key)
      flat -> flat
    end
  end

  defp resolve_from_store(%__MODULE__{} = config, key) do
    with {store_key, fun, arity} <- Map.get(@resolution, key),
         module when is_atom(module) and not is_nil(module) <- Map.get(config, store_key),
         true <- callback_exported?(module, fun, arity) do
      {module, fun}
    else
      _ -> nil
    end
  end

  defp callback_exported?(module, fun, arity) do
    Code.ensure_loaded?(module) and function_exported?(module, fun, arity)
  end

  # One resolver fun per flat callback key. Each is a thin alias over
  # `resolve_callback/2` so consumers read the callback by name without knowing
  # the resolution table, matching the integrator's "resolver funs on Config"
  # surface. They return the same `callback()`-or-`nil` value.
  for {key, _} <- @resolution do
    name = key |> Atom.to_string() |> String.trim_trailing("?") |> Kernel.<>("_fun")
    name = String.to_atom(name)

    @doc """
    Resolve the `#{key}` callback. See `resolve_callback/2`.
    """
    @spec unquote(name)(t()) :: callback() | nil
    def unquote(name)(%__MODULE__{} = config), do: resolve_callback(config, unquote(key))
  end

  @doc """
  Resolve and load the host's client by `client_id` (RFC 6749 §2.2).

  A required callback (`:load_client` / `AttestoPhoenix.ClientStore`); this
  helper invokes the resolved callback so consumers do not re-derive it.
  """
  @spec client_store_load(t(), String.t()) :: term()
  def client_store_load(%__MODULE__{} = config, client_id),
    do: Callback.invoke(load_client_fun(config), [client_id])

  @doc """
  Resolve and run the host's constant-time client-secret verification
  (RFC 6749 §2.3.1) for `client`/`presented_secret`.
  """
  @spec client_store_verify_secret(t(), term(), String.t()) :: boolean()
  def client_store_verify_secret(%__MODULE__{} = config, client, presented_secret),
    do: Callback.invoke(verify_client_secret_fun(config), [client, presented_secret]) == true

  @doc """
  Invokes the host's `:build_userinfo_claims` callback for the authenticated
  subject and returns the raw claims map it produces.

  The callback is applied with `[subject, granted_scopes, requested_claims]`
  (see the `:build_userinfo_claims` key documentation). It is the claim source
  for the UserInfo endpoint (OpenID Connect Core §5.3); the host owns the claim
  values, the controller owns the scope-to-claim shaping. Raises
  `ArgumentError` when the host has not configured the callback, so a mounted
  UserInfo endpoint cannot silently return an empty document.
  """
  @spec build_userinfo_claims(t(), String.t(), [String.t()], map()) :: map()
  def build_userinfo_claims(%__MODULE__{} = config, subject, scopes, requested) do
    case build_userinfo_claims_fun(config) do
      nil ->
        raise ArgumentError,
              "AttestoPhoenix.Config: :build_userinfo_claims is required to serve the UserInfo endpoint"

      callback ->
        Callback.invoke(callback, [subject, scopes, requested])
    end
  end

  defp validate!(%__MODULE__{} = config) do
    Enum.each(@required, fn key ->
      if is_nil(Map.fetch!(config, key)) do
        raise ArgumentError,
              "AttestoPhoenix.Config: required key #{inspect(key)} is missing. " <>
                required_key_hint(key)
      end
    end)

    # Required capabilities are validated by RESOLUTION, not flat-key presence,
    # so installing a behaviour module (`:client_store`/`:principal_store`)
    # satisfies them just as a flat callback does.
    Enum.each(@required_capabilities, fn capability ->
      if is_nil(resolve_callback(config, capability)) do
        raise ArgumentError, required_capability_hint(capability)
      end
    end)

    if config.mtls_enabled and is_nil(config.cert_der) do
      raise ArgumentError,
            "AttestoPhoenix.Config: :cert_der is required when :mtls_enabled is true. " <>
              "Add a `cert_der: &MyApp.AuthZ.cert_der/1` callback " <>
              "(implements AttestoPhoenix.ClientStore-adjacent mTLS extraction) " <>
              "or set `mtls_enabled: false`."
    end

    if config.registration_enabled and is_nil(register_client_fun(config)) do
      raise ArgumentError,
            "AttestoPhoenix.Config: :register_client is required when " <>
              ":registration_enabled is true. Add a " <>
              "`register_client: &MyApp.AuthZ.register_client/1` callback " <>
              "(or install a `:registration` module implementing " <>
              "AttestoPhoenix.RegistrationStore) or set " <>
              "`registration_enabled: false` so no registration endpoint is mounted."
    end

    validate_behaviour_modules!(config)
    validate_request_object_policy!(config)

    validate_path!(:oauth_path_prefix, config.oauth_path_prefix)
    validate_optional_path!(:authorize_path, config.authorize_path)
    validate_optional_path!(:token_path, config.token_path)
    validate_optional_path!(:par_path, config.par_path)
    validate_optional_path!(:revocation_path, config.revocation_path)
    validate_optional_path!(:registration_path, config.registration_path)
    validate_optional_path!(:userinfo_path, config.userinfo_path)

    config
  end

  # The required (non-optional) behaviour callbacks each installed
  # behaviour-module Config key must export. A module installed under the key
  # must be loadable and export every `{function, arity}` here, so a typo'd or
  # partial module fails fast at boot rather than silently resolving to `nil`
  # at request time. Optional behaviour callbacks are not listed: a module may
  # omit them and the resolver falls through to `nil` (the consumer's
  # fail-closed default), so they are not boot errors.
  @behaviour_required %{
    client_store: [load_client: 1, verify_client_secret: 2],
    principal_store: [load_principal: 1],
    consent_policy: [],
    scope_policy: [authorize_scope: 2],
    event_sink: [on_event: 1],
    registration: [register_client: 1],
    claims_provider: []
  }

  # Boot-time conformance: every installed behaviour module must be loadable and
  # must export the required callbacks of the behaviour it is installed as.
  # `:request_object_policy` is a security knob; reject a wrong value at boot
  # rather than crashing later in `RequestObject.Policy.to_verify_opts/1` when a
  # PAR or /authorize request is verified. `apply_defaults/1` has already
  # replaced a `nil` with `%Attesto.RequestObject.Policy{}`.
  defp validate_request_object_policy!(%__MODULE__{
         request_object_policy: %Attesto.RequestObject.Policy{}
       }),
       do: :ok

  defp validate_request_object_policy!(%__MODULE__{request_object_policy: other}) do
    raise ArgumentError,
          "AttestoPhoenix.Config: :request_object_policy must be an " <>
            "%Attesto.RequestObject.Policy{} (e.g. " <>
            "Attesto.RequestObject.Policy.fapi_message_signing/0); got #{inspect(other)}."
  end

  defp validate_behaviour_modules!(%__MODULE__{} = config) do
    Enum.each(@behaviour_modules, fn {store_key, behaviour} ->
      case Map.get(config, store_key) do
        nil -> :ok
        module -> validate_behaviour_module!(store_key, behaviour, module, config)
      end
    end)
  end

  defp validate_behaviour_module!(store_key, behaviour, module, _config) when is_atom(module) do
    unless Code.ensure_loaded?(module) do
      raise ArgumentError,
            "AttestoPhoenix.Config: #{inspect(store_key)} is set to #{inspect(module)}, " <>
              "which cannot be loaded. Set it to a module implementing " <>
              "#{inspect(behaviour)}."
    end

    Enum.each(Map.fetch!(@behaviour_required, store_key), fn {fun, arity} ->
      unless function_exported?(module, fun, arity) do
        raise ArgumentError,
              "AttestoPhoenix.Config: #{inspect(store_key)} module #{inspect(module)} " <>
                "does not export #{fun}/#{arity}, required by #{inspect(behaviour)}."
      end
    end)
  end

  defp validate_behaviour_module!(store_key, behaviour, module, _config) do
    raise ArgumentError,
          "AttestoPhoenix.Config: #{inspect(store_key)} must be a module implementing " <>
            "#{inspect(behaviour)}; got #{inspect(module)}."
  end

  # The store/callback each required key installs, so a missing-key error tells
  # the host exactly what to wire rather than just naming the key.
  defp required_key_hint(:issuer),
    do: "Set it to the https issuer URL (RFC 8414 §2), e.g. \"https://api.example\"."

  defp required_key_hint(:keystore),
    do: "Set it to a module implementing the Attesto.Keystore behaviour."

  defp required_key_hint(:repo), do: "Set it to your Ecto.Repo module."

  defp required_key_hint(_key), do: ""

  # A required capability is unresolved when neither the flat callback nor an
  # installed behaviour module provides it. Name BOTH install routes so the host
  # knows it can wire a flat callback OR install the owning behaviour module.
  defp required_capability_hint(capability) do
    {store_key, fun, arity} = Map.fetch!(@resolution, capability)
    behaviour = Map.fetch!(@behaviour_modules, store_key)

    "AttestoPhoenix.Config: the #{inspect(capability)} capability is required but " <>
      "unresolved. Provide it either as a flat callback " <>
      "(`#{capability}: &MyApp.AuthZ.#{fun}/#{arity}`) or by installing a " <>
      "`#{inspect(store_key)}` module implementing #{inspect(behaviour)} " <>
      "(which exports #{fun}/#{arity})."
  end

  # `:oauth_path_prefix` is always present (defaulted); it must be an absolute
  # path reference so it merges cleanly onto the issuer.
  defp validate_path!(key, value) do
    if not (is_binary(value) and String.starts_with?(value, "/")) do
      raise ArgumentError,
            "AttestoPhoenix.Config: #{inspect(key)} must be an absolute path " <>
              "beginning with \"/\" (e.g. \"/oauth\" or \"/mcp/oauth\"); got #{inspect(value)}"
    end
  end

  # A per-endpoint override is optional (nil = derive from the prefix); when
  # set it must be an absolute path reference.
  defp validate_optional_path!(_key, nil), do: :ok
  defp validate_optional_path!(key, value), do: validate_path!(key, value)
end
