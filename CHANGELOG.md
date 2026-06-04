# Changelog

All notable changes to this project are documented here. The format is
based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and this
project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Security / FAPI 2.0 conformance

Closes four conformance gaps found by auditing the OpenID FAPI 2.0 test suite
source against the implementation:

- **PAR `request_uri` is bound to the client.** The authorization endpoint now
  rejects a front-channel `client_id` that does not match the client the
  `request_uri` was issued to (RFC 9126 §2.2 / `PAREnsureRequestUriIsBoundToClient`)
  instead of silently using the stored client.
- **Unknown/expired PAR `request_uri` → `invalid_request_uri`.** A
  `urn:ietf:params:oauth:request_uri:` reference not in the store now returns the
  correct `invalid_request_uri` error rather than falling through to
  `request_uri_not_supported`/`invalid_request` (RFC 9126 §2.2 /
  `PARAttemptToUseExpiredRequestUri`). External (non-PAR) references still report
  `request_uri_not_supported`.
- **PAR rejects a `request_uri` parameter.** The PAR endpoint rejects a request
  carrying `request_uri` (RFC 9126 §2.1 step 2), checked on the raw parameters so
  it cannot be masked by a `request` object replacing the set.
- **Client-assertion audience is issuer-only.** `private_key_jwt` assertions at
  the token, PAR, and introspection endpoints must be audienced to the issuer
  identifier (FAPI 2.0 §5.3.2.1); the concrete endpoint URL is no longer accepted
  as `aud`, closing a confused-deputy gap (`PAREndpointAsAudienceFails`).

### Changed

- `:authorization_response_iss` now defaults to **`true`** (RFC 9207
  authorization-server mix-up defense, mandated by FAPI 2.0). Set `false` to opt
  out. Discovery advertises `authorization_response_iss_parameter_supported`
  accordingly.
- Internal: `mix dialyzer` is clean again. `token.ex` resolves `:principal_kinds`
  by reading the struct field directly (its type admits a list, unlike the
  `callback() | nil` reader), and two fail-closed grant-pipeline clauses are
  documented in `.dialyzer_ignore.exs`. No behaviour change.

## [0.7.3] - 2026-06-04

The FAPI 2.0 Message Signing endpoints on the Phoenix layer: signed
authorization responses (JARM), the RFC 7662 / RFC 9701 introspection endpoint,
and PAR/JAR hardening. Requires `attesto ~> 0.6.13`.

### Added

- `POST /oauth/introspect` — OAuth 2.0 Token Introspection (RFC 7662) with the
  RFC 9701 signed-JWT response (FAPI 2.0 Message Signing §5.5). Authenticates
  the caller through the shared `AttestoPhoenix.ClientAuthentication` core
  (`client_secret_basic`/`client_secret_post`/`private_key_jwt`), introspects
  via the conn-free `Attesto.Introspection`, and negotiates by `Accept` between
  the plain JSON response and `application/token-introspection+jwt`.
- `:introspection_authorize` Config callback `(caller_client_id, response ->
  boolean)` — authorizes the authenticated introspection caller against the
  token (RFC 7662 §4 / RFC 9701 §5). Consulted only for an active response;
  a non-`true` return (or a raise) downgrades the response to
  `%{"active" => false}` so a caller not entitled to the token learns nothing
  about it. Optional — when unset, every authenticated caller may introspect
  any token (the single-trust-domain default).
- The authorization endpoint emits JARM (§5.4) responses for the JARM
  `response_mode`s (`jwt`/`query.jwt`/`fragment.jwt`/`form_post.jwt`), and the
  discovery documents advertise the supported `response_modes_supported`,
  `authorization_signing_alg_values_supported`, the introspection endpoint, and
  its signing-algorithm metadata.

### Changed

- The PAR endpoint now validates the pushed request as an authorization request
  at push time (RFC 9126 §2.1 step 3): the request `redirect_uri` must exactly
  match one of the client's registered URIs (RFC 6749 §3.1.2.3), and the
  `response_type`/PKCE/`response_mode` must be valid, so an invalid request is
  refused early rather than only when the `request_uri` is later resolved at
  `/authorize`. The redirect-URI/PKCE/nonce policy is resolved by the new
  conn-free `AttestoPhoenix.AuthorizationServer.RequestPolicy`, shared with the
  authorization endpoint so both validate identically. **A host that mounts the
  PAR endpoint must configure `:client_redirect_uris`** (the authorization
  endpoint already required it).
- `AttestoPhoenix.ClientAuthentication.Result.client_id` falls back to the
  presented credential identifier so the signed-introspection audience (and the
  PAR/token client identity) resolves without a separate `:client_id` callback.
- OpenID Provider Metadata derives `request_parameter_supported` (and only then
  advertises `request_object_signing_alg_values_supported`) from actual
  request-object capability — whether the host can resolve a client's trusted
  JWKS (a `:client_jwks` callback or an installed `:client_store`). An install
  without that capability now advertises `request_parameter_supported: false`
  instead of a JAR support it cannot honour.
- The OAuth 2.0 Authorization Server Metadata document (RFC 8414) now advertises
  the signed-request-object metadata (`require_signed_request_object` and
  `request_object_signing_alg_values_supported`, RFC 9101 §10.5), matching the
  OpenID Provider Metadata document so a FAPI client reading either sees
  identical JAR support. Both documents derive it from the new conn-free
  `AttestoPhoenix.AuthorizationServer.RequestObjectMetadata` (no more split,
  drift-prone assembly).
- `AttestoPhoenix.Config` now rejects at boot a `:request_object_policy` that
  requires a signed request object (e.g. `Policy.fapi_message_signing/0`) when
  no `:client_jwks` capability is configured. Such a config is unsatisfiable
  (every authorization request would be rejected) and would otherwise advertise
  the incoherent pair `request_parameter_supported: false` +
  `require_signed_request_object: true`. Pair the policy with `:client_jwks`
  (or an installed `:client_store`).

## [0.7.2] - 2026-06-03

### Added

- `:request_object_policy` Config key (an `Attesto.RequestObject.Policy`,
  default `%Policy{}` = generic OpenID Connect §6.1). It is enforced at BOTH
  the PAR endpoint and `/authorize`: a signed request object pushed to `/par`
  is verified there (rejected with `invalid_request_object` if it fails the
  policy), and re-verified at `/authorize` (RFC 9101). On success the PAR store
  holds the VERIFIED request-object parameters, never the unsigned body values
  beside them (RFC 9101 §6.3). A non-`%Attesto.RequestObject.Policy{}` value is
  rejected at boot. Set
  `Attesto.RequestObject.Policy.fapi_message_signing()` for the FAPI 2.0
  Message Signing §5.3.1 profile (`nbf`/`exp` required and bounded to 60
  minutes, `typ` = `"oauth-authz-req+jwt"`). Behaviour is unchanged unless a
  host opts in. Requires `attesto ~> 0.6.12`.

## [0.7.1] - 2026-06-03

### Added

- `:client_auth_signing_algs` Config key — the JOSE algorithms accepted for
  `private_key_jwt` client-assertion signatures, threaded into
  `Attesto.ClientAssertion.verify/5` (via its `:accepted_algs` opt) and also
  rendered as `token_endpoint_auth_signing_alg_values_supported` in discovery.
  Defaults to `Attesto.SigningAlg.fapi_algs/0` (PS256, ES256, EdDSA), so
  behaviour is unchanged unless a host overrides it. Verification and the
  advertised metadata now read this one value and cannot drift. Requires
  `attesto ~> 0.6.11`.

## [0.7.0] - 2026-06-03

A structural refactor of the token/PAR controllers into a reusable
authorization-server core, plus a behaviour-module install surface and several
correctness fixes. Pre-1.0 minor bump because it carries breaking changes to
the host-callback contract (see **BREAKING** below).

### Added

- Behaviour-module install for host callbacks. The Config keys `:client_store`,
  `:principal_store`, `:consent_policy`, `:scope_policy`, `:event_sink`,
  `:registration`, and `:claims_provider` each resolve their callbacks from a
  single installed module. Precedence is fixed: an explicit flat callback key
  wins; else the installed behaviour module if it exports the callback; else
  `nil`. The required capabilities (`load_client`, `verify_client_secret`,
  `load_principal`) are validated by *resolution* at boot, so a
  behaviour-module-only install works. Boot-time conformance validation fails
  fast on a typo'd or partial module.
- `AttestoPhoenix.ClaimsProvider` behaviour — the host UserInfo/ID-Token claim
  source (`build_userinfo_claims/3`, `build_id_token_claims/4`).
- `AttestoPhoenix.Callback` — one callback dispatcher (function / `{m,f}` /
  `{m,f,extra}`), replacing ~10 duplicated private `invoke/2` helpers.
- `AttestoPhoenix.ClientAuthentication` and
  `AttestoPhoenix.AuthorizationServer.{SenderConstraint, Token, PAR}` — conn-free
  core modules. The token and PAR controllers are now thin adapters that lift
  conn facts into data, call the core, and render; the core returns data and
  audit events rather than writing the conn or emitting events.

### Changed

- **BREAKING:** the ID-Token extra-claims source is now the separate
  `:build_id_token_claims` callback (`(client, subject, granted_scopes,
  requested_claims -> map)`, and it MUST NOT carry `sub`). Previously the
  4-arity form of `:build_userinfo_claims` doubled as the ID-Token source;
  `:build_userinfo_claims` is now the 3-arity UserInfo source only. Hosts that
  wired a 4-arity `:build_userinfo_claims` must move it to
  `:build_id_token_claims`.
- **BREAKING:** `AttestoPhoenix.ClaimsProvider` no longer declares
  `build_principal/3`; principal building stays solely on
  `AttestoPhoenix.PrincipalStore`. Claim sourcing and principal loading are
  separate concerns.
- Client-assertion `aud` now accepts the issuer **or** the concrete token/PAR
  endpoint URL (RFC 7523 / OIDC Core §9), widened from issuer-only. The endpoint
  URL is derived from trusted Config (issuer + path), never the request Host.
  Still FAPI 2 valid (the issuer remains accepted).
- Client authentication (RFC 6749 §2.3.1): a request-body `client_id` presented
  alongside HTTP Basic is accepted as identification when it matches the Basic
  userid, and rejected as `invalid_request` when it conflicts. Only a second
  *credential* (body `client_secret` or `client_assertion`) is treated as a
  competing authentication method. The token and PAR endpoints now share one
  client-authentication implementation, so they no longer diverge.
- PAR stores the resolved authenticated `client_id`; when no `:client_id`
  callback is configured it leaves the request's presented `client_id` intact
  rather than clobbering it. The opaque-struct `client[:id]`/`client["id"]`
  fallback is removed.

## [0.6.23] - 2026-06-02

### Changed

- Require the client-authentication assertion `aud` to be the issuer identifier
  at both the token and PAR endpoints (FAPI 2). The endpoint URL is no longer
  accepted as an audience. Requires `attesto ~> 0.6.10`.

## [0.6.22] - 2026-06-02

### Changed

- Advertise only the FAPI 2 client-authentication signing algorithms
  (`PS256`, `ES256`, `EdDSA`) in `token_endpoint_auth_signing_alg_values_supported`,
  matching the underlying enforcement in attesto 0.6.9 which rejects RS256
  client assertions. Requires `attesto ~> 0.6.9`.

## [0.6.21] - 2026-06-02

### Fixed

- Return the standard OAuth token endpoint error `invalid_request` when a
  client that requires DPoP omits the proof entirely. Presented-but-invalid
  proofs still return `invalid_dpop_proof`; the omitted-proof case now matches
  FAPI's expected token endpoint error classification.

## [0.6.20] - 2026-06-02

### Added

- Add `:refresh_token_rotation_grace_seconds` to `AttestoPhoenix.Config` and
  pass it through to `Attesto.RefreshToken.rotate/3`. The default is now a
  FAPI retry-compatible 60-second idempotency window for retrying a
  just-rotated refresh token when the client did not receive or persist the
  first rotation response; set `0` for strict immediate reuse revocation.

## [0.6.19] - 2026-06-02

### Fixed

- Bind refresh tokens to the DPoP proof key only for public clients, as
  required by RFC 9449. Confidential clients keep refresh tokens bound to the
  authenticated client, allowing a later refresh request to use a fresh DPoP
  proof key while still minting the returned access token as DPoP-bound to that
  current proof.

## [0.6.18] - 2026-06-02

### Added

- Add `:client_requires_dpop?` as a host callback so deployments can mark a
  client as requiring DPoP-bound token issuance. When such a client calls the
  token endpoint without a DPoP proof, the controller now rejects the request
  with `invalid_dpop_proof` rather than silently issuing an unbound Bearer
  token.

## [0.6.17] - 2026-06-02

### Fixed

- Treat a resolved PAR `request_uri` as the complete authorization request, so
  front-channel parameters outside the pushed request object do not augment the
  request. In particular, a `state` query parameter that was not included in the
  pushed request is no longer echoed in the authorization response.

## [0.6.16] - 2026-06-02

### Fixed

- Allow PAR requests to carry an explicit `dpop_jkt` without also requiring a
  DPoP proof on the PAR request itself. If a PAR DPoP proof is present, an
  explicit `dpop_jkt` must still match that proof; otherwise the stored
  thumbprint is later enforced when the authorization code is redeemed.

## [0.6.15] - 2026-06-02

### Fixed

- Carry the DPoP JWK thumbprint from a pushed authorization request into the
  issued authorization code. A token request that redeems the code with a
  different DPoP proof key is now rejected instead of minting a token bound to
  the later key.

## [0.6.14] - 2026-06-01

### Fixed

- Verify DPoP proofs at the PAR endpoint and bind stored pushed
  authorization requests to the verified proof key. If a PAR request includes
  an explicit `dpop_jkt`, it must match the verified proof JWK thumbprint;
  mismatches now return `invalid_dpop_proof` instead of issuing a
  `request_uri`.

## [0.6.13] - 2026-06-01

### Fixed

- Accept `private_key_jwt` client assertions whose `aud` is the issuer at the
  token endpoint and PAR endpoint, while continuing to accept endpoint-specific
  audiences and reject unrelated audiences. This matches FAPI conformance suite
  client-authentication behavior without relaxing signature, `iss`/`sub`, `jti`,
  or replay checks.

## [0.6.12] - 2026-06-01

### Security

- Reject replayed `private_key_jwt` client assertions at the token endpoint and
  PAR endpoint by recording assertion `jti` values through the configured
  replay check.
- Enforce per-client registered grant types when a host provides
  `:client_grant_types`, preventing a client registered for one grant from
  minting tokens through another.
- Bind PAR `request_uri` authorization requests to the authenticated pushed
  request client and store that authenticated client id, rather than trusting a
  front-channel or body-supplied `client_id`.

### Fixed

- Preserve keystore-provided per-key `alg` metadata in the JWKS endpoint. This
  keeps FAPI deployments that sign ID tokens with `PS256` from advertising the
  same key as `RS256`.
- Add the zero-arity `issue/0` entrypoint to the Ecto DPoP nonce store so
  server-issued DPoP nonces work when the store is configured directly as a
  behaviour module.
- Decode form-encoded client id and secret values in revocation endpoint Basic
  authentication, matching the token endpoint.
- Make the default ETS PAR store tolerate concurrent first-use table creation.

## [0.6.11] - 2026-06-01

### Fixed

- Resolve PAR `request_uri` references non-destructively at the authorization
  endpoint, so host login or consent re-entry can complete without consuming the
  pushed request before authorization-code issuance.

### Changed

- Add a `fetch` callback to `AttestoPhoenix.PARStore` for authorization-endpoint
  resolution. Existing custom stores that only implement `take/1` still work
  through a compatibility fallback, but new stores should implement `fetch/1`.

## [0.6.10] - 2026-06-01

### Fixed

- Treat an explicit `nil` `:par_store` config value as unset when applying the
  default ETS PAR store. This prevents PAR from calling `nil.put/3` when hosts
  enable pushed authorization requests without overriding the development PAR
  store.
- Apply the same nil-aware defaulting to authorization-endpoint PAR resolution.

## [0.6.9] - 2026-06-01

### Added

- Advertise FAPI-required discovery metadata when configured:
  `authorization_response_iss_parameter_supported: true` when RFC 9207
  authorization-response `iss` is enabled, and
  `token_endpoint_auth_signing_alg_values_supported` from Attesto's asymmetric
  signing algorithm set for `private_key_jwt` clients.

## [0.6.8] - 2026-06-01

### Added

- Add host-configurable FAPI-oriented authorization-server controls:
  `:require_pushed_authorization_requests` rejects direct front-channel
  authorization requests unless they arrive through a PAR `request_uri`, and
  `:authorization_response_iss` includes the RFC 9207 `iss` parameter on
  successful and error authorization responses.
- Allow hosts to configure the advertised and accepted token endpoint client
  authentication methods. The token endpoint and PAR endpoint now enforce
  `:token_endpoint_auth_methods_supported` when set, so deployments can expose
  stricter profiles such as `private_key_jwt` only.
- Advertise configured token endpoint authentication methods and PAR-required
  policy in OAuth/OIDC metadata.

## [0.6.7] - 2026-06-01

### Added

- Mount `POST /oauth/authorize` alongside `GET /oauth/authorize`, matching
  OpenID Connect Core's requirement that the Authorization Endpoint support both
  methods.
- Extend the Ecto authorization-code store with successful-consumption markers
  and issued-access-token tracking. When a successfully redeemed authorization
  code is replayed, the token endpoint still returns `invalid_grant` and now
  revokes the access token minted by the original code redemption when the Ecto
  store is configured.

## [0.6.6] - 2026-06-01

### Fixed

- Dynamic client registration now preserves inline `jwks` metadata (RFC 7591
  §2) and hands it to the host `:register_client` callback. Hosts can then
  return those keys through `:client_jwks` for request-object and
  `private_key_jwt` verification.

## [0.6.5] - 2026-06-01

### Fixed

- Return a clean `request_uri_not_supported` authorization response for
  unsupported OIDC `request_uri` references when no PAR store is configured,
  instead of calling a nil PAR store.

## [0.6.4] - 2026-05-31

### Changed

- Replace the direct `jason` dependency with Elixir's built-in `JSON` module.

### Added

- Add a test-only `req_dpop` compatibility check proving that
  `AttestoPhoenix.Plug.Authenticate` accepts RFC 9449 DPoP proofs generated by
  an external Req client plugin. `req_dpop` is not a runtime dependency.
- Document `req_dpop` as an optional Req client companion for tests and
  internal tooling.

## [0.6.3] - 2026-05-31

### Added

- `mix attesto_phoenix.install`, an upgrade-aware Igniter installer. It is
  idempotent and re-runnable: it adds the `AttestoPhoenix.Config` config skeleton
  (issuer, keystore, repo, the Ecto-backed token stores, a chosen
  `:oauth_path_prefix`, and neutral defaults) to the host config, mounts
  `attesto_routes/1` at the chosen prefix into the host router, scaffolds host
  callback modules implementing the recommended behaviours (`ClientStore`,
  `PrincipalStore`, `ScopePolicy`, `ConsentPolicy`, `RegistrationStore`,
  `EventSink`) with documented stub callbacks, and points the host at
  `mix attesto_phoenix.gen.migration` for the Ecto tables. `igniter` is declared
  as an optional dependency, so the runtime package never forces it on consumers;
  the task is available to a host that opts into running it. Options:
  `--oauth-path-prefix` and `--callbacks-module`.

- Configurable OAuth endpoint paths. `AttestoPhoenix.Config` now accepts an
  `:oauth_path_prefix` (default `"/oauth"`, reproducing the historic surface)
  plus explicit per-endpoint overrides (`:authorize_path`, `:token_path`,
  `:par_path`, `:revocation_path`, `:registration_path`, `:userinfo_path`) that
  win when set. Resolver helpers (`token_endpoint_url/1`, `par_endpoint_url/1`,
  `revocation_endpoint_url/1`, `registration_endpoint_url/1`,
  `userinfo_endpoint_url/1`, `authorize_endpoint_url/1`, `jwks_uri/1`,
  `registration_client_uri/2`, and the `*_path/1` helpers) build absolute URLs
  from the issuer and the resolved path. The discovery (RFC 8414),
  OpenID-configuration (OpenID Connect Discovery), and registration (RFC 7591 /
  RFC 7592) controllers read every advertised URL from these resolvers instead
  of hardcoding `/oauth/*`, and `to_attesto_config/2` passes the resolved token
  path to the core builder automatically so the DPoP `htu` follows the mount.
  A host that mounts under `/mcp/oauth` now advertises correct URLs.
- Named host-contract behaviours documenting the full callback contract with
  the governing RFC for each callback, as the recommended production shape:
  `AttestoPhoenix.ClientStore`, `AttestoPhoenix.PrincipalStore`,
  `AttestoPhoenix.ScopePolicy`, `AttestoPhoenix.ConsentPolicy`,
  `AttestoPhoenix.RegistrationStore`, and `AttestoPhoenix.EventSink`. Wiring is
  unchanged: pass an anonymous function, a `{module, function}` pair, or a
  `{module, function, extra_args}` triple per `AttestoPhoenix.Config` key.
- Dynamic registration metadata passthrough (RFC 7591 §2). The registration
  endpoint now validates and carries the known client-identity members
  (`client_name`, `client_uri`, `logo_uri`, `contacts`, `policy_uri`,
  `tos_uri`, and related software/JWKS members) through to `:register_client`
  so consent screens keep the client's identity. Unknown members are dropped
  and never promoted to trusted policy; known members are merged under the
  validated protocol-critical members so they cannot override them.
- Actionable `AttestoPhoenix.Config.new/1` validation errors that name the
  callback/store/path to add for each enabled feature, and absolute-path
  validation for `:oauth_path_prefix` and the per-endpoint overrides.
- Operations guides wired into the published docs: `replay_nonce_production.md`,
  `proxy_canonical_host.md`, `error_envelope.md`, `consumer_migration.md`, and
  `examples.md`.

## [0.6.2]

- Advertise `response_modes_supported: ["query"]` from the RFC 8414 OAuth
  Authorization Server Metadata endpoint, matching the authorization-code
  redirect response mode already used by the Phoenix authorization endpoint.

## [0.6.1]

- Emit `:token_denied` audit/telemetry events for token endpoint failures,
  including OAuth error, status, client/grant/scope context when available, and
  sender-constraint presence.
- Normalize Phoenix callback specs before handing `:cert_der` to core Attesto
  protected-resource verification, so function captures, `{Module, function}`,
  and `{Module, function, extra_args}` all work consistently.

## [0.6.0]

Initial release: a Phoenix/Ecto OAuth 2.0 / OIDC authorization server layer
over [attesto](https://hex.pm/packages/attesto).

### Added

- `AttestoPhoenix.Config`: centralized, validated configuration with neutral
  host callbacks (`:load_client`, `:verify_client_secret`, `:load_principal`,
  `:authorize_scope`, `:on_event`, and others), deriving the `Attesto.Config`
  the protocol layer consumes.
- `AttestoPhoenix.Router`: the `attesto_routes/1` macro mounting the token,
  revocation, discovery, JWKS, and optional dynamic-registration endpoints.
- Controllers for the token endpoint (`authorization_code`, `refresh_token`,
  and `client_credentials` grants), revocation (RFC 7009), discovery
  (RFC 8414), JWKS (RFC 7517), and optional dynamic client registration
  (RFC 7591).
- `AttestoPhoenix.Plug.Authenticate` and `AttestoPhoenix.Plug.RequireScopes`
  protected-resource plugs with DPoP and mTLS sender-constraint enforcement.
- Ecto-backed implementations of the attesto store behaviours: code store,
  refresh store (rotation with reuse detection), DPoP nonce store, and DPoP
  `jti` replay check, plus an optional TTL sweeper.
- `mix attesto_phoenix.gen.migration` to generate the operational tables.
- Pushed Authorization Requests (PAR, RFC 9126), `private_key_jwt` client
  authentication, signed request object validation, token exchange, UserInfo,
  registration management cleanup, and Phoenix resource-server plugs.
