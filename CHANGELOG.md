# Changelog

All notable changes to this project are documented here. The format is
based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and this
project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

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
