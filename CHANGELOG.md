# Changelog

All notable changes to this project are documented here. The format is
based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and this
project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

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
