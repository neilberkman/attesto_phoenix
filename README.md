# AttestoPhoenix

[![Hex.pm](https://img.shields.io/hexpm/v/attesto_phoenix)](https://hex.pm/packages/attesto_phoenix)
[![Hexdocs.pm](https://img.shields.io/badge/docs-hexdocs.pm-blue)](https://hexdocs.pm/attesto_phoenix)
[![Elixir CI](https://github.com/XukuLLC/attesto_phoenix/actions/workflows/elixir.yml/badge.svg)](https://github.com/XukuLLC/attesto_phoenix/actions/workflows/elixir.yml)
[![License: MIT](https://img.shields.io/badge/license-MIT-green)](https://github.com/XukuLLC/attesto_phoenix/blob/main/LICENSE)
[![Elixir](https://img.shields.io/badge/elixir-%E2%89%A5%201.18-purple)](https://elixir-lang.org)

An opinionated Phoenix/Ecto OAuth 2.0 / OIDC authorization server on top of
[attesto](https://hex.pm/packages/attesto).

**attesto brings the protocol, attesto_phoenix brings transport + persistence;
you bring principals, keys, and policy.**

`attesto` is a transport-agnostic library of OAuth/OIDC primitives: JWT access
tokens, JWKS/key handling, DPoP, mTLS, PKCE, scope algebra, private-key client
assertions, signed request objects, JARM response JWTs, token introspection
primitives, and the token-lifecycle building blocks.
`attesto_phoenix` wires those primitives into a running server:

- HTTP endpoints (authorization, token, PAR, revocation, discovery, JWKS,
  UserInfo, optional dynamic registration) mounted into your router with one
  macro. The authorization endpoint supports the default query response mode
  and the JARM JWT response modes.
- Protected-resource plugs that verify Bearer JWTs and enforce DPoP / mTLS
  sender-constraint binding.
- Ecto-backed implementations of the attesto store behaviours for authorization
  codes, refresh tokens, and (for clustered deployments) DPoP nonces and proof
  `jti` replay records.

It deliberately does **not** own your client registry, principal store, secret
hashing, scope catalog, or audit log. Those are application policy and are
supplied through a small set of neutral configuration callbacks.

## Positioning vs. attesto core

| Concern | `attesto` (core) | `attesto_phoenix` (this package) |
| --- | --- | --- |
| JWT mint/verify, JWKS, DPoP, mTLS, PKCE, scopes | yes | reuses core |
| `private_key_jwt`, signed request objects, JARM, token exchange primitives | yes | wires into endpoints |
| Grant orchestration primitives | yes | reuses core |
| HTTP endpoints + router macro | no | yes |
| Protected-resource plugs | core plug building blocks | Phoenix-friendly wrappers |
| Ecto-backed token stores | store *behaviours* only | Ecto *implementations* |
| Client registry, principals, keys, audit | no | supplied via callbacks |

If you only need the protocol primitives and want to build your own transport,
depend on `attesto` directly. If you want a batteries-included Phoenix
authorization server, use `attesto_phoenix`.

## Contents

- [Installation](#installation)
- [Quick start](#quick-start)
- [Configuration](#configuration)
- [Mounting the routes](#mounting-the-routes)
- [Protecting resources](#protecting-resources)
- [Database migration](#database-migration)
- [Guides and examples](#guides-and-examples)
- [Development](#development)
- [License](#license)

## Installation

Add `attesto_phoenix` to your dependencies:

```elixir
def deps do
  [
    {:attesto_phoenix, "~> 0.7"}
  ]
end
```

The optional Igniter installer needs `igniter` available while you run it. It is
not a runtime dependency of this package:

```elixir
def deps do
  [
    {:attesto_phoenix, "~> 0.7"},
    {:igniter, "~> 0.5", only: [:dev], runtime: false}
  ]
end
```

## Quick start

For a new Phoenix app, start with the installer. It is idempotent and writes the
host-owned callback modules as stubs rather than guessing your client registry,
principal model, or authorization policy.

```bash
mix deps.get
mix attesto_phoenix.install
mix attesto_phoenix.gen.migration --repo MyApp.Repo
mix ecto.migrate
```

Use `--oauth-path-prefix` when the OAuth endpoints should not live under
`/oauth`:

```bash
mix attesto_phoenix.install --oauth-path-prefix /mcp/oauth
```

After the installer runs, fill in the generated callback modules and configure a
keystore. The rest of this README shows the same pieces explicitly so you can
review what the installer generated or wire them by hand.

## Configuration

All behavior is centralized in `AttestoPhoenix.Config`. Anything that is
inherently application policy is a neutral callback rather than a baked-in
assumption.

```elixir
config :my_app, AttestoPhoenix.Config,
  # --- required ---
  issuer: "https://auth.example.com",
  keystore: MyApp.Keystore,            # implements Attesto.Keystore
  repo: MyApp.Repo,                    # Ecto.Repo for the token stores

  # host policy modules (preferred install surface)
  client_store: MyApp.OAuth.ClientStore,
  principal_store: MyApp.OAuth.PrincipalStore,
  scope_policy: MyApp.OAuth.ScopePolicy,
  consent_policy: MyApp.OAuth.ConsentPolicy,
  claims_provider: MyApp.OIDC.ClaimsProvider,
  event_sink: MyApp.OAuth.Events,

  # --- optional policy ---
  scopes_supported: ["profile", "email", "read:*", "write:*"],
  send_error: &MyApp.OAuthErrors.render/3,
  #   (conn, status, body_map -> conn), optional custom OAuth error envelope
  client_auth_signing_algs: Attesto.SigningAlg.fapi_algs(),
  request_object_policy: Attesto.RequestObject.Policy.generic(),

  # --- optional deployment + features ---
  require_https: true,
  trusted_proxies: ["10.0.0.0/8"],     # honor X-Forwarded-* only from these
  access_token_ttl: 900,
  refresh_token_ttl: 1_209_600,
  authorization_code_ttl: 60,
  dpop_enabled: true,
  dpop_nonce_required: false,
  mtls_enabled: false,                 # if true, also set :cert_der
  registration_enabled: false          # if true, also set registration callbacks
```

Build the validated struct wherever you need it:

```elixir
config = AttestoPhoenix.Config.from_otp_app(:my_app)
```

Required keys are validated at build time; a missing key (or a missing
dependency such as `:cert_der` when mTLS is enabled) raises immediately so
misconfiguration fails fast.

### Host policy modules

The preferred install surface groups host-owned callbacks by concern:

- **client registry** -> `:client_store`
  (`load_client`, `verify_client_secret`, `client_jwks`, client metadata)
- **principals** -> `:principal_store`
  (`load_principal`, `build_principal`, principal kinds)
- **scope policy** -> `:scope_policy`
  (`authorize_scope`, supported scopes)
- **login / consent** -> `:consent_policy`
  (`authenticate_resource_owner`, `consent`)
- **claims** -> `:claims_provider`
  (`build_userinfo_claims/3`, `build_id_token_claims/4`)
- **audit / telemetry** -> `:event_sink` (`on_event`)
- **dynamic registration** -> `:registration` (only with registration)

Flat callback keys such as `:load_client`, `:verify_client_secret`,
`:client_jwks`, `:load_principal`, and `:authorize_scope` are still accepted and
take precedence when present. Use them for small installs or targeted overrides;
use behaviour modules for production wiring.

Other deployment callbacks remain flat because they are endpoint mechanics, not
domain policy: `:send_error`, `:www_authenticate`, `:no_store`, `:cert_der`,
`:require_https`, and `:trusted_proxies`.

## Mounting the routes

Use the router macro to mount the server endpoints under a scope you choose:

```elixir
defmodule MyAppWeb.Router do
  use MyAppWeb, :router
  use AttestoPhoenix.Router

  pipeline :oauth do
    plug :accepts, ["json"]
  end

  scope "/" do
    pipe_through :oauth
    attesto_routes()
  end
end
```

`attesto_routes/1` mounts:

- `GET  /.well-known/oauth-authorization-server` (RFC 8414 metadata)
- `GET  /.well-known/openid-configuration` (OIDC Discovery metadata)
- `GET  /.well-known/jwks.json` (RFC 7517 JWK Set)
- `GET  /oauth/authorize`
- `POST /oauth/token`
- `POST /oauth/par` (RFC 9126)
- `POST /oauth/revoke` (RFC 7009)
- `POST /oauth/register` (RFC 7591, only when `registration_enabled: true`)
- `DELETE /oauth/register/:client_id` (RFC 7592, with registration)
- `GET  /oauth/userinfo`
- `POST /oauth/userinfo`

Discovery and JWKS are public; the token and revocation endpoints authenticate
the client via your `:load_client` / `:verify_client_secret` callbacks.
The token endpoint also accepts `private_key_jwt` when `:client_jwks` is wired,
and supports authorization-code, refresh-token, client-credentials, and OAuth
token-exchange grants. The PAR endpoint accepts the same confidential-client
secret methods plus `private_key_jwt`, then stores the authorization request
behind a one-time `request_uri`.

When `:request_object_policy` is configured, signed request objects are verified
at PAR submission and re-verified at `/authorize`; verified request-object
parameters are authoritative over unsigned request body/query values. Set
`Attesto.RequestObject.Policy.fapi_message_signing/0` to enforce the FAPI 2.0
Message Signing JAR profile.

The authorization endpoint also emits JARM responses when the validated request
uses `response_mode=jwt`, `query.jwt`, `fragment.jwt`, or `form_post.jwt`.
Discovery advertises the supported response modes and the server signing
algorithms used for authorization response JWTs.

## Protecting resources

```elixir
pipeline :api_protected do
  plug AttestoPhoenix.Plug.Authenticate
end

scope "/api", MyAppWeb do
  pipe_through [:api, :api_protected]

  scope "/reports" do
    plug AttestoPhoenix.Plug.RequireScopes, "read:reports"
    get "/", ReportController, :index
  end
end
```

`AttestoPhoenix.Plug.Authenticate` verifies the Bearer JWT, enforces DPoP and
mTLS binding when enabled, resolves the subject via `:load_principal`, emits
neutral `:auth_succeeded` / `:auth_denied` events through `:on_event`, and
assigns:

- `conn.assigns.attesto_claims` - the verified JWT claims
- `conn.assigns.attesto_principal` - the host principal returned by
  `:load_principal`
- `conn.assigns.attesto_context` - a neutral `%{subject, client_id, scope,
  claims, cnf, principal}` map

`AttestoPhoenix.Plug.RequireScopes` enforces route-level scope authorization
using `Attesto.Scope` grant-form algebra. It accepts either a single scope
string or a list of required scopes.

For first-party web flows, keep cookie semantics in your app and pass a generic
credential extractor to the plug:

```elixir
plug AttestoPhoenix.Plug.Authenticate,
  credential_from_conn: &MyAppWeb.Auth.access_token_from_cookie/1
```

The extractor returns `{:ok, :bearer, token}`, `{:ok, :dpop, token}`, or
`:missing`. Attesto still verifies the token through the same JWT/DPoP/mTLS
path; the cookie format and CSRF policy remain host concerns.

### Req DPoP clients

`attesto_phoenix` is the server-side Phoenix layer. If you also use
[`Req`](https://hex.pm/packages/req) for OAuth clients in tests or internal
tooling, [`req_dpop`](https://hex.pm/packages/req_dpop) generates RFC 9449 DPoP
proofs that interoperate with `AttestoPhoenix.Plug.Authenticate`. It is not a
runtime dependency of this package; `attesto_phoenix` uses it only in tests as
an external client compatibility check.

## Database migration

The library owns four operational tables backing the attesto store behaviours:
`authorizations`, `refresh_tokens`, `dpop_nonces`, and `dpop_replays`. It does
**not** own a clients table (that is yours, behind `:load_client`). The default
PAR store is single-node ETS; clustered deployments should provide a
`AttestoPhoenix.PARStore` backed by shared storage.

Generate the migration into your app:

```bash
mix attesto_phoenix.gen.migration --repo MyApp.Repo
```

Then run it:

```bash
mix ecto.migrate
```

Single-node deployments may skip the Ecto nonce/replay tables and wire
attesto's in-memory ETS implementations via `:nonce_store` and `:replay_check`;
the Ecto variants exist for clustered correctness.

## Guides and examples

- [Example configurations](guides/examples.md) - confidential and public-client
  configuration sketches.
- [Consumer migration](guides/consumer_migration.md) - moving from a custom or
  legacy OAuth route surface while keeping historical migrations compiling.
- [Proxy and canonical host](guides/proxy_canonical_host.md) - issuer,
  forwarded header, and HTTPS behavior behind proxies/CDNs.
- [Replay and nonce production notes](guides/replay_nonce_production.md) -
  shared-store requirements for clustered DPoP replay and nonce handling.
- [Error envelope hooks](guides/error_envelope.md) - using `:send_error` and
  related callbacks to keep a host application's API error format.
- [Livebook demo](notebooks/attesto_phoenix_demo.livemd) - a self-contained
  Phoenix/Bandit resource-server demo using `Req` + `req_dpop`.

## Development

```bash
mix deps.get
mix precommit
mix test --include ecto   # requires Postgres
```

## License

MIT. See [LICENSE](LICENSE).
