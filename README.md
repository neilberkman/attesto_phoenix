# AttestoPhoenix

An opinionated Phoenix/Ecto OAuth 2.0 / OIDC authorization server on top of
[attesto](https://hex.pm/packages/attesto).

**attesto brings the protocol, attesto_phoenix brings transport + persistence;
you bring principals, keys, and policy.**

`attesto` is a transport-agnostic library of OAuth/OIDC primitives: JWT access
tokens, JWKS/key handling, DPoP, mTLS, PKCE, scope algebra, private-key client
assertions, signed request objects, and the token-lifecycle building blocks.
`attesto_phoenix` wires those primitives into a running server:

- HTTP endpoints (authorization, token, PAR, revocation, discovery, JWKS,
  UserInfo, optional dynamic registration) mounted into your router with one
  macro.
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
| `private_key_jwt`, signed request objects, token exchange primitives | yes | wires into endpoints |
| Grant orchestration primitives | yes | reuses core |
| HTTP endpoints + router macro | no | yes |
| Protected-resource plugs | core plug building blocks | Phoenix-friendly wrappers |
| Ecto-backed token stores | store *behaviours* only | Ecto *implementations* |
| Client registry, principals, keys, audit | no | supplied via callbacks |

If you only need the protocol primitives and want to build your own transport,
depend on `attesto` directly. If you want a batteries-mostly-included Phoenix
server, use `attesto_phoenix`.

## Installation

Add `attesto_phoenix` to your dependencies:

```elixir
def deps do
  [
    {:attesto_phoenix, "~> 0.6"}
  ]
end
```

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

  # client lookup + secret verification (you own the client registry)
  load_client: &MyApp.Clients.fetch/1,
  #   (client_id -> {:ok, client} | {:error, :not_found} | {:error, :revoked})
  verify_client_secret: &MyApp.Clients.verify_secret/2,
  #   (client, presented_secret -> boolean) -- constant time
  client_jwks: &MyApp.Clients.jwks/1,
  #   (client -> {:ok, jwks} | jwks), for private_key_jwt and request objects

  # subject/principal resolution for protected-resource auth
  load_principal: &MyApp.Principals.fetch/1,
  #   (subject_id -> {:ok, principal} | {:error, :not_found})

  # --- optional policy ---
  scopes_supported: ["profile", "email", "read:*", "write:*"],
  authorize_scope: &MyApp.Scopes.authorize/2,
  #   (client, requested_scope -> {:ok, granted} | {:error, :invalid_scope})
  on_event: &MyApp.Audit.record/1,     # (%AttestoPhoenix.Event{} -> any)
  send_error: &MyApp.OAuthErrors.render/3,
  #   (conn, status, body_map -> conn), optional custom OAuth error envelope

  # --- optional deployment + features ---
  require_https: true,
  trusted_proxies: ["10.0.0.0/8"],     # honor X-Forwarded-* only from these
  access_token_ttl: 900,
  refresh_token_ttl: 1_209_600,
  authorization_code_ttl: 60,
  dpop_enabled: true,
  dpop_nonce_required: false,
  mtls_enabled: false,                 # if true, also set :cert_der
  registration_enabled: false          # if true, also set :register_client
```

Build the validated struct wherever you need it:

```elixir
config = AttestoPhoenix.Config.from_otp_app(:my_app)
```

Required keys are validated at build time; a missing key (or a missing
dependency such as `:cert_der` when mTLS is enabled) raises immediately so
misconfiguration fails fast.

### The callbacks, in OAuth terms

- **client lookup** -> `:load_client`
- **client secret verification** -> `:verify_client_secret`
- **client public keys** -> `:client_jwks`
- **subject/principal resolution** -> `:load_principal`
- **scope catalog / narrowing** -> `:scopes_supported` and/or `:authorize_scope`
- **audit / telemetry** -> `:on_event` (optional, no-op by default)
- **error envelope / transport rendering** -> `:send_error`,
  `:www_authenticate`, `:no_store` (optional)
- **dynamic client persistence** -> `:register_client` (only with registration)
- **mTLS certificate extraction** -> `:cert_der` (only with mTLS)
- **HTTPS / proxy trust** -> `:require_https` + `:trusted_proxies`

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

## License

MIT. See [LICENSE](LICENSE).
