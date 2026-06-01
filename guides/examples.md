# Example configurations

Two minimal `AttestoPhoenix.Config` setups. Both assume the host has wired the
router macro and a pipeline that installs the config on the connection.

## Confidential client (server-side app, client secret)

A confidential client authenticates with a secret at the token endpoint
(RFC 6749 §2.3.1). This config issues access and refresh tokens for the
authorization-code grant and serves discovery.

```elixir
AttestoPhoenix.Config.new(
  issuer: "https://auth.example",
  keystore: MyApp.Keystore,
  repo: MyApp.Repo,

  # Client registry (AttestoPhoenix.ClientStore).
  load_client: &MyApp.AuthZ.load_client/1,
  verify_client_secret: &MyApp.AuthZ.verify_client_secret/2,
  client_id: &MyApp.AuthZ.client_id/1,
  client_redirect_uris: &MyApp.AuthZ.client_redirect_uris/1,
  client_public?: fn _client -> false end,

  # Subject (AttestoPhoenix.PrincipalStore).
  load_principal: &MyApp.AuthZ.load_principal/1,
  build_principal: &MyApp.AuthZ.build_principal/3,

  # Login + consent (AttestoPhoenix.ConsentPolicy).
  authenticate_resource_owner: &MyApp.AuthZ.authenticate_resource_owner/3,
  consent: &MyApp.AuthZ.consent/3,

  # Scope policy (AttestoPhoenix.ScopePolicy); omit to default to
  # "subset of :scopes_supported".
  authorize_scope: &MyApp.AuthZ.authorize_scope/2,
  scopes_supported: ["openid", "profile", "email"],

  # Shared production token stores.
  code_store: AttestoPhoenix.Store.EctoCodeStore,
  refresh_store: AttestoPhoenix.Store.EctoRefreshStore,
  replay_check: &AttestoPhoenix.Store.EctoReplayCheck.check_and_record/2,
  nonce_store: AttestoPhoenix.Store.EctoNonceStore,
  sweep_interval_ms: 60_000
)
```

## Public PKCE client (native / SPA, no secret)

A public client holds no secret and proves possession of the authorization
code with PKCE (RFC 7636). It authenticates at the token endpoint with
`none`.

```elixir
AttestoPhoenix.Config.new(
  issuer: "https://auth.example",
  keystore: MyApp.Keystore,
  repo: MyApp.Repo,

  load_client: &MyApp.AuthZ.load_client/1,
  # A public client presents no secret; verification always fails closed if a
  # secret is somehow presented.
  verify_client_secret: fn _client, _secret -> false end,
  client_id: &MyApp.AuthZ.client_id/1,
  client_redirect_uris: &MyApp.AuthZ.client_redirect_uris/1,
  client_public?: fn _client -> true end,

  load_principal: &MyApp.AuthZ.load_principal/1,
  build_principal: &MyApp.AuthZ.build_principal/3,
  authenticate_resource_owner: &MyApp.AuthZ.authenticate_resource_owner/3,

  # require_pkce defaults to true; PKCE is enforced for the code grant.
  scopes_supported: ["openid", "profile"],

  code_store: AttestoPhoenix.Store.EctoCodeStore,
  refresh_store: AttestoPhoenix.Store.EctoRefreshStore,
  replay_check: &AttestoPhoenix.Store.EctoReplayCheck.check_and_record/2,
  nonce_store: AttestoPhoenix.Store.EctoNonceStore,
  sweep_interval_ms: 60_000
)
```

## Mounting somewhere other than `/oauth`

Both configs above advertise the historic `/oauth/*` endpoints. To advertise a
different mount (for example `/mcp/oauth`), add a single key:

```elixir
oauth_path_prefix: "/mcp/oauth"
```

See `guides/consumer_migration.md` for the details.
