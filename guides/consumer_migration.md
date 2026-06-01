# Migrating to Attesto from Boruta or a custom OAuth provider

A checklist for replacing an existing OAuth/OIDC provider (Boruta, a
hand-rolled provider, or an `ex_oauth2_provider`-style library) with the
`attesto` / `attesto_phoenix` stack.

## 1. Mount the routes

Add the router macro and mount the endpoints. The well-known documents are
always at the host root (RFC 8615); the OAuth endpoints live under your chosen
prefix:

```elixir
use AttestoPhoenix.Router

scope "/" do
  attesto_routes(registration: true)
end
```

## 2. Configure the host callbacks

Build an `AttestoPhoenix.Config`. The recommended production shape is the named
behaviours - `AttestoPhoenix.ClientStore`, `AttestoPhoenix.PrincipalStore`,
`AttestoPhoenix.ScopePolicy`, `AttestoPhoenix.ConsentPolicy`,
`AttestoPhoenix.RegistrationStore`, `AttestoPhoenix.EventSink` - wired into the
matching Config keys. See `guides/examples.md` for minimal configs.

## 3. Map your existing client store

Your old provider already has a client table. Point `:load_client`,
`:verify_client_secret`, `:client_id`, `:client_redirect_uris`, and
`:client_public?` at it. You do not need to migrate the rows into a new schema;
you need callbacks that read your existing rows.

## 4. Remove the runtime provider, keep historical migrations

This is the step that trips people up. When you delete the old provider
dependency:

  * **Remove the runtime code** - the old provider's plugs, routes, and any
    `use OldProvider.X` lines.

  * **Keep the historical migrations working.** Your repo's migration history
    still references the old provider's tables and, sometimes, helper modules
    the old provider exposed at migration time. If you delete the dependency
    outright, `mix ecto.migrate` on a fresh database fails when it reaches
    those old migrations.

    Options that keep history runnable:

      - Leave the old migrations as-is and keep a thin compatibility shim for
        any module they reference, OR
      - Squash the historical migrations into a single baseline that no longer
        references the removed dependency (only safe once every environment is
        past those migrations), OR
      - Replace the dependency-specific calls inside the old migration files
        with the raw SQL they generated, so the migration no longer needs the
        dependency at all.

    Pick one before removing the dep from `mix.exs`. Do not remove the dep and
    discover the break on the next clean deploy.

## 5. Scope and token claims

Move scope policy into `:authorize_scope` (or `AttestoPhoenix.ScopePolicy`) and
the principal/claim shaping into `:build_principal` /
`:build_userinfo_claims`. Attesto owns the JWT/JWKS/DPoP mechanics; your host
owns who the subject is and which scopes a client may hold.

## 6. Verify discovery

Fetch `/.well-known/oauth-authorization-server` and
`/.well-known/openid-configuration` and confirm every advertised endpoint URL
points at a route you actually mounted.

## Note for a `/mcp/oauth` (or any non-`/oauth`) consumer

If you mount the OAuth endpoints somewhere other than `/oauth` - for example
under `/mcp/oauth` to avoid colliding with a legacy provider at `/oauth` - set
the mount once:

```elixir
oauth_path_prefix: "/mcp/oauth"
```

With that set, the discovery documents and the RFC 7591
`registration_client_uri` advertise the `/mcp/oauth/*` paths automatically, and
`AttestoPhoenix.Config.to_attesto_config/2` passes the resolved token path into
the core config for you. A consumer that previously hand-passed
`token_endpoint_path: "/mcp/oauth/token"` into `to_attesto_config/2` can drop
that argument once `:oauth_path_prefix` is set, since the resolver now derives
it. (Explicit per-endpoint overrides such as `:token_path` still win if you
need a path that does not follow the prefix.)
