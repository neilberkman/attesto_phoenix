# Fitting OAuth errors into an existing JSON error envelope

The authorization-server controllers and the protected-resource plugs render
errors through `AttestoPhoenix.OAuthError`, which owns the RFC-mandated status
codes, `WWW-Authenticate` challenges, and cache-control semantics. An app that
already has its own JSON error shape can reshape the body **without losing**
those RFC guarantees, using three optional transport hooks in
`AttestoPhoenix.Config`.

These hooks change only the transport rendering. The error code, the HTTP
status, the challenge header, and the no-store semantics are still owned by the
library.

## `:send_error` - reshape the body

`(conn, status, body_map -> conn)`. Called to serialize an OAuth/OIDC error
into the host's envelope. Preserve `status` and the meaning of `body_map`
(which carries `error` and, usually, `error_description` per RFC 6749 §5.2).

```elixir
send_error: fn conn, status, body_map ->
  conn
  |> Plug.Conn.put_status(status)
  |> Phoenix.Controller.json(%{
    "ok" => false,
    # Keep the RFC fields so spec-compliant clients still parse the error.
    "error" => %{
      "code" => body_map["error"] || body_map[:error],
      "message" => body_map["error_description"] || body_map[:error_description]
    }
  })
end
```

Do not drop the RFC status: a token error is `400`/`401` for a reason
(RFC 6749 §5.2), and clients branch on it.

## `:www_authenticate` - write the challenge header

`(conn, challenge_string -> conn)`. RFC 6749 §5.2 and RFC 6750 §3 require a
matching `WWW-Authenticate` header on `401`s. The library computes the exact
challenge string (scheme + `error`, `error_description`, `scope`, and DPoP
`algs` auth-params); this hook only writes it.

```elixir
www_authenticate: fn conn, challenge ->
  Plug.Conn.put_resp_header(conn, "www-authenticate", challenge)
end
```

Write the challenge verbatim. Rewriting it risks dropping an auth-param a
client needs (for example the DPoP `algs`).

## `:no_store` - suppress caching

`(conn -> conn)`. A token/credential response must never be cached
(RFC 6749 §5.1). This hook applies the host's no-store headers.

```elixir
no_store: fn conn ->
  Plug.Conn.put_resp_header(conn, "cache-control", "no-store")
end
```

## What stays the library's job

  * Choosing the `error` code and HTTP status per the governing RFC.
  * Deciding *when* a `WWW-Authenticate` challenge or no-store header is
    required.
  * Computing the challenge string contents.

The hooks let you control the bytes; they do not let you change the protocol
semantics.
