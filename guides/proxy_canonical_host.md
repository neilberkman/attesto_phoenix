# Issuer, resource, and redirect URL correctness behind a proxy

Behind Fly, NGINX, a CDN, or any reverse proxy, the request the application
sees is not the request the client sent: the scheme is often plain HTTP after
TLS termination, and the `Host` header may be an internal name. OAuth and OIDC
URL correctness depends on the **canonical, client-visible** host and scheme,
not on whatever reached the application socket.

## Why this matters

  * The **issuer** (`iss`) is minted into every token and published in the
    discovery documents (RFC 8414 §2). It MUST be the canonical `https` URL
    clients use. Deriving it from a live request behind a proxy can leak an
    internal host or an `http` scheme.

  * The **DPoP `htu`** (RFC 9449 §4.3) is the URL the client signed. If the
    server computes `htu` from a proxied request it may not match what the
    client signed, and valid proofs are rejected.

  * **Redirect URIs** are exact-matched (RFC 6749 §3.1.2.3). A host/scheme
    mismatch breaks the match.

## Configure the canonical identity, not the request

`AttestoPhoenix.Config`:

  * `:issuer` - set this to the fixed canonical `https` issuer URL. The library
    derives the discovery issuer and the advertised endpoint URLs from it (via
    the `:oauth_path_prefix` / per-endpoint path resolvers), so it never needs
    to reconstruct the host from a request. This is stable behind any TLS
    terminator.

  * `:trusted_proxies` - the list of trusted proxy CIDRs/IPs that controls
    whether `X-Forwarded-*` headers are honored. Default `[]` (no forwarded
    trust): nothing is taken from a `Forwarded` / `X-Forwarded-*` header unless
    the immediate peer is in this list. Set it to your proxy's address range so
    forwarded scheme/host are trusted only from your proxy and never from an
    arbitrary client.

  * `:require_https` - keep this `true` (the default) in production so the
    endpoints enforce HTTPS.

  * `:htu` - `(conn -> canonical_url_string)`. When the default derivation from
    `:trusted_proxies` is not enough (an unusual proxy chain, a host rewrite),
    override exactly how the DPoP `htu` is computed. Return the canonical URL
    the client would have signed.

## Checklist

  - [ ] `:issuer` is the fixed canonical `https` URL (no internal host).
  - [ ] `:trusted_proxies` lists your proxy's address range, nothing wider.
  - [ ] `:require_https` is `true`.
  - [ ] Advertised endpoint paths match the mount via `:oauth_path_prefix` (see
        the consumer migration guide).
  - [ ] If proofs are rejected behind the proxy, set `:htu` to return the
        canonical signed URL.
