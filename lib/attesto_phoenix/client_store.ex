defmodule AttestoPhoenix.ClientStore do
  @moduledoc """
  The host-owned OAuth client registry contract (RFC 6749 §2 / §3.1.2).

  The library never owns the client registry: it resolves a client from its
  identifier, verifies its secret in constant time, and reads the per-client
  attributes the authorization, token, PAR, and revocation endpoints need. A
  host implements this behaviour and wires each callback into
  `AttestoPhoenix.Config` as an anonymous function, a `{module, function}`
  pair, or a `{module, function, extra_args}` triple. This module is the
  contract those Config keys install; it is the recommended production shape
  but the wiring is unchanged from passing the callbacks individually.

  Each `@callback` corresponds to the identically named `AttestoPhoenix.Config`
  key:

    * `load_client/1` (`:load_client`, required)
    * `verify_client_secret/2` (`:verify_client_secret`, required)
    * `client_id/1` (`:client_id`)
    * `client_jwks/1` (`:client_jwks`)
    * `client_redirect_uris/1` (`:client_redirect_uris`)
    * `client_public?/1` (`:client_public?`)
    * `client_requires_mtls?/1` (`:client_requires_mtls?`)
    * `client_requires_dpop?/1` (`:client_requires_dpop?`)
    * `client_grant_types/1` (`:client_grant_types`)

  The `client` term is opaque to the library: whatever
  `load_client/1` returns is threaded back into the other callbacks unchanged.
  """

  @typedoc "The host's opaque client representation (e.g. an Ecto struct)."
  @type client :: term()

  @doc """
  Resolve an OAuth client by its identifier (RFC 6749 §2.2).

  Returns `{:ok, client}` for a usable client, `{:error, :not_found}` when no
  such client exists, or `{:error, :revoked}` when the client is known but has
  been revoked. The host owns the registry and the revocation policy.
  """
  @callback load_client(client_id :: String.t()) ::
              {:ok, client()} | {:error, :not_found} | {:error, :revoked}

  @doc """
  Constant-time verification of a presented client secret (RFC 6749 §2.3.1).

  Returns `true` iff `presented_secret` matches the client's stored secret.
  The host owns secret hashing; use `Attesto.SecureCompare` to avoid timing
  leaks.
  """
  @callback verify_client_secret(client(), presented_secret :: String.t()) :: boolean()

  @doc """
  The client's OAuth identifier (RFC 6749 §2.2), extracted from the host's
  client representation.
  """
  @callback client_id(client()) :: String.t()

  @doc """
  The client's trusted public JWK Set for `private_key_jwt` client
  authentication (RFC 7523 / OpenID Connect Core §9). Returns `nil` for a
  client that does not authenticate with a signed assertion.
  """
  @callback client_jwks(client()) :: map() | nil

  @doc """
  The client's registered redirect URIs (RFC 6749 §3.1.2.2). The authorization
  endpoint exact-matches the request `redirect_uri` against this set
  (RFC 6749 §3.1.2.3); a client exposing none rejects every authorization
  request (fail closed).
  """
  @callback client_redirect_uris(client()) :: [String.t()]

  @doc """
  Whether the client may authenticate without a secret and rely on PKCE
  (RFC 6749 §2.1 / RFC 7636).
  """
  @callback client_public?(client()) :: boolean()

  @doc """
  Whether the client requires mTLS-bound token issuance (RFC 8705).
  """
  @callback client_requires_mtls?(client()) :: boolean()

  @doc """
  Whether the client requires DPoP-bound token issuance (RFC 9449).
  """
  @callback client_requires_dpop?(client()) :: boolean()

  @doc """
  The grant types registered for this client (RFC 7591 §2).

  When the host exposes this callback, the token endpoint rejects a requested
  `grant_type` not in the returned list before dispatching to the grant
  implementation. Return `nil` only when the host has no per-client grant
  registry and wants the package's legacy configured-supported-grants behavior.
  """
  @callback client_grant_types(client()) :: [String.t()] | nil

  @optional_callbacks client_id: 1,
                      client_jwks: 1,
                      client_redirect_uris: 1,
                      client_public?: 1,
                      client_requires_mtls?: 1,
                      client_requires_dpop?: 1,
                      client_grant_types: 1
end
