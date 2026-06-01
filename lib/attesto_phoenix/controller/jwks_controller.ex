defmodule AttestoPhoenix.Controller.JWKSController do
  @moduledoc """
  `GET /.well-known/jwks.json` - the JSON Web Key Set (RFC 7517 §5).

  Publishes the public halves of the issuer's signing keys as a JWK Set so a
  resource server (or any client) can verify issued JWTs without a shared
  secret. A verifier fetches this set, then selects the key whose `kid` matches
  the token's JWS header (RFC 7515 §4.1.4). This is the document the
  authorization-server metadata's `jwks_uri` points at (RFC 8414 §2).

  The set carries every verification key, so it covers a rotation window:
  tokens minted under the outgoing key still verify while the incoming key is
  also published. Only public key material is emitted; private components never
  appear (RFC 7517 §1).

  This endpoint is unauthenticated public metadata, and its response is the same
  for every caller, so it is marked publicly cacheable (RFC 9111 §5.2.2). The
  JWK Set construction is delegated to `Attesto.JWKS`; this controller owns only
  the HTTP binding and the cache policy.

  ## Configuration

  Built on `AttestoPhoenix.Config`. The set is derived entirely from
  configuration; this controller holds no policy of its own:

    * `:keystore` - the `Attesto.Keystore` whose `verification_pems/0` are
      published. The host owns where the keys come from.

  The configured `AttestoPhoenix.Config` is read from
  `conn.private[:attesto_phoenix_config]`, placed there by the host's router
  pipeline.
  """

  use Phoenix.Controller, formats: [:json]

  import Plug.Conn

  alias Attesto.JWKS
  alias AttestoPhoenix.Config

  # RFC 7517 §8.5.1 registers `application/jwk-set+json` for a JWK Set document.
  @jwk_set_media_type "application/jwk-set+json"

  # RFC 9111 §5.2.2.1: public cache lifetime, seconds. A verifier may hold the
  # set for this long before re-fetching; kept below a typical rotation window
  # so a newly published key is picked up promptly.
  @cache_max_age_seconds 600

  # The configured AttestoPhoenix.Config is threaded through the connection's
  # private storage by the host pipeline.
  @config_key :attesto_phoenix_config

  @doc """
  Handle `GET /.well-known/jwks.json` (RFC 7517 §5).

  Builds the public JWK Set from the configured keystore's verification keys and
  renders it as a publicly cacheable JSON document.
  """
  @spec show(Plug.Conn.t(), map()) :: Plug.Conn.t()
  def show(conn, _params) do
    config = fetch_config!(conn)

    # Keep the published key metadata aligned with the token signing path:
    # `from_config/1` preserves the keystore's per-key `alg` metadata.
    jwk_set = JWKS.from_config(attesto_config(config))

    conn
    |> put_public_cache()
    |> put_resp_content_type(@jwk_set_media_type)
    |> json(jwk_set)
  end

  # RFC 9111 §5.2.2.5 / §5.2.2.1: the set is identical for every caller and may
  # be shared by intermediary caches for `max-age` seconds.
  defp put_public_cache(conn) do
    put_resp_header(conn, "cache-control", "public, max-age=#{@cache_max_age_seconds}")
  end

  defp fetch_config!(conn) do
    case conn.private do
      %{@config_key => %Config{} = config} ->
        config

      _missing ->
        raise ArgumentError,
              "AttestoPhoenix.Controller.JWKSController: no %AttestoPhoenix.Config{} " <>
                "in conn.private[#{inspect(@config_key)}]; wire the host pipeline that assigns it"
    end
  end

  defp attesto_config(config) do
    Config.to_attesto_config(config, principal_kinds_extra(config))
  end

  defp principal_kinds_extra(%Config{principal_kinds: kinds})
       when is_list(kinds) and kinds != [] do
    [principal_kinds: kinds]
  end

  defp principal_kinds_extra(%Config{principal_kinds: callback}) when not is_nil(callback) do
    case invoke(callback, []) do
      kinds when is_list(kinds) and kinds != [] -> [principal_kinds: kinds]
      _other -> []
    end
  end

  defp principal_kinds_extra(_config), do: []

  defp invoke(fun, args) when is_function(fun), do: apply(fun, args)

  defp invoke({module, fun}, args) when is_atom(module) and is_atom(fun),
    do: apply(module, fun, args)

  defp invoke({module, fun, extra}, args) when is_atom(module) and is_atom(fun),
    do: apply(module, fun, args ++ extra)
end
