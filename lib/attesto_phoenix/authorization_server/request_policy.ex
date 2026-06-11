defmodule AttestoPhoenix.AuthorizationServer.RequestPolicy do
  @moduledoc """
  Conn-free resolution of the per-request authorization-request validation
  policy shared by the authorization endpoint and the PAR endpoint.

  Both endpoints validate the same authorization request the same way (RFC 9126
  §2.1: "validate the pushed request as it would an authorization request sent
  to the authorization endpoint"), so the policy inputs `Attesto.AuthorizationRequest.validate/2`
  needs - the client's registered redirect URIs (RFC 6749 §3.1.2.3), whether
  PKCE is required (RFC 9700 §2.1.1), and whether `nonce` is required (OIDC Core
  §3.1.2.1) - are resolved here once, from `%AttestoPhoenix.Config{}` and the
  opaque host client, rather than duplicated per endpoint. This module reads
  only data: it touches no `conn` and carries no policy of its own beyond the
  fail-closed defaults documented on each function.
  """

  alias Attesto.AuthorizationRequest
  alias AttestoPhoenix.{Callback, Config}
  alias AttestoPhoenix.AuthorizationServer.SenderConstraint

  @doc """
  Validate `params` as an authorization request for `client`, resolving the
  redirect-URI/PKCE/nonce policy from `config` and delegating to
  `Attesto.AuthorizationRequest.validate/2`.

  This is the shared entry point both the authorization endpoint and the PAR
  endpoint use so a request is validated identically wherever it arrives
  (RFC 9126 §2.1). Pass `extra_opts` to thread request-object verification
  inputs (`:request_object_jwks`, `:request_object_audience`,
  `:request_object_policy`) when the `params` still carry an unverified signed
  `request` object; omit them when the object has already been verified and
  merged.
  """
  @spec validate(Config.t(), term(), map(), keyword()) ::
          {:ok, AuthorizationRequest.t()} | {:error, AuthorizationRequest.error()}
  def validate(config, client, params, extra_opts \\ []) do
    opts =
      [
        registered_redirect_uris: registered_redirect_uris(config, client),
        require_pkce: require_pkce?(config, client),
        require_nonce: require_nonce?(config)
      ] ++ extra_opts

    AuthorizationRequest.validate(params, opts)
  end

  @doc """
  The client's registered redirect URIs (RFC 6749 §3.1.2.3), resolved through
  the host's `:client_redirect_uris` callback. An absent callback or a
  non-list return resolves to `[]`, which rejects every request with an
  unregistered redirect URI (fail closed).
  """
  @spec registered_redirect_uris(Config.t(), term()) :: [String.t()]
  def registered_redirect_uris(config, client) do
    case Callback.invoke(Config.client_redirect_uris_fun(config), [client], []) do
      uris when is_list(uris) -> uris
      _ -> []
    end
  end

  @doc """
  Whether PKCE is required for this client (RFC 7636 §4.3 / RFC 9700 §2.1.1).

  A public client MUST use PKCE, so `client_public?/2` forces it regardless of
  config. A sender-constrained client (DPoP or mTLS) is a FAPI 2.0 client, and
  FAPI 2.0 Security Profile §5.3.1.2 / RFC 9700 §2.1.1 require PKCE for it even
  though it authenticates confidentially - so `client_requires_dpop?/2` and
  `client_requires_mtls?/2` force it too. For any other confidential client the
  global `:require_pkce` flag applies (default `true`). Fail closed: absent the
  host's deliberate opt-out, PKCE is required.
  """
  @spec require_pkce?(Config.t(), term()) :: boolean()
  def require_pkce?(config, client) do
    client_public?(config, client) or
      SenderConstraint.client_requires_dpop?(config, client) or
      SenderConstraint.client_requires_mtls?(config, client) or
      Callback.config_flag(config, :require_pkce)
  end

  @doc """
  Classify the client as public via the host's `:client_public?` callback.

  Absent the callback, fail closed by treating the client as public, so PKCE
  stays required (a confidential exemption demands a deliberate host
  classification).
  """
  @spec client_public?(Config.t(), term()) :: boolean()
  def client_public?(config, client) do
    case Config.client_public_fun(config) do
      nil -> true
      callback -> Callback.invoke(callback, [client]) == true
    end
  end

  @doc """
  The host's OP nonce policy flag (OIDC Core §3.1.2.1).

  Returns the raw `:require_nonce` configuration. The OIDC openid-scope gate is
  NOT applied here: it must run on the EFFECTIVE request (after any signed
  `request` object is merged), which only `Attesto.AuthorizationRequest.validate/2`
  sees. Applying the gate on the raw outer params here would let a direct JAR
  carrying `scope=openid` only inside the signed object bypass the requirement.
  """
  @spec require_nonce?(Config.t()) :: boolean()
  def require_nonce?(config) do
    Callback.config_flag(config, :require_nonce)
  end
end
