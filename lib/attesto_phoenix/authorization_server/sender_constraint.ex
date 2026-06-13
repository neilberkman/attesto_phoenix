defmodule AttestoPhoenix.AuthorizationServer.SenderConstraint do
  @moduledoc """
  Sender-constraint resolution for the token endpoint (RFC 9449 / RFC 8705),
  as conn-free core.

  This is the single place that turns the sender-constraint facts of a token
  request - a presented DPoP proof (RFC 9449), a presented client certificate
  (RFC 8705), and the canonical request URL/method the proof is bound to
  (RFC 9449 §4.2 / §4.3) - together with the configured policy and the client's
  binding requirements into either a resolved binding or an
  `AttestoPhoenix.OAuthError`. The controller parses these facts off the
  `Plug.Conn` (via `AttestoPhoenix.RequestContext` and the `DPoP` request
  header) and passes them as a plain map; this module reads only data, never
  touches a conn, and never emits an event.

  ## Input

  `resolve/3` takes the validated `%AttestoPhoenix.Config{}`, the resolved
  client, and an `input` map the controller builds from the request:

    * `:dpop_proof` - the first `DPoP` request-header value (RFC 9449 §4.1), or
      `nil` when the request carries no proof.
    * `:mtls_cert_der` - the peer certificate DER (RFC 8705 §3), or `nil` when
      no client certificate was presented.
    * `:http_uri` - the canonical request URL (`htu`) the proof is bound to
      (RFC 9449 §4.3).
    * `:http_method` - the HTTP method (`htm`) the proof is bound to
      (RFC 9449 §4.2); the token endpoint is reached by POST.

  ## Return value

  `{:ok, binding, token_type}` where `binding` is one of `{:dpop, jkt}`,
  `{:mtls, thumbprint}`, or `:none`, and `token_type` is the RFC 9449 §7.1 /
  RFC 6750 presentation type (`"DPoP"` for a DPoP binding, `"Bearer"`
  otherwise). On failure, `{:error, %AttestoPhoenix.OAuthError{}}`.

  ## Precedence and fail-closed policy

  DPoP takes precedence when a proof is presented (RFC 9449 §5); otherwise an
  mTLS certificate binds the token to its thumbprint; otherwise the token is an
  unbound Bearer - but only if the client does not *require* a sender
  constraint.

  RFC 8705 §3: a client configured to require certificate-bound tokens MUST NOT
  be silently downgraded to a Bearer token when it calls without a certificate.
  RFC 9449 is the DPoP equivalent: a client configured for DPoP-bound issuance
  must present a proof at the token endpoint. The host's
  `:client_requires_mtls?` / `:client_requires_dpop?` callbacks gate this; both
  are read defensively and fail open only to "not required" when the host has
  not supplied the callback (the constraints are off by default per
  `:dpop_enabled` / `:mtls_enabled`).

  ## DPoP nonce challenge preserved

  When a fresh DPoP nonce is required (RFC 9449 §8 / §9), the returned
  `%AttestoPhoenix.OAuthError{}` carries the `use_dpop_nonce` code and the fresh
  `DPoP-Nonce` value in its `:headers`, so the controller renders the header
  verbatim alongside the error.
  """

  alias Attesto.MTLS
  alias AttestoPhoenix.{Callback, Config, OAuthError}

  @typedoc "The sender-constraint facts the controller derives from the request."
  @type input :: %{
          optional(:dpop_proof) => String.t() | nil,
          optional(:mtls_cert_der) => binary() | nil,
          optional(:http_uri) => String.t() | nil,
          optional(:http_method) => String.t() | nil
        }

  @typedoc "The resolved sender-constraint binding."
  @type binding :: {:dpop, String.t()} | {:mtls, String.t()} | :none

  # RFC 6749 §5.2 / RFC 9449 §5 error codes.
  @error_invalid_request "invalid_request"
  @error_invalid_client "invalid_client"
  @error_invalid_dpop_proof "invalid_dpop_proof"
  @error_use_dpop_nonce "use_dpop_nonce"

  # RFC 9449 §7.1 / RFC 6750: access-token presentation type.
  @token_type_dpop "DPoP"
  @token_type_bearer "Bearer"

  # RFC 9449 §8 / §9: the response header carrying a fresh server-issued nonce.
  @dpop_nonce_header "dpop-nonce"

  @doc """
  Resolve the sender-constraint binding for a token request.

  Returns `{:ok, binding, token_type}` or `{:error, %OAuthError{}}`. See the
  module docs for the precedence rules and the input shape.
  """
  @spec resolve(Config.t(), input(), term()) ::
          {:ok, binding(), String.t()} | {:error, OAuthError.t()}
  def resolve(%Config{} = config, input, client) do
    cond do
      config.dpop_enabled and dpop_present?(input) ->
        bind_dpop(config, input)

      config.mtls_enabled and mtls_cert_present?(input) ->
        bind_mtls(input)

      client_requires_dpop?(config, client) ->
        # RFC 9449 defines `invalid_dpop_proof` for presented DPoP proof
        # failures. When the token request omits a required proof entirely,
        # return a standard OAuth token-endpoint error so FAPI clients can
        # classify the grant attempt without relying on DPoP-specific error
        # vocabulary.
        {:error, error(@error_invalid_request, "DPoP proof required")}

      client_requires_mtls?(config, client) ->
        # No DPoP proof and no client certificate, yet this client must be
        # certificate-bound: refuse rather than issue an unbound token.
        {:error, error(@error_invalid_client, "client certificate required")}

      true ->
        {:ok, :none, @token_type_bearer}
    end
  end

  @doc """
  The `Attesto.Token.mint/3` confirmation opt for a resolved `binding`
  (RFC 9449 / RFC 8705).

  DPoP binds `cnf.jkt`; mTLS binds `cnf.x5t#S256` (the certificate thumbprint,
  threaded so a real `cnf` is minted rather than dropped); an unbound binding
  carries no opt.
  """
  @spec mint_opts(binding()) :: keyword()
  def mint_opts(:none), do: []
  def mint_opts({:dpop, jkt}), do: [dpop_jkt: jkt]
  def mint_opts({:mtls, thumbprint}), do: [mtls_cert_thumbprint: thumbprint]

  @doc """
  The DPoP thumbprint a stateful grant (authorization-code redemption, refresh
  rotation) binds to. Only DPoP flows through those engines' `:dpop_jkt` opt;
  an mTLS binding carries no DPoP thumbprint.
  """
  @spec binding_jkt(binding()) :: String.t() | nil
  def binding_jkt({:dpop, jkt}), do: jkt
  def binding_jkt(_binding), do: nil

  @doc """
  The DPoP thumbprint to bind a refresh token to (RFC 9449 §8).

  Public clients get DPoP-bound refresh tokens; for confidential clients the
  refresh token stays bound to the authenticated `client_id` (RFC 6749 §6 /
  §10.4) rather than one DPoP proof key, so no DPoP thumbprint is threaded.
  """
  @spec refresh_binding_jkt(Config.t(), term(), binding()) :: String.t() | nil
  def refresh_binding_jkt(%Config{} = config, client, binding) do
    if client_public?(config, client), do: binding_jkt(binding)
  end

  @doc """
  Whether the client requires DPoP-bound token issuance (RFC 9449).

  Read defensively; fails open to "not required" when the host supplies no
  `:client_requires_dpop?` callback.
  """
  @spec client_requires_dpop?(Config.t(), term()) :: boolean()
  def client_requires_dpop?(%Config{} = config, client) do
    Callback.invoke(Config.client_requires_dpop_fun(config), [client], false) == true
  end

  @doc """
  Whether the client requires certificate-bound token issuance (RFC 8705).

  Read defensively; fails open to "not required" when the host supplies no
  `:client_requires_mtls?` callback.
  """
  @spec client_requires_mtls?(Config.t(), term()) :: boolean()
  def client_requires_mtls?(%Config{} = config, client) do
    Callback.invoke(Config.client_requires_mtls_fun(config), [client], false) == true
  end

  # ----- internal -----

  defp dpop_present?(input), do: is_binary(dpop_proof(input))

  defp mtls_cert_present?(input), do: is_binary(mtls_cert_der(input))

  defp bind_dpop(config, input) do
    proof = dpop_proof(input)

    verify_opts =
      [
        http_method: http_method(input),
        http_uri: http_uri(input)
      ]
      |> put_optional_kw(:nonce_check, nonce_check(config))

    case invoke_dpop_verify(proof, verify_opts) do
      {:ok, %{jkt: jkt}} ->
        {:ok, {:dpop, jkt}, @token_type_dpop}

      {:error, :use_dpop_nonce} ->
        # RFC 9449 §8/§9: hand the client a fresh nonce and demand a retry.
        {:error, dpop_nonce_required(config)}

      {:error, reason} ->
        {:error, error(@error_invalid_dpop_proof, "invalid DPoP proof: #{inspect(reason)}")}
    end
  end

  # The proof verifier is part of the `Attesto.DPoP` core; the replay-check
  # callback is host-supplied. Both are reached only through the configured
  # surface so this module hardcodes neither a store nor a clock.
  defp invoke_dpop_verify(proof, opts) do
    Attesto.DPoP.verify_proof(proof, opts)
  end

  defp bind_mtls(input) do
    case mtls_cert_der(input) do
      der when is_binary(der) ->
        case MTLS.compute_thumbprint(der) do
          {:ok, x5t} ->
            # RFC 8705 §3: the certificate thumbprint becomes the token's
            # `cnf.x5t#S256` (minted via `Attesto.Token`'s
            # `:mtls_cert_thumbprint` opt). mTLS-bound tokens keep the
            # `Bearer` type (RFC 8705 §3.1).
            {:ok, {:mtls, x5t}, @token_type_bearer}

          {:error, _reason} ->
            {:error, error(@error_invalid_client, "invalid client certificate")}
        end

      _ ->
        {:error, error(@error_invalid_client, "client certificate required")}
    end
  end

  # RFC 9449 §8/§9: when the deployment requires server-issued nonces
  # (`config.dpop_nonce_required`), hand `Attesto.DPoP.verify_proof/2` a
  # `:nonce_check` callback that validates the proof's `nonce` claim against
  # the configured `Attesto.DPoP.NonceStore`. The callback receives the
  # proof's `nonce` (which may be `nil` if the client sent none) and returns
  # `:ok` only for a currently-valid nonce, else `{:error, :use_dpop_nonce}`
  # so the controller answers with a fresh `DPoP-Nonce`. When nonces are not
  # required, no callback is supplied and the engine enforces none.
  defp nonce_check(%Config{dpop_nonce_required: true, nonce_store: store}) when is_atom(store) and not is_nil(store) do
    fn nonce ->
      if store.valid?(nonce), do: :ok, else: {:error, :use_dpop_nonce}
    end
  end

  defp nonce_check(_config), do: nil

  # RFC 9449 §8: issue a fresh server nonce and return it in the error's
  # `:headers` so the controller can replay the `DPoP-Nonce` header verbatim,
  # telling the client to retry its proof with the `nonce` claim included.
  defp dpop_nonce_required(config) do
    nonce = issue_nonce(config)

    error(@error_use_dpop_nonce, "DPoP proof requires a server-issued nonce",
      status: 400,
      headers: [{@dpop_nonce_header, nonce}]
    )
  end

  defp issue_nonce(%Config{nonce_store: store}) when is_atom(store) and not is_nil(store) do
    store.issue()
  end

  defp issue_nonce(_config), do: ""

  defp client_public?(config, client) do
    Callback.invoke(Config.client_public_fun(config), [client], false) == true
  end

  defp dpop_proof(input), do: Map.get(input, :dpop_proof)
  defp mtls_cert_der(input), do: Map.get(input, :mtls_cert_der)
  defp http_uri(input), do: Map.get(input, :http_uri)
  defp http_method(input), do: Map.get(input, :http_method)

  defp put_optional_kw(kw, _key, nil), do: kw
  defp put_optional_kw(kw, key, value), do: Keyword.put(kw, key, value)

  defp error(code, description) do
    OAuthError.new(error_code(code), description, status: 400)
  end

  defp error(code, description, opts) do
    OAuthError.new(error_code(code), description,
      status: Keyword.get(opts, :status, 400),
      headers: Keyword.get(opts, :headers, [])
    )
  end

  defp error_code(code) when is_binary(code), do: String.to_existing_atom(code)
end
