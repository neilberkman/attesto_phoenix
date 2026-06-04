defmodule AttestoPhoenix.AuthorizationServer.PAR do
  @moduledoc """
  Pushed Authorization Request storage (RFC 9126), as conn-free core.

  This is the single place that turns an authenticated client and a parsed
  authorization request into either a stored `request_uri` reference or an
  `AttestoPhoenix.OAuthError`. The Pushed Authorization Request endpoint
  (RFC 9126) authenticates the client (RFC 6749 §2.3), stores the submitted
  authorization request parameters behind a `request_uri`, and returns that
  reference to be used at the authorization endpoint, which still performs the
  normal client/redirect/scope/PKCE validation when the reference is resolved.

  ## North star

  `AttestoPhoenix.Controller.PARController` parses the request off the
  `Plug.Conn`, authenticates the client via `AttestoPhoenix.ClientAuthentication`
  (RFC 6749 §2.3), lifts the DPoP facts into a `%Request{}` of plain data, and
  calls `store/2`. This module reads only data, never touches a conn, and never
  emits an event. Policy is carried on the `%AttestoPhoenix.Config{}` the caller
  passes in (the `:par_store` persistence, the `:par_ttl`, the host callbacks);
  nothing is hardcoded here.

  ## Return value

  `{:ok, %{request_uri: request_uri, expires_in: ttl}}` on success, where
  `request_uri` is a freshly generated `urn:ietf:params:oauth:request_uri:`
  reference (RFC 9126 §2.2) and `ttl` is the configured lifetime in seconds.
  `{:error, %AttestoPhoenix.OAuthError{}}` on failure.

  ## Security details preserved

    * The stored record carries the authenticated `client_id` resolved through
      the host's `:client_id` callback (RFC 6749 §2.2), overriding any
      body-supplied value. When no `:client_id` callback is configured the
      request's own presented `client_id` is left intact (not clobbered with
      `nil`); the library makes no assumption about the opaque client shape. The
      client-authentication credentials (`client_secret`, `client_assertion`,
      `client_assertion_type`) are dropped before storage.
    * RFC 9449: when a `DPoP` proof is presented at the PAR endpoint, it is
      verified against the canonical request URL/method (RFC 9449 §4.2 / §4.3)
      with the configured replay check, and its `jkt` is stored as the
      `dpop_jkt` the authorization code will later be sender-constrained to. A
      submitted `dpop_jkt` request parameter that disagrees with the verified
      proof's thumbprint is rejected (`invalid_dpop_proof`). Presenting more
      than one `DPoP` proof is rejected (RFC 9449 §4.1). A `dpop_jkt` parameter
      submitted without a proof is honoured as-is, since the proof of possession
      is demonstrated later at the token endpoint.
  """

  alias Attesto.DPoP
  alias Attesto.DPoP.ReplayCache
  alias Attesto.RequestObject
  alias AttestoPhoenix.AuthorizationServer.PAR.Request
  alias AttestoPhoenix.AuthorizationServer.RequestPolicy
  alias AttestoPhoenix.{Callback, Config, OAuthError}

  @typedoc """
  The conn-free DPoP facts the controller lifts off the PAR request
  (RFC 9449 §4.1 / §4.2 / §4.3).

    * `:proofs` - the `DPoP` request-header values
      (`Plug.Conn.get_req_header(conn, "dpop")`); `[]` when no proof was
      presented, more than one entry being a rejected ambiguous request.
    * `:http_uri` - the canonical request URL (`htu`) the proof is bound to.
    * `:http_method` - the HTTP method (`htm`) the proof is bound to.
  """
  @type dpop_input :: %{
          optional(:proofs) => [String.t()],
          optional(:http_uri) => String.t() | nil,
          optional(:http_method) => String.t() | nil
        }

  # RFC 6749 §5.2 / RFC 9449 error codes.
  @error_invalid_request "invalid_request"
  @error_invalid_request_object "invalid_request_object"
  @error_invalid_dpop_proof "invalid_dpop_proof"

  # RFC 9126 §2.2: the `request_uri` reference scheme.
  @request_uri_prefix "urn:ietf:params:oauth:request_uri:"

  # RFC 9126 §2.2: the default `request_uri` lifetime, in seconds, when the host
  # configures no `:par_ttl`.
  @default_par_ttl 90

  @doc """
  Store a pushed authorization request, returning the `request_uri` reference
  and its lifetime, or an error.

  `config` is the validated `%AttestoPhoenix.Config{}` carrying the `:par_store`
  persistence, the `:par_ttl`, and the host callbacks; `request` is the
  `AttestoPhoenix.AuthorizationServer.PAR.Request` the controller built from the
  authenticated client, the request body, and the conn-free DPoP facts. See the
  module docs for the return shape and the security details preserved.
  """
  @spec store(Config.t(), Request.t()) ::
          {:ok, %{request_uri: String.t(), expires_in: pos_integer()}}
          | {:error, OAuthError.t()}
  def store(%Config{} = config, %Request{} = request) do
    %{client: client, params: params, dpop_input: dpop_input} = request
    ttl = config_field(config, :par_ttl, @default_par_ttl)
    request_uri = @request_uri_prefix <> random()

    # Verify the request object FIRST so its signed parameters are authoritative
    # (RFC 9101 §6.3) before DPoP reconciliation: a signed `dpop_jkt` must be the
    # value the presented proof is checked against, never an unsigned body value.
    with :ok <- reject_request_uri(params),
         {:ok, params} <- verify_request_object(config, client, params),
         :ok <- validate_pushed_request(config, client, params),
         {:ok, dpop_jkt} <- verify_dpop_binding(config, dpop_input, params) do
      stored =
        params
        |> Map.drop(["client_secret", "client_assertion", "client_assertion_type"])
        |> put_verified_dpop_jkt(dpop_jkt)
        |> put_resolved_client_id(client_id(config, client))

      case par_store(config).put(request_uri, stored, ttl) do
        :ok ->
          {:ok, %{request_uri: request_uri, expires_in: ttl}}

        _ ->
          {:error, error(@error_invalid_request, "could not store pushed authorization request")}
      end
    end
  end

  # RFC 9126 §2.1 (step 2): the PAR endpoint MUST reject a request that itself
  # carries a `request_uri` parameter - a client cannot push a reference to
  # another reference. Checked on the RAW pushed parameters, before request-
  # object verification, so a `request` object replacing the parameter set
  # cannot mask a `request_uri` smuggled in as a sibling form parameter.
  defp reject_request_uri(%{"request_uri" => value}) when is_binary(value) and value != "" do
    {:error,
     error(@error_invalid_request, "request_uri must not be used at the PAR endpoint")}
  end

  defp reject_request_uri(_params), do: :ok

  # RFC 9126 §2.1 step 3: validate the pushed request as the authorization
  # endpoint would - the request `redirect_uri` must exactly match one of the
  # client's registered URIs (RFC 6749 §3.1.2.3), the `response_type`/PKCE/
  # `response_mode` must be valid - so an invalid request is refused early here
  # rather than only when the `request_uri` is later resolved at /authorize. The
  # `RequestPolicy` resolvers are shared with the authorization endpoint so both
  # validate identically. The signed `request` object, already verified and
  # merged into `params` above, is dropped before validation so it is not
  # re-verified (its parameters are already authoritative). Every PAR error is a
  # direct response (RFC 9126 §2.3), never a redirect, so a redirectable
  # classification is flattened to its OAuth error code.
  defp validate_pushed_request(config, client, params) do
    case RequestPolicy.validate(config, client, Map.delete(params, "request")) do
      {:ok, _request} -> :ok
      {:error, reason} -> {:error, par_validation_error(reason)}
    end
  end

  # OIDC Core §3.1.2.6 classifies a redirect_uri/client_id failure as
  # non-redirectable; at the PAR endpoint there is no redirect either way, so
  # both the direct and the (would-be) redirect classifications collapse to a
  # direct RFC 6749 §5.2 error response, preserving the error code the
  # authorization endpoint would have surfaced.
  defp par_validation_error({:direct, reason}) do
    error(@error_invalid_request, "invalid authorization request: #{reason}")
  end

  defp par_validation_error({:redirect, %{error: code, error_description: description}}) do
    OAuthError.new(validation_code_atom(code), description, status: 400)
  end

  # The RFC 6749 §4.1.2.1 / §5.2 error codes `Attesto.AuthorizationRequest`
  # raises for a redirectable failure, mapped to the atoms `OAuthError` expects.
  # An unrecognised code falls back to `invalid_request` (the §5.2 catch-all).
  defp validation_code_atom("invalid_request"), do: :invalid_request
  defp validation_code_atom("invalid_request_object"), do: :invalid_request_object
  defp validation_code_atom("invalid_scope"), do: :invalid_scope
  defp validation_code_atom("unsupported_response_type"), do: :unsupported_response_type
  defp validation_code_atom("request_not_supported"), do: :request_not_supported
  defp validation_code_atom("request_uri_not_supported"), do: :request_uri_not_supported
  defp validation_code_atom(_other), do: :invalid_request

  # RFC 9449: bind the pushed request to a DPoP proof when one is presented.
  # No proof keeps any submitted `dpop_jkt` parameter as-is (proof of possession
  # is demonstrated later at the token endpoint); a single proof is verified and
  # its thumbprint stored; more than one proof is an ambiguous request
  # (RFC 9449 §4.1) and is rejected.
  defp verify_dpop_binding(config, dpop_input, params) do
    case dpop_proofs(dpop_input) do
      [] ->
        {:ok, submitted_dpop_jkt(params)}

      [proof] ->
        verify_dpop_proof(config, dpop_input, params, proof)

      _multiple ->
        {:error, error(@error_invalid_dpop_proof, "multiple DPoP proofs")}
    end
  end

  defp verify_dpop_proof(config, dpop_input, params, proof) do
    opts = [
      http_method: http_method(dpop_input),
      http_uri: http_uri(dpop_input),
      replay_check: replay_check(config)
    ]

    with {:ok, %{jkt: verified_jkt}} <- DPoP.verify_proof(proof, opts),
         :ok <- check_submitted_dpop_jkt(Map.get(params, "dpop_jkt"), verified_jkt) do
      {:ok, verified_jkt}
    else
      {:error, reason} ->
        {:error, error(@error_invalid_dpop_proof, "invalid DPoP proof: #{inspect(reason)}")}
    end
  end

  # RFC 9449: a submitted `dpop_jkt` is honoured only when it matches the proof
  # the client actually demonstrated; a disagreement is a confused request and
  # is rejected (an absent or empty `dpop_jkt` is no constraint to reconcile).
  defp check_submitted_dpop_jkt(nil, _verified_jkt), do: :ok
  defp check_submitted_dpop_jkt("", _verified_jkt), do: :ok
  defp check_submitted_dpop_jkt(verified_jkt, verified_jkt), do: :ok
  defp check_submitted_dpop_jkt(_submitted_jkt, _verified_jkt), do: {:error, :dpop_jkt_mismatch}

  defp put_verified_dpop_jkt(params, nil), do: params
  defp put_verified_dpop_jkt(params, dpop_jkt), do: Map.put(params, "dpop_jkt", dpop_jkt)

  defp submitted_dpop_jkt(%{"dpop_jkt" => jkt}) when is_binary(jkt) and jkt != "", do: jkt
  defp submitted_dpop_jkt(_params), do: nil

  defp replay_check(%Config{replay_check: nil}), do: &ReplayCache.check_and_record/2
  defp replay_check(%Config{replay_check: callback}), do: callback

  # The client's identifier (RFC 6749 §2.2), resolved through the host's
  # `:client_id` callback. When no `:client_id` callback is configured the
  # identifier cannot be derived from the opaque client struct (`nil`), matching
  # the resolution used everywhere else in the library.
  defp client_id(config, client) do
    Callback.invoke(Config.client_id_fun(config), [client], nil)
  end

  # Store the authenticated `client_id` when it resolves. When it does not (no
  # `:client_id` callback), leave the request's own presented `client_id`
  # intact rather than clobbering it with `nil`. The prior
  # `client[:id]`/`client["id"]` struct-shape fallback is intentionally gone -
  # the library makes no assumption about the opaque host client shape.
  defp put_resolved_client_id(params, nil), do: params
  defp put_resolved_client_id(params, client_id), do: Map.put(params, "client_id", client_id)

  defp par_store(config), do: config_field(config, :par_store, AttestoPhoenix.Store.PAR.ETS)

  defp dpop_proofs(dpop_input), do: Map.get(dpop_input, :proofs, [])
  defp http_uri(dpop_input), do: Map.get(dpop_input, :http_uri)
  defp http_method(dpop_input), do: Map.get(dpop_input, :http_method)

  defp random, do: 32 |> :crypto.strong_rand_bytes() |> Base.url_encode64(padding: false)

  defp config_field(config, field, default) do
    case Map.get(config, field) do
      nil -> default
      value -> value
    end
  end

  # FAPI 2.0 Message Signing §5.3.1: when a signed `request` object is pushed,
  # the AS verifies it AT the PAR endpoint (not only later at /authorize), so a
  # bad JAR is rejected here. Verification uses the authenticated client's
  # trusted JWKS, the issuer audience, and the configured request-object policy
  # (`Attesto.RequestObject.Policy`; default generic OIDC §6.1).
  #
  # On success the VERIFIED request-object parameters become the stored request
  # (RFC 9101 §6.3: when a request object is present its signed parameters are
  # authoritative and unsigned body parameters are ignored), so the stored PAR
  # record never carries unsigned body values beside a verified object. The
  # compact `request` JWT is retained so /authorize re-verifies it too. A PAR
  # carrying no `request` object is stored as-is - requiring its presence is a
  # separate profile concern.
  defp verify_request_object(config, client, %{"request" => request})
       when is_binary(request) and request != "" do
    opts =
      [issuer: client_id(config, client), audience: config.issuer] ++
        RequestObject.Policy.to_verify_opts(request_object_policy(config))

    case RequestObject.verify(request, client_jwks(config, client) || %{"keys" => []}, opts) do
      {:ok, object_params} ->
        {:ok, Map.put(object_params, "request", request)}

      {:error, _reason} ->
        {:error, error(@error_invalid_request_object, "request object is invalid")}
    end
  end

  # No `request` object pushed. FAPI 2.0 Message Signing §5.3.1: when the
  # configured policy requires a signed request object, a PAR carrying none is
  # rejected here (RFC 9126 §2.3 invalid_request) rather than stored as a plain
  # request; otherwise the pushed plain parameters stand (generic OIDC §6.1).
  defp verify_request_object(config, _client, params) do
    if RequestObject.Policy.require_request_object?(request_object_policy(config)) do
      {:error,
       error(
         @error_invalid_request,
         "pushed authorization request must use a signed request object"
       )}
    else
      {:ok, params}
    end
  end

  defp request_object_policy(config), do: config.request_object_policy || %RequestObject.Policy{}

  # Resolve the client's trusted JWK set, mirroring the authorize controller's
  # resolution (the host's `:client_jwks` callback, returning a JWKS or `nil`).
  defp client_jwks(config, client) do
    case Config.client_jwks_fun(config) do
      nil ->
        nil

      callback ->
        case Callback.invoke(callback, [client]) do
          {:ok, jwks} -> jwks
          jwks when is_map(jwks) or is_list(jwks) -> jwks
          _other -> nil
        end
    end
  end

  defp error(code, description) do
    OAuthError.new(code_atom(code), description, status: 400)
  end

  defp code_atom(@error_invalid_request), do: :invalid_request
  defp code_atom(@error_invalid_request_object), do: :invalid_request_object
  defp code_atom(@error_invalid_dpop_proof), do: :invalid_dpop_proof
end
