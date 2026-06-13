defmodule AttestoPhoenix.AuthorizationServer.PARTest do
  @moduledoc """
  Direct, data-level unit tests for the conn-free Pushed Authorization Request
  core (RFC 9126 / RFC 9449).

  These exercise `AttestoPhoenix.AuthorizationServer.PAR.store/2` against a
  `%Request{}` of plain data - no `Plug.Conn`, no controller. The focus is the
  contract the controller depends on: a freshly generated `request_uri`
  reference is returned with the configured lifetime, the authenticated
  `client_id` is stored (never a body value), client-authentication credentials
  are stripped, and the DPoP binding (RFC 9449 §4.2 / §4.3) is verified and
  stored - with a submitted `dpop_jkt` reconciled against the proof and multiple
  proofs rejected.
  """
  use ExUnit.Case, async: false

  alias AttestoPhoenix.AuthorizationServer.PAR
  alias AttestoPhoenix.AuthorizationServer.PAR.Request
  alias AttestoPhoenix.{Config, OAuthError}

  @htu "https://issuer.example/oauth/par"
  @htm "POST"
  @client %{id: "confidential-1"}

  defmodule StubKeystore do
    @moduledoc false
  end

  defmodule StubRepo do
    @moduledoc false
  end

  # An in-process PAR store keyed per test, so `store/2` persists somewhere
  # inspectable without a global table.
  defmodule Store do
    @moduledoc false
    @behaviour AttestoPhoenix.PARStore

    @impl true
    def put(request_uri, params, ttl) do
      Process.put({:par, request_uri}, {params, ttl})
      :ok
    end

    @impl true
    def fetch(request_uri) do
      case Process.get({:par, request_uri}) do
        {params, _ttl} -> {:ok, params}
        nil -> :error
      end
    end

    def lookup(request_uri) do
      case Process.get({:par, request_uri}) do
        {params, ttl} -> {:ok, params, ttl}
        nil -> :error
      end
    end
  end

  # A PAR store whose `put/3` fails, to exercise the storage-failure path.
  defmodule FailingStore do
    @moduledoc false
    @behaviour AttestoPhoenix.PARStore

    @impl true
    def put(_request_uri, _params, _ttl), do: {:error, :boom}

    @impl true
    def fetch(_request_uri), do: :error
  end

  defp required_fields do
    [
      issuer: "https://issuer.example",
      keystore: StubKeystore,
      repo: StubRepo,
      load_client: fn _ -> {:error, :not_found} end,
      verify_client_secret: fn _client, _given -> false end,
      load_principal: fn _ -> {:error, :not_found} end
    ]
  end

  defp config(overrides \\ []) do
    required_fields()
    |> Keyword.merge(
      client_id: fn client -> Map.get(client, :id) end,
      # RFC 9126 §2.1 step 3: the PAR endpoint validates the pushed request as
      # the authorization endpoint would, so the client's registered redirect
      # URIs must be resolvable for the exact-match check (RFC 6749 §3.1.2.3).
      client_redirect_uris: fn _client -> ["https://client.example/cb"] end,
      par_store: Store,
      par_ttl: 45,
      replay_check: fn _key, _ttl -> :ok end
    )
    |> Keyword.merge(overrides)
    |> Config.new()
  end

  defp request(overrides) do
    fields =
      [
        client: @client,
        params: %{},
        dpop_input: %{proofs: [], http_uri: @htu, http_method: @htm}
      ]
      |> Keyword.merge(overrides)

    struct!(Request, fields)
  end

  defp base_params do
    %{
      "client_id" => "confidential-1",
      "redirect_uri" => "https://client.example/cb",
      "response_type" => "code",
      "scope" => "openid profile",
      # PKCE is required (RFC 7636 / RFC 9700 §2.1.1); the PAR endpoint now
      # enforces it at push time, so a complete pushed request carries it.
      "code_challenge" => "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM",
      "code_challenge_method" => "S256"
    }
  end

  # A valid DPoP proof (RFC 9449 §4.2) bound to @htu/@htm; the matching `jkt`
  # is returned for assertion.
  defp dpop_proof_and_jkt do
    jwk = JOSE.JWK.generate_key({:ec, "P-256"})
    {_, pub_map} = JOSE.JWK.to_public_map(jwk)

    payload = %{
      "htm" => @htm,
      "htu" => @htu,
      "iat" => System.system_time(:second),
      "jti" => Base.url_encode64(:crypto.strong_rand_bytes(16), padding: false)
    }

    header = %{"alg" => "ES256", "typ" => "dpop+jwt", "jwk" => pub_map}
    {_, compact} = JOSE.JWS.compact(JOSE.JWT.sign(jwk, header, payload))
    {compact, Attesto.DPoP.compute_jkt(pub_map)}
  end

  describe "store/2 (RFC 9126 §2.2)" do
    test "returns a fresh request_uri reference and the configured lifetime" do
      config = config()

      assert {:ok, %{request_uri: request_uri, expires_in: 45}} =
               PAR.store(config, request(params: base_params()))

      assert String.starts_with?(request_uri, "urn:ietf:params:oauth:request_uri:")
      assert {:ok, _stored, 45} = Store.lookup(request_uri)
    end

    test "the request_uri reference is unique per call" do
      config = config()

      assert {:ok, %{request_uri: first}} = PAR.store(config, request(params: base_params()))
      assert {:ok, %{request_uri: second}} = PAR.store(config, request(params: base_params()))

      refute first == second
    end

    test "defaults the lifetime to 90 seconds when par_ttl is unset" do
      config = config(par_ttl: nil)

      assert {:ok, %{expires_in: 90}} = PAR.store(config, request(params: base_params()))
    end

    test "stores the authenticated client_id, never a body-supplied value" do
      # RFC 6749 §2.3.1: the stored record carries the client_id resolved from
      # the authenticated client, even when the body carries a different one.
      config = config()
      params = Map.put(base_params(), "client_id", "body-supplied-other")

      assert {:ok, %{request_uri: request_uri}} = PAR.store(config, request(params: params))
      assert {:ok, stored, 45} = Store.lookup(request_uri)
      assert stored["client_id"] == "confidential-1"
    end

    test "strips client-authentication credentials before storing" do
      config = config()

      params =
        base_params()
        |> Map.merge(%{
          "client_secret" => "s3cr3t",
          "client_assertion" => "header.body.sig",
          "client_assertion_type" => "urn:ietf:params:oauth:client-assertion-type:jwt-bearer"
        })

      assert {:ok, %{request_uri: request_uri}} = PAR.store(config, request(params: params))
      assert {:ok, stored, 45} = Store.lookup(request_uri)
      refute Map.has_key?(stored, "client_secret")
      refute Map.has_key?(stored, "client_assertion")
      refute Map.has_key?(stored, "client_assertion_type")
      assert stored["redirect_uri"] == "https://client.example/cb"
    end

    test "a storage failure surfaces as invalid_request without leaking detail" do
      config = config(par_store: FailingStore)

      assert {:error, %OAuthError{error: :invalid_request, status: 400}} =
               PAR.store(config, request(params: base_params()))
    end

    test "rejects a request_uri parameter at the PAR endpoint (RFC 9126 §2.1)" do
      # RFC 9126 §2.1 step 2 / FAPI2SPFinalPARRejectRequestUriInParAuthorizationFormParams:
      # a client may not push a reference to another reference. Checked on the
      # raw params, so it is not masked by a request object replacing the set.
      config = config()
      params = Map.put(base_params(), "request_uri", "urn:ietf:params:oauth:request_uri:nested")

      assert {:error, %OAuthError{error: :invalid_request, status: 400}} =
               PAR.store(config, request(params: params))
    end
  end

  describe "DPoP binding (RFC 9449 §4.2 / §4.3)" do
    test "verifies a presented proof and stores its thumbprint as dpop_jkt" do
      {proof, jkt} = dpop_proof_and_jkt()
      config = config()
      req = request(params: base_params(), dpop_input: dpop_input(proofs: [proof]))

      assert {:ok, %{request_uri: request_uri}} = PAR.store(config, req)
      assert {:ok, stored, 45} = Store.lookup(request_uri)
      assert stored["dpop_jkt"] == jkt
    end

    test "honours a submitted dpop_jkt that matches the proof" do
      {proof, jkt} = dpop_proof_and_jkt()
      config = config()
      params = Map.put(base_params(), "dpop_jkt", jkt)
      req = request(params: params, dpop_input: dpop_input(proofs: [proof]))

      assert {:ok, %{request_uri: request_uri}} = PAR.store(config, req)
      assert {:ok, stored, 45} = Store.lookup(request_uri)
      assert stored["dpop_jkt"] == jkt
    end

    test "rejects a submitted dpop_jkt that mismatches the proof" do
      {proof, _jkt} = dpop_proof_and_jkt()
      {_other, other_jkt} = dpop_proof_and_jkt()
      config = config()
      params = Map.put(base_params(), "dpop_jkt", other_jkt)
      req = request(params: params, dpop_input: dpop_input(proofs: [proof]))

      assert {:error, %OAuthError{error: :invalid_dpop_proof, status: 400}} =
               PAR.store(config, req)
    end

    test "honours an explicit dpop_jkt without a proof (proof-of-possession deferred)" do
      {_proof, jkt} = dpop_proof_and_jkt()
      config = config()
      params = Map.put(base_params(), "dpop_jkt", jkt)
      req = request(params: params, dpop_input: dpop_input(proofs: []))

      assert {:ok, %{request_uri: request_uri}} = PAR.store(config, req)
      assert {:ok, stored, 45} = Store.lookup(request_uri)
      assert stored["dpop_jkt"] == jkt
    end

    test "stores no dpop_jkt when neither a proof nor a parameter is present" do
      config = config()

      assert {:ok, %{request_uri: request_uri}} =
               PAR.store(config, request(params: base_params()))

      assert {:ok, stored, 45} = Store.lookup(request_uri)
      refute Map.has_key?(stored, "dpop_jkt")
    end

    test "rejects a malformed proof with invalid_dpop_proof" do
      config = config()
      req = request(params: base_params(), dpop_input: dpop_input(proofs: ["not-a-jwt"]))

      assert {:error, %OAuthError{error: :invalid_dpop_proof, status: 400}} =
               PAR.store(config, req)
    end

    test "rejects more than one presented DPoP proof (RFC 9449 §4.1)" do
      {proof, _jkt} = dpop_proof_and_jkt()
      config = config()
      req = request(params: base_params(), dpop_input: dpop_input(proofs: [proof, proof]))

      assert {:error, %OAuthError{error: :invalid_dpop_proof, status: 400}} =
               PAR.store(config, req)
    end
  end

  describe "authorization-request validation (RFC 9126 §2.1 step 3)" do
    test "rejects a pushed request whose redirect_uri is not registered" do
      config = config()
      params = Map.put(base_params(), "redirect_uri", "https://attacker.example/cb")

      assert {:error, %OAuthError{error: :invalid_request, status: 400}} =
               PAR.store(config, request(params: params))
    end

    test "rejects a pushed request missing PKCE (RFC 7636 / RFC 9700 §2.1.1)" do
      config = config()

      params =
        base_params() |> Map.drop(["code_challenge", "code_challenge_method"])

      assert {:error, %OAuthError{error: :invalid_request, status: 400}} =
               PAR.store(config, request(params: params))
    end

    test "rejects a pushed request with an unsupported response_type" do
      config = config()
      params = Map.put(base_params(), "response_type", "token")

      assert {:error, %OAuthError{error: :unsupported_response_type, status: 400}} =
               PAR.store(config, request(params: params))
    end

    test "the validation is not deferred: an invalid request never reaches the store" do
      config = config()
      params = Map.put(base_params(), "redirect_uri", "https://attacker.example/cb")

      assert {:error, %OAuthError{}} = PAR.store(config, request(params: params))
      # No request_uri was minted, so nothing could have been persisted.
      assert Store.lookup("urn:ietf:params:oauth:request_uri:anything") == :error
    end
  end

  defp dpop_input(overrides) do
    Map.merge(%{proofs: [], http_uri: @htu, http_method: @htm}, Map.new(overrides))
  end
end
