defmodule AttestoPhoenix.Controller.PARControllerTest do
  use ExUnit.Case, async: false

  import Plug.Test

  alias Attesto.RequestObject.Policy
  alias AttestoPhoenix.Controller.PARController
  alias AttestoPhoenix.Store.PAR.ETS

  @endpoint_path "/oauth/par"
  @client %{id: "confidential-1", secret: "s3cr3t"}

  defmodule StubKeystore do
    @moduledoc false
  end

  defmodule StubRepo do
    @moduledoc false
  end

  defmodule PARStore do
    @moduledoc false
    @behaviour AttestoPhoenix.PARStore

    @table :"#{__MODULE__}.Requests"

    def reset do
      if :ets.whereis(@table) == :undefined do
        :ets.new(@table, [:set, :public, :named_table])
      else
        :ets.delete_all_objects(@table)
      end
    end

    @impl true
    def put(request_uri, params, ttl) do
      true = :ets.insert(@table, {request_uri, params, ttl})
      :ok
    end

    @impl true
    def fetch(request_uri) do
      case :ets.lookup(@table, request_uri) do
        [{^request_uri, params, _ttl}] -> {:ok, params}
        [] -> :error
      end
    end

    @impl true
    def take(request_uri) do
      case :ets.take(@table, request_uri) do
        [{^request_uri, params, _ttl}] -> {:ok, params}
        [] -> :error
      end
    end

    def lookup(request_uri) do
      case :ets.lookup(@table, request_uri) do
        [{^request_uri, params, ttl}] -> {:ok, params, ttl}
        [] -> :error
      end
    end
  end

  setup do
    PARStore.reset()

    put_config(
      issuer: "https://issuer.example",
      keystore: StubKeystore,
      repo: StubRepo,
      load_client: fn
        "confidential-1" -> {:ok, @client}
        _ -> {:error, :not_found}
      end,
      verify_client_secret: fn
        %{secret: secret}, given -> secret == given
        _unknown, _given -> false
      end,
      load_principal: fn _ -> {:error, :not_found} end,
      client_id: fn client -> client.id end,
      # RFC 9126 §2.1 step 3: the PAR endpoint validates the pushed request as
      # the authorization endpoint would, so the client's registered redirect
      # URIs must resolve for the exact-match check (RFC 6749 §3.1.2.3).
      client_redirect_uris: fn _client -> ["https://client.example/cb"] end,
      par_store: PARStore,
      par_ttl: 45,
      replay_check: fn _key, _ttl -> :ok end,
      require_https: false
    )

    :ok
  end

  test "stores a pushed authorization request authenticated with client_secret_basic" do
    params = auth_params()
    credentials = Base.encode64("confidential-1:s3cr3t")

    conn =
      :post
      |> conn(@endpoint_path, params)
      |> Plug.Conn.put_req_header("authorization", "Basic " <> credentials)
      |> PARController.create(params)

    assert conn.status == 201
    body = JSON.decode!(conn.resp_body)
    assert body["expires_in"] == 45
    assert body["request_uri"] =~ "urn:ietf:params:oauth:request_uri:"

    assert {:ok, stored, 45} = PARStore.lookup(body["request_uri"])
    assert stored["client_id"] == "confidential-1"
    assert stored["redirect_uri"] == "https://client.example/cb"
    refute Map.has_key?(stored, "client_secret")
  end

  test "stores the authenticated client_id when a redundant matching client_id is in the body" do
    # RFC 6749 §2.3.1: the Basic userid is the authoritative client_id; a body
    # client_id is mere identification and is honoured only when it agrees.
    # The stored record always carries the authenticated client_id, never a
    # body-supplied value.
    params = Map.put(auth_params(), "client_id", "confidential-1")
    credentials = Base.encode64("confidential-1:s3cr3t")

    conn =
      :post
      |> conn(@endpoint_path, params)
      |> Plug.Conn.put_req_header("authorization", "Basic " <> credentials)
      |> PARController.create(params)

    assert conn.status == 201
    body = JSON.decode!(conn.resp_body)
    assert {:ok, stored, 45} = PARStore.lookup(body["request_uri"])
    assert stored["client_id"] == "confidential-1"
  end

  test "rejects a body client_id that conflicts with the Basic credentials (RFC 6749 §2.3.1)" do
    # An internally inconsistent request: a body client_id that disagrees with
    # the authoritative Basic userid is rejected before any secret verification.
    params = Map.put(auth_params(), "client_id", "body-supplied-client")
    credentials = Base.encode64("confidential-1:s3cr3t")

    conn =
      :post
      |> conn(@endpoint_path, params)
      |> Plug.Conn.put_req_header("authorization", "Basic " <> credentials)
      |> PARController.create(params)

    assert conn.status == 400
    assert JSON.decode!(conn.resp_body)["error"] == "invalid_request"
  end

  test "uses the default ETS PAR store when par_store is unset" do
    put_config(par_store: nil)

    params = auth_params()
    credentials = Base.encode64("confidential-1:s3cr3t")

    conn =
      :post
      |> conn(@endpoint_path, params)
      |> Plug.Conn.put_req_header("authorization", "Basic " <> credentials)
      |> PARController.create(params)

    assert conn.status == 201
    body = JSON.decode!(conn.resp_body)

    assert {:ok, stored} = ETS.take(body["request_uri"])
    assert stored["client_id"] == "confidential-1"
    assert stored["redirect_uri"] == "https://client.example/cb"
  end

  test "uses the default ETS PAR store for private_key_jwt when par_store is unset" do
    client_key = JOSE.JWK.generate_key({:ec, "P-256"})
    client_jwks = %{"keys" => [public_jwk(client_key)]}

    put_config(
      par_store: nil,
      token_endpoint_auth_methods_supported: ["private_key_jwt"],
      client_jwks: fn %{id: "confidential-1"} -> client_jwks end
    )

    params =
      Map.merge(auth_params(), %{
        "code_challenge" => "Z_P4EKbGwIkA01e3Y5fp4tMCvn_Ae5nUw7qY7XwkTrQ",
        "code_challenge_method" => "S256",
        "client_assertion_type" => Attesto.ClientAssertion.assertion_type(),
        "client_assertion" => client_assertion(client_key, "confidential-1")
      })

    conn =
      :post
      |> conn(@endpoint_path, params)
      |> PARController.create(params)

    assert conn.status == 201
    body = JSON.decode!(conn.resp_body)

    assert {:ok, stored} = ETS.take(body["request_uri"])
    assert stored["client_id"] == "confidential-1"
    assert stored["response_type"] == "code"
    assert stored["code_challenge_method"] == "S256"
    refute Map.has_key?(stored, "client_assertion")
    refute Map.has_key?(stored, "client_assertion_type")
  end

  test "stores a pushed authorization request authenticated with private_key_jwt" do
    client_key = JOSE.JWK.generate_key({:ec, "P-256"})
    client_jwks = %{"keys" => [public_jwk(client_key)]}

    put_config(client_jwks: fn %{id: "confidential-1"} -> client_jwks end)

    params =
      Map.merge(auth_params(), %{
        "client_assertion_type" => Attesto.ClientAssertion.assertion_type(),
        "client_assertion" => client_assertion(client_key, "confidential-1")
      })

    conn =
      :post
      |> conn(@endpoint_path, params)
      |> PARController.create(params)

    assert conn.status == 201
    body = JSON.decode!(conn.resp_body)
    assert {:ok, stored, 45} = PARStore.lookup(body["request_uri"])
    assert stored["client_id"] == "confidential-1"
    refute Map.has_key?(stored, "client_assertion")
    refute Map.has_key?(stored, "client_assertion_type")
  end

  test "stores the verified DPoP proof thumbprint for sender-constrained PAR" do
    params = auth_params()
    credentials = Base.encode64("confidential-1:s3cr3t")
    {proof, jkt} = dpop_proof()

    conn =
      params
      |> https_post()
      |> Plug.Conn.put_req_header("authorization", "Basic " <> credentials)
      |> Plug.Conn.put_req_header("dpop", proof)
      |> PARController.create(params)

    assert conn.status == 201
    body = JSON.decode!(conn.resp_body)
    assert {:ok, stored, 45} = PARStore.lookup(body["request_uri"])
    assert stored["dpop_jkt"] == jkt
  end

  test "accepts an explicit PAR dpop_jkt only when it matches the DPoP proof" do
    credentials = Base.encode64("confidential-1:s3cr3t")
    {proof, jkt} = dpop_proof()
    params = Map.put(auth_params(), "dpop_jkt", jkt)

    conn =
      params
      |> https_post()
      |> Plug.Conn.put_req_header("authorization", "Basic " <> credentials)
      |> Plug.Conn.put_req_header("dpop", proof)
      |> PARController.create(params)

    assert conn.status == 201
    body = JSON.decode!(conn.resp_body)
    assert {:ok, stored, 45} = PARStore.lookup(body["request_uri"])
    assert stored["dpop_jkt"] == jkt
  end

  test "stores an explicit PAR dpop_jkt without requiring a PAR DPoP proof" do
    credentials = Base.encode64("confidential-1:s3cr3t")
    {_proof, jkt} = dpop_proof()
    params = Map.put(auth_params(), "dpop_jkt", jkt)

    conn =
      :post
      |> conn(@endpoint_path, params)
      |> Plug.Conn.put_req_header("authorization", "Basic " <> credentials)
      |> PARController.create(params)

    assert conn.status == 201
    body = JSON.decode!(conn.resp_body)
    assert {:ok, stored, 45} = PARStore.lookup(body["request_uri"])
    assert stored["dpop_jkt"] == jkt
  end

  test "rejects an explicit PAR dpop_jkt that mismatches the DPoP proof" do
    credentials = Base.encode64("confidential-1:s3cr3t")
    {proof, _jkt} = dpop_proof()
    {_other_proof, other_jkt} = dpop_proof()
    params = Map.put(auth_params(), "dpop_jkt", other_jkt)

    conn =
      params
      |> https_post()
      |> Plug.Conn.put_req_header("authorization", "Basic " <> credentials)
      |> Plug.Conn.put_req_header("dpop", proof)
      |> PARController.create(params)

    assert conn.status == 400
    assert JSON.decode!(conn.resp_body)["error"] == "invalid_dpop_proof"
  end

  test "accepts private_key_jwt assertion audience set to issuer" do
    client_key = JOSE.JWK.generate_key({:ec, "P-256"})
    client_jwks = %{"keys" => [public_jwk(client_key)]}

    put_config(client_jwks: fn %{id: "confidential-1"} -> client_jwks end)

    params =
      Map.merge(auth_params(), %{
        "client_assertion_type" => Attesto.ClientAssertion.assertion_type(),
        "client_assertion" => client_assertion(client_key, "confidential-1", %{"aud" => "https://issuer.example"})
      })

    conn =
      :post
      |> conn(@endpoint_path, params)
      |> PARController.create(params)

    assert conn.status == 201
  end

  test "rejects a private_key_jwt assertion audienced to the PAR endpoint URL (FAPI: issuer only)" do
    # FAPI 2.0 §5.3.2.1 requires the client-assertion `aud` to be the issuer
    # identifier; the concrete endpoint URL must NOT be accepted (conformance
    # FAPI2SPFinalPAREndpointAsAudienceFails).
    client_key = JOSE.JWK.generate_key({:ec, "P-256"})
    client_jwks = %{"keys" => [public_jwk(client_key)]}

    put_config(client_jwks: fn %{id: "confidential-1"} -> client_jwks end)

    params =
      Map.merge(auth_params(), %{
        "client_assertion_type" => Attesto.ClientAssertion.assertion_type(),
        "client_assertion" =>
          client_assertion(client_key, "confidential-1", %{
            "aud" => "https://issuer.example/oauth/par"
          })
      })

    conn =
      :post
      |> conn(@endpoint_path, params)
      |> PARController.create(params)

    assert conn.status == 400
    assert JSON.decode!(conn.resp_body)["error"] == "invalid_client"
  end

  test "rejects private_key_jwt assertion audience that is neither the issuer nor the endpoint" do
    client_key = JOSE.JWK.generate_key({:ec, "P-256"})
    client_jwks = %{"keys" => [public_jwk(client_key)]}

    put_config(client_jwks: fn %{id: "confidential-1"} -> client_jwks end)

    params =
      Map.merge(auth_params(), %{
        "client_assertion_type" => Attesto.ClientAssertion.assertion_type(),
        "client_assertion" => client_assertion(client_key, "confidential-1", %{"aud" => "https://other.example"})
      })

    conn =
      :post
      |> conn(@endpoint_path, params)
      |> PARController.create(params)

    assert conn.status == 400
    assert JSON.decode!(conn.resp_body)["error"] == "invalid_client"
  end

  test "rejects replayed private_key_jwt assertions" do
    client_key = JOSE.JWK.generate_key({:ec, "P-256"})
    client_jwks = %{"keys" => [public_jwk(client_key)]}
    assertion = client_assertion(client_key, "confidential-1")

    put_config(
      client_jwks: fn %{id: "confidential-1"} -> client_jwks end,
      replay_check: replay_once()
    )

    params =
      Map.merge(auth_params(), %{
        "client_assertion_type" => Attesto.ClientAssertion.assertion_type(),
        "client_assertion" => assertion
      })

    first =
      :post
      |> conn(@endpoint_path, params)
      |> PARController.create(params)

    assert first.status == 201

    second =
      :post
      |> conn(@endpoint_path, params)
      |> PARController.create(params)

    assert second.status == 400
    assert JSON.decode!(second.resp_body)["error"] == "invalid_client"
  end

  test "rejects client_secret_basic when configured for private_key_jwt only" do
    put_config(token_endpoint_auth_methods_supported: ["private_key_jwt"])

    params = auth_params()
    credentials = Base.encode64("confidential-1:s3cr3t")

    conn =
      :post
      |> conn(@endpoint_path, params)
      |> Plug.Conn.put_req_header("authorization", "Basic " <> credentials)
      |> PARController.create(params)

    assert conn.status == 400
    assert JSON.decode!(conn.resp_body)["error"] == "invalid_client"
  end

  test "allows private_key_jwt when configured for private_key_jwt only" do
    client_key = JOSE.JWK.generate_key({:ec, "P-256"})
    client_jwks = %{"keys" => [public_jwk(client_key)]}

    put_config(
      token_endpoint_auth_methods_supported: ["private_key_jwt"],
      client_jwks: fn %{id: "confidential-1"} -> client_jwks end
    )

    params =
      Map.merge(auth_params(), %{
        "client_assertion_type" => Attesto.ClientAssertion.assertion_type(),
        "client_assertion" => client_assertion(client_key, "confidential-1")
      })

    conn =
      :post
      |> conn(@endpoint_path, params)
      |> PARController.create(params)

    assert conn.status == 201
  end

  test "rejects multiple client authentication methods" do
    params =
      Map.merge(auth_params(), %{
        "client_secret" => "s3cr3t",
        "client_assertion_type" => Attesto.ClientAssertion.assertion_type(),
        "client_assertion" => "header.body.sig"
      })

    conn =
      :post
      |> conn(@endpoint_path, params)
      |> PARController.create(params)

    assert conn.status == 400
    assert JSON.decode!(conn.resp_body)["error"] == "invalid_request"
  end

  test "rejects unknown clients without revealing existence" do
    params = Map.merge(auth_params(), %{"client_id" => "missing", "client_secret" => "anything"})

    conn =
      :post
      |> conn(@endpoint_path, params)
      |> PARController.create(params)

    assert conn.status == 400
    body = JSON.decode!(conn.resp_body)
    assert body["error"] == "invalid_client"
    assert body["error_description"] == "client authentication failed"
  end

  describe "PAR-time request object verification (FAPI Message Signing 2.0 §5.3.1)" do
    test "default policy accepts a signed request object without nbf/exp" do
      request_key = JOSE.JWK.generate_key({:ec, "P-256"})

      put_config(client_jwks: fn %{id: "confidential-1"} -> %{"keys" => [public_jwk(request_key)]} end)

      request =
        signed_request_object(
          request_key,
          "confidential-1",
          Map.drop(request_claims(), ["nbf", "exp"])
        )

      conn = par_with_request_object(request)

      assert conn.status == 201
    end

    test "FAPI policy accepts a compliant signed request object at the PAR endpoint" do
      request_key = JOSE.JWK.generate_key({:ec, "P-256"})

      put_config(
        client_jwks: fn %{id: "confidential-1"} -> %{"keys" => [public_jwk(request_key)]} end,
        request_object_policy: Policy.fapi_message_signing()
      )

      request =
        signed_request_object(request_key, "confidential-1", request_claims(), %{
          "typ" => "oauth-authz-req+jwt"
        })

      conn = par_with_request_object(request)

      assert conn.status == 201
    end

    test "FAPI policy rejects a non-compliant signed request object AT the PAR endpoint" do
      request_key = JOSE.JWK.generate_key({:ec, "P-256"})

      put_config(
        client_jwks: fn %{id: "confidential-1"} -> %{"keys" => [public_jwk(request_key)]} end,
        request_object_policy: Policy.fapi_message_signing()
      )

      # Missing nbf under the FAPI profile: PAR itself must reject it, not defer
      # the rejection to /authorize.
      request =
        signed_request_object(
          request_key,
          "confidential-1",
          Map.delete(request_claims(), "nbf"),
          %{
            "typ" => "oauth-authz-req+jwt"
          }
        )

      conn = par_with_request_object(request)

      assert conn.status == 400
      assert JSON.decode!(conn.resp_body)["error"] == "invalid_request_object"
    end

    test "FAPI policy rejects a PAR that carries no signed request object" do
      # FAPI 2.0 Message Signing §5.3.1: the profile mandates a signed request
      # object, so a plain PAR (parameters in the body, no `request`) is rejected
      # at the PAR endpoint rather than stored as a plain pushed request. A
      # required-request-object policy needs :client_jwks (enforced at boot).
      put_config(
        request_object_policy: Policy.fapi_message_signing(),
        client_jwks: fn %{id: "confidential-1"} -> %{"keys" => []} end
      )

      params = auth_params()
      credentials = Base.encode64("confidential-1:s3cr3t")

      conn =
        :post
        |> conn(@endpoint_path, params)
        |> Plug.Conn.put_req_header("authorization", "Basic " <> credentials)
        |> PARController.create(params)

      assert conn.status == 400
      assert JSON.decode!(conn.resp_body)["error"] == "invalid_request"
    end

    test "the default (generic) policy still stores a plain PAR with no request object" do
      # Generic OpenID Connect §6.1: signed request objects are optional, so a
      # plain PAR remains valid and is stored.
      params = auth_params()
      credentials = Base.encode64("confidential-1:s3cr3t")

      conn =
        :post
        |> conn(@endpoint_path, params)
        |> Plug.Conn.put_req_header("authorization", "Basic " <> credentials)
        |> PARController.create(params)

      assert conn.status == 201
    end

    test "stores the verified request-object params, not the unsigned body params (RFC 9101 §6.3)" do
      request_key = JOSE.JWK.generate_key({:ec, "P-256"})

      put_config(client_jwks: fn %{id: "confidential-1"} -> %{"keys" => [public_jwk(request_key)]} end)

      # The signed object grants only "openid"; the unsigned body claims more and
      # carries a state the object omits. The stored record must reflect the
      # signed object, never the unsigned body values.
      request =
        signed_request_object(
          request_key,
          "confidential-1",
          Map.put(request_claims(), "scope", "openid")
        )

      params =
        Map.merge(auth_params(), %{"request" => request, "scope" => "openid profile admin"})

      credentials = Base.encode64("confidential-1:s3cr3t")

      conn =
        :post
        |> conn(@endpoint_path, params)
        |> Plug.Conn.put_req_header("authorization", "Basic " <> credentials)
        |> PARController.create(params)

      assert conn.status == 201
      assert {:ok, stored, 45} = PARStore.lookup(JSON.decode!(conn.resp_body)["request_uri"])
      assert stored["scope"] == "openid"
      refute Map.has_key?(stored, "state")
    end

    test "a signed dpop_jkt that disagrees with the presented DPoP proof is rejected" do
      # RFC 9101 §6.3 + RFC 9449: the signed request object's dpop_jkt is
      # authoritative, so a presented proof for a different key is a mismatch -
      # the body's (absent) dpop_jkt must not let the proof override the signed
      # value. Verifying the object before DPoP reconciliation makes this so.
      request_key = JOSE.JWK.generate_key({:ec, "P-256"})

      put_config(client_jwks: fn %{id: "confidential-1"} -> %{"keys" => [public_jwk(request_key)]} end)

      {proof, _proof_jkt} = dpop_proof()
      signed_jkt = JOSE.JWK.thumbprint(JOSE.JWK.generate_key({:ec, "P-256"}))

      request =
        signed_request_object(
          request_key,
          "confidential-1",
          Map.put(request_claims(), "dpop_jkt", signed_jkt)
        )

      params = Map.put(auth_params(), "request", request)
      credentials = Base.encode64("confidential-1:s3cr3t")

      conn =
        params
        |> https_post()
        |> Plug.Conn.put_req_header("authorization", "Basic " <> credentials)
        |> Plug.Conn.put_req_header("dpop", proof)
        |> PARController.create(params)

      assert conn.status == 400
      assert JSON.decode!(conn.resp_body)["error"] == "invalid_dpop_proof"
    end

    test "rejects a signed request object when the client has no JWKS configured (fail closed)" do
      request_key = JOSE.JWK.generate_key({:ec, "P-256"})

      # The default (generic) policy permits a host with no :client_jwks (request
      # objects are optional), but a request object that IS pushed still has no
      # key to verify against, so it is rejected rather than trusted. (A policy
      # that REQUIRES request objects without :client_jwks is rejected at boot;
      # see AttestoPhoenix.ConfigTest.)

      request =
        signed_request_object(request_key, "confidential-1", request_claims(), %{
          "typ" => "oauth-authz-req+jwt"
        })

      conn = par_with_request_object(request)

      assert conn.status == 400
      assert JSON.decode!(conn.resp_body)["error"] == "invalid_request_object"
    end
  end

  defp request_claims do
    now = System.system_time(:second)

    %{
      "iss" => "confidential-1",
      "aud" => "https://issuer.example",
      "client_id" => "confidential-1",
      "redirect_uri" => "https://client.example/cb",
      "response_type" => "code",
      "scope" => "openid",
      "code_challenge" => "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM",
      "code_challenge_method" => "S256",
      "nbf" => now,
      "exp" => now + 300
    }
  end

  defp signed_request_object(jwk, _client_id, claims, header_overrides \\ %{}) do
    header = Map.merge(%{"alg" => "ES256", "kid" => JOSE.JWK.thumbprint(jwk)}, header_overrides)
    {_header, compact} = jwk |> JOSE.JWT.sign(header, claims) |> JOSE.JWS.compact()
    compact
  end

  defp par_with_request_object(request) do
    params = Map.put(auth_params(), "request", request)
    credentials = Base.encode64("confidential-1:s3cr3t")

    :post
    |> conn(@endpoint_path, params)
    |> Plug.Conn.put_req_header("authorization", "Basic " <> credentials)
    |> PARController.create(params)
  end

  defp auth_params do
    %{
      "client_id" => "confidential-1",
      "redirect_uri" => "https://client.example/cb",
      "response_type" => "code",
      "scope" => "openid profile",
      "state" => "state-123",
      "nonce" => "nonce-123",
      # PKCE is required (RFC 7636 / RFC 9700 §2.1.1); the PAR endpoint enforces
      # it at push time, so a complete pushed request carries it.
      "code_challenge" => "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM",
      "code_challenge_method" => "S256"
    }
  end

  defp https_post(params) do
    %Plug.Conn{} = base = conn(:post, @endpoint_path, params)
    %{base | scheme: :https, host: "issuer.example", port: 443}
  end

  defp dpop_proof do
    jwk = JOSE.JWK.generate_key({:ec, "P-256"})
    {_, public_jwk} = JOSE.JWK.to_public_map(jwk)

    payload = %{
      "htm" => "POST",
      "htu" => "https://issuer.example/oauth/par",
      "iat" => System.system_time(:second),
      "jti" => Base.url_encode64(:crypto.strong_rand_bytes(16), padding: false)
    }

    header = %{"alg" => "ES256", "typ" => "dpop+jwt", "jwk" => public_jwk}
    {_header, compact} = jwk |> JOSE.JWT.sign(header, payload) |> JOSE.JWS.compact()
    {compact, JOSE.JWK.thumbprint(jwk)}
  end

  defp client_assertion(jwk, client_id, overrides \\ %{}) do
    now = System.system_time(:second)

    claims =
      Map.merge(
        %{
          "iss" => client_id,
          "sub" => client_id,
          "aud" => "https://issuer.example",
          "iat" => now,
          "exp" => now + 60,
          "jti" => Base.url_encode64(:crypto.strong_rand_bytes(16), padding: false)
        },
        overrides
      )

    header = %{"alg" => "ES256", "kid" => JOSE.JWK.thumbprint(jwk)}
    {_header, compact} = jwk |> JOSE.JWT.sign(header, claims) |> JOSE.JWS.compact()
    compact
  end

  defp public_jwk(jwk) do
    {_kty, map} = JOSE.JWK.to_public_map(jwk)
    Map.merge(map, %{"kid" => JOSE.JWK.thumbprint(jwk), "alg" => "ES256", "use" => "sig"})
  end

  defp replay_once do
    fn key, _ttl ->
      process_key = {:client_assertion_replay, key}

      if Process.get(process_key) do
        {:error, :replay}
      else
        Process.put(process_key, true)
        :ok
      end
    end
  end

  @config_keys [AttestoPhoenix, AttestoPhoenix.Config]

  defp put_config(overrides) do
    prev_otp = Application.get_env(:attesto_phoenix, :otp_app)
    Application.put_env(:attesto_phoenix, :otp_app, :attesto_phoenix)

    for key <- @config_keys do
      current = Application.get_env(:attesto_phoenix, key, [])
      Application.put_env(:attesto_phoenix, key, Keyword.merge(current, overrides))
    end

    on_exit(fn ->
      for key <- @config_keys, do: Application.delete_env(:attesto_phoenix, key)

      if prev_otp do
        Application.put_env(:attesto_phoenix, :otp_app, prev_otp)
      else
        Application.delete_env(:attesto_phoenix, :otp_app)
      end
    end)
  end
end
