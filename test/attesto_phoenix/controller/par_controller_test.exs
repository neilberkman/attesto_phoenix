defmodule AttestoPhoenix.Controller.PARControllerTest do
  use ExUnit.Case, async: false

  import Plug.Test

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
        "client_assertion" =>
          client_assertion(client_key, "confidential-1", %{"aud" => "https://issuer.example"})
      })

    conn =
      :post
      |> conn(@endpoint_path, params)
      |> PARController.create(params)

    assert conn.status == 201
  end

  test "rejects private_key_jwt assertion audience that is not the issuer" do
    client_key = JOSE.JWK.generate_key({:ec, "P-256"})
    client_jwks = %{"keys" => [public_jwk(client_key)]}

    put_config(client_jwks: fn %{id: "confidential-1"} -> client_jwks end)

    params =
      Map.merge(auth_params(), %{
        "client_assertion_type" => Attesto.ClientAssertion.assertion_type(),
        "client_assertion" =>
          client_assertion(client_key, "confidential-1", %{"aud" => "https://other.example"})
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

  defp auth_params do
    %{
      "client_id" => "confidential-1",
      "redirect_uri" => "https://client.example/cb",
      "response_type" => "code",
      "scope" => "openid profile",
      "state" => "state-123",
      "nonce" => "nonce-123"
    }
  end

  defp https_post(params) do
    %Plug.Conn{} = base = conn(:post, @endpoint_path, params)
    %Plug.Conn{base | scheme: :https, host: "issuer.example", port: 443}
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
