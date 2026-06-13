defmodule AttestoPhoenix.AuthorizationServer.SenderConstraintTest do
  @moduledoc """
  Direct unit tests for the conn-free sender-constraint core
  (RFC 9449 / RFC 8705).

  These exercise `AttestoPhoenix.AuthorizationServer.SenderConstraint.resolve/3`
  against data only - the `input` map a controller builds from the request
  (`:dpop_proof`, `:mtls_cert_der`, `:http_uri`, `:http_method`) - with no conn
  involved. The focus is the precedence and fail-closed policy (RFC 9449 §5,
  RFC 8705 §3) and, critically, that a required-but-absent DPoP nonce surfaces
  as a `use_dpop_nonce` `OAuthError` carrying the fresh `DPoP-Nonce` value in
  its `:headers` so the controller can render the header verbatim
  (RFC 9449 §8 / §9).
  """
  use ExUnit.Case, async: false

  alias Attesto.DPoP.NonceStore.ETS
  alias AttestoPhoenix.AuthorizationServer.SenderConstraint
  alias AttestoPhoenix.{Config, OAuthError}

  @htu "https://issuer.example/oauth/token"
  @htm "POST"

  # A client whose binding requirements are read through the config callbacks.
  @plain %{id: "plain-1"}
  @dpop_required %{id: "dpop-1"}
  @mtls_required %{id: "mtls-1"}

  defmodule StubKeystore do
    @moduledoc false
  end

  defmodule StubRepo do
    @moduledoc false
  end

  # The `%Config{}` enforced keys the sender-constraint core never reads;
  # supplied as inert stubs so a valid struct can be built for these data tests.
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

  defp base_config(overrides \\ []) do
    fields =
      required_fields()
      |> Keyword.merge(
        client_requires_dpop?: fn client -> Map.get(client, :id) == "dpop-1" end,
        client_requires_mtls?: fn client -> Map.get(client, :id) == "mtls-1" end,
        client_public?: fn client -> Map.get(client, :public?, false) == true end
      )
      |> Keyword.merge(overrides)

    struct!(Config, fields)
  end

  defp bare_config, do: struct!(Config, required_fields())

  defp input(overrides) do
    %{
      dpop_proof: nil,
      mtls_cert_der: nil,
      http_uri: @htu,
      http_method: @htm
    }
    |> Map.merge(Map.new(overrides))
  end

  # A valid DPoP proof (RFC 9449 §4.2) bound to @htu/@htm, key freshly
  # generated per call; the matching `jkt` is returned for assertion.
  defp dpop_proof_and_jkt(opts \\ []) do
    nonce = Keyword.get(opts, :nonce)
    jwk = JOSE.JWK.generate_key({:ec, "P-256"})
    {_, pub_map} = JOSE.JWK.to_public_map(jwk)

    payload =
      %{
        "htm" => @htm,
        "htu" => @htu,
        "iat" => System.system_time(:second),
        "jti" => Base.url_encode64(:crypto.strong_rand_bytes(16), padding: false)
      }
      |> maybe_put("nonce", nonce)

    header = %{"alg" => "ES256", "typ" => "dpop+jwt", "jwk" => pub_map}
    {_, compact} = JOSE.JWS.compact(JOSE.JWT.sign(jwk, header, payload))
    {compact, Attesto.DPoP.compute_jkt(pub_map)}
  end

  defp maybe_put(map, _key, nil), do: map
  defp maybe_put(map, key, value), do: Map.put(map, key, value)

  defp self_signed_cert_der do
    %{cert: der} = :public_key.pkix_test_root_cert(~c"CN=attesto-test", [])
    der
  end

  describe "DPoP binding (RFC 9449 §5)" do
    test "a valid proof binds {:dpop, jkt} and the DPoP token type" do
      {proof, jkt} = dpop_proof_and_jkt()
      config = base_config(dpop_enabled: true)

      assert {:ok, {:dpop, ^jkt}, "DPoP"} =
               SenderConstraint.resolve(config, input(dpop_proof: proof), @plain)
    end

    test "DPoP takes precedence over a presented certificate (RFC 9449 §5)" do
      {proof, jkt} = dpop_proof_and_jkt()
      config = base_config(dpop_enabled: true, mtls_enabled: true)

      assert {:ok, {:dpop, ^jkt}, "DPoP"} =
               SenderConstraint.resolve(
                 config,
                 input(dpop_proof: proof, mtls_cert_der: self_signed_cert_der()),
                 @plain
               )
    end

    test "a malformed proof is rejected with invalid_dpop_proof" do
      config = base_config(dpop_enabled: true)

      assert {:error, %OAuthError{error: :invalid_dpop_proof, status: 400}} =
               SenderConstraint.resolve(config, input(dpop_proof: "not-a-jwt"), @plain)
    end

    test "a proof is ignored when DPoP is disabled, falling back to Bearer" do
      {proof, _jkt} = dpop_proof_and_jkt()
      config = base_config(dpop_enabled: false)

      assert {:ok, :none, "Bearer"} =
               SenderConstraint.resolve(config, input(dpop_proof: proof), @plain)
    end
  end

  describe "DPoP nonce challenge (RFC 9449 §8 / §9)" do
    setup do
      store = ETS
      start_supervised!(store)
      {:ok, store: store}
    end

    test "a required-but-absent nonce yields use_dpop_nonce carrying a fresh DPoP-Nonce header",
         %{store: store} do
      {proof, _jkt} = dpop_proof_and_jkt(nonce: nil)

      config =
        base_config(dpop_enabled: true, dpop_nonce_required: true, nonce_store: store)

      assert {:error, %OAuthError{error: :use_dpop_nonce, status: 400, headers: headers}} =
               SenderConstraint.resolve(config, input(dpop_proof: proof), @plain)

      assert [{"dpop-nonce", nonce}] = headers
      assert is_binary(nonce) and nonce != ""
      assert store.valid?(nonce)
    end

    test "an invalid (stale) nonce is rejected with a fresh DPoP-Nonce header", %{store: store} do
      {proof, _jkt} = dpop_proof_and_jkt(nonce: "stale-nonce")

      config =
        base_config(dpop_enabled: true, dpop_nonce_required: true, nonce_store: store)

      assert {:error, %OAuthError{error: :use_dpop_nonce, headers: [{"dpop-nonce", fresh}]}} =
               SenderConstraint.resolve(config, input(dpop_proof: proof), @plain)

      assert store.valid?(fresh)
    end

    test "a currently-valid nonce binds DPoP", %{store: store} do
      nonce = store.issue()
      {proof, jkt} = dpop_proof_and_jkt(nonce: nonce)

      config =
        base_config(dpop_enabled: true, dpop_nonce_required: true, nonce_store: store)

      assert {:ok, {:dpop, ^jkt}, "DPoP"} =
               SenderConstraint.resolve(config, input(dpop_proof: proof), @plain)
    end
  end

  describe "mTLS binding (RFC 8705 §3)" do
    test "a presented certificate binds {:mtls, thumbprint} and keeps the Bearer type" do
      der = self_signed_cert_der()
      {:ok, thumbprint} = Attesto.MTLS.compute_thumbprint(der)
      config = base_config(mtls_enabled: true)

      assert {:ok, {:mtls, ^thumbprint}, "Bearer"} =
               SenderConstraint.resolve(config, input(mtls_cert_der: der), @plain)
    end

    test "a certificate is ignored when mTLS is disabled, falling back to Bearer" do
      config = base_config(mtls_enabled: false)

      assert {:ok, :none, "Bearer"} =
               SenderConstraint.resolve(
                 config,
                 input(mtls_cert_der: self_signed_cert_der()),
                 @plain
               )
    end

    test "an unparseable certificate is rejected with invalid_client" do
      config = base_config(mtls_enabled: true)

      assert {:error, %OAuthError{error: :invalid_client}} =
               SenderConstraint.resolve(config, input(mtls_cert_der: "not-a-cert"), @plain)
    end
  end

  describe "unbound Bearer and required-constraint refusal" do
    test "no constraint presented and none required yields an unbound Bearer" do
      config = base_config(dpop_enabled: true, mtls_enabled: true)

      assert {:ok, :none, "Bearer"} = SenderConstraint.resolve(config, input([]), @plain)
    end

    test "a DPoP-required client calling without a proof is refused (RFC 9449)" do
      config = base_config(dpop_enabled: true, mtls_enabled: true)

      assert {:error, %OAuthError{error: :invalid_request}} =
               SenderConstraint.resolve(config, input([]), @dpop_required)
    end

    test "an mTLS-required client calling without a certificate is refused (RFC 8705 §3)" do
      config = base_config(dpop_enabled: true, mtls_enabled: true)

      assert {:error, %OAuthError{error: :invalid_client}} =
               SenderConstraint.resolve(config, input([]), @mtls_required)
    end

    test "binding requirements fail open to not-required when callbacks are absent" do
      config = bare_config()

      assert {:ok, :none, "Bearer"} =
               SenderConstraint.resolve(config, input([]), @dpop_required)
    end
  end

  describe "mint_opts/1" do
    test "maps each binding to the Attesto.Token confirmation opt" do
      assert SenderConstraint.mint_opts(:none) == []
      assert SenderConstraint.mint_opts({:dpop, "jkt-abc"}) == [dpop_jkt: "jkt-abc"]
      assert SenderConstraint.mint_opts({:mtls, "x5t-abc"}) == [mtls_cert_thumbprint: "x5t-abc"]
    end
  end

  describe "binding_jkt/1" do
    test "returns the DPoP thumbprint only for a DPoP binding" do
      assert SenderConstraint.binding_jkt({:dpop, "jkt-abc"}) == "jkt-abc"
      assert SenderConstraint.binding_jkt({:mtls, "x5t-abc"}) == nil
      assert SenderConstraint.binding_jkt(:none) == nil
    end
  end

  describe "refresh_binding_jkt/3" do
    test "public clients carry the DPoP thumbprint onto the refresh token (RFC 9449 §8)" do
      config = base_config()
      public = %{id: "p", public?: true}

      assert SenderConstraint.refresh_binding_jkt(config, public, {:dpop, "jkt-abc"}) == "jkt-abc"
    end

    test "confidential clients do not bind the refresh token to a DPoP key (RFC 6749 §6)" do
      config = base_config()
      confidential = %{id: "c", public?: false}

      assert SenderConstraint.refresh_binding_jkt(config, confidential, {:dpop, "jkt-abc"}) == nil
    end

    test "an mTLS binding never threads a DPoP thumbprint, even for a public client" do
      config = base_config()
      public = %{id: "p", public?: true}

      assert SenderConstraint.refresh_binding_jkt(config, public, {:mtls, "x5t-abc"}) == nil
    end
  end

  describe "client_requires_dpop?/2 and client_requires_mtls?/2" do
    test "read the config callbacks, failing open when absent" do
      config = base_config()
      bare = bare_config()

      assert SenderConstraint.client_requires_dpop?(config, @dpop_required)
      refute SenderConstraint.client_requires_dpop?(config, @plain)
      refute SenderConstraint.client_requires_dpop?(bare, @dpop_required)

      assert SenderConstraint.client_requires_mtls?(config, @mtls_required)
      refute SenderConstraint.client_requires_mtls?(config, @plain)
      refute SenderConstraint.client_requires_mtls?(bare, @mtls_required)
    end
  end
end
