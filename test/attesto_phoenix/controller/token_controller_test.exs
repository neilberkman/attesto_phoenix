defmodule AttestoPhoenix.Controller.TokenControllerTest do
  @moduledoc """
  Tests for the OAuth 2.0 token endpoint (RFC 6749 §3.2).

  These exercise the controller-owned protocol framing: client authentication
  (RFC 6749 §2.3), grant-type validation (RFC 6749 §4), no-store cache headers
  (RFC 7234 §5.2), and RFC 6749 §5.2 error rendering. Cryptographic grant
  state (code redemption, refresh rotation, token minting) belongs to the
  `Attesto` core and is covered by that library's own suite; here those paths
  are reached only far enough to confirm the controller dispatches and frames
  them correctly.

  Host policy is supplied as a real `%AttestoPhoenix.Config{}` resolved from
  the application environment, exactly as a deployment supplies it, so no live
  datastore is required.
  """
  use ExUnit.Case, async: false

  import Plug.Test
  import Plug.Conn

  alias AttestoPhoenix.Controller.TokenController

  @endpoint_path "/oauth/token"

  # PKCE (RFC 7636) verifier/challenge pair: challenge = b64url(sha256(verifier)).
  @code_verifier "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
  @code_challenge "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"
  @redirect_uri "https://client.example/cb"

  # A throwaway RSA keypair generated once for this test module. Used by the
  # paths that actually mint a token (public-client success, mTLS binding,
  # initial refresh issuance), where a real signing key is required. Stashed
  # in the application env so the inline keystore can read it without any
  # committed key material.
  @signing_pem JOSE.JWK.generate_key({:rsa, 2048}) |> JOSE.JWK.to_pem() |> elem(1)

  # An inline `Attesto.Keystore` that publishes the module's throwaway key.
  defmodule Keystore do
    @moduledoc false
    @behaviour Attesto.Keystore

    @impl true
    def signing_pem do
      :attesto_phoenix
      |> Application.fetch_env!(__MODULE__)
      |> Keyword.fetch!(:signing_pem)
    end

    @impl true
    def verification_pems, do: [signing_pem()]
  end

  # A reuse-tracking `Attesto.CodeStore` (OAuth 2.0 Security BCP §4.13). Unlike
  # the bundled `Attesto.CodeStore.ETS`, it implements the OPTIONAL
  # reuse-tracking pair: `take/1` returns `{:error, :consumed, meta}` for a code
  # that was already successfully redeemed, and `mark_consumed/2` records the
  # `family_id`/`subject` of that first redemption. This is what lets the token
  # controller's reuse branch fire and revoke the descendant family. State lives
  # in two ETS tables keyed by code hash: live codes and consumed-markers.
  defmodule ReuseCodeStore do
    @moduledoc false
    @behaviour Attesto.CodeStore

    @live :"#{__MODULE__}.Live"
    @consumed :"#{__MODULE__}.Consumed"
    @access_tokens :"#{__MODULE__}.AccessTokens"

    def reset do
      for table <- [@live, @consumed, @access_tokens] do
        if :ets.whereis(table) == :undefined do
          :ets.new(table, [:set, :public, :named_table])
        else
          :ets.delete_all_objects(table)
        end
      end

      :ok
    end

    @impl true
    def put(%{code_hash: code_hash} = record) do
      true = :ets.insert(@live, {code_hash, record})
      :ok
    end

    @impl true
    def take(code_hash) do
      case :ets.take(@live, code_hash) do
        [{^code_hash, record}] ->
          {:ok, record}

        [] ->
          # OAuth 2.0 Security BCP §4.13: distinguish an already-redeemed code
          # (reuse) from a never-issued one via the consumed-marker table.
          case :ets.lookup(@consumed, code_hash) do
            [{^code_hash, meta}] -> {:error, :consumed, meta}
            [] -> :error
          end
      end
    end

    @impl true
    def mark_consumed(code_hash, meta) do
      true = :ets.insert(@consumed, {code_hash, meta})
      :ok
    end

    def record_access_token(family_id, jti, _expires_at) do
      true = :ets.insert(@access_tokens, {{:token, family_id}, jti})
      :ok
    end

    def revoke_family_access_tokens(family_id) do
      for {{:token, ^family_id}, jti} <- :ets.tab2list(@access_tokens) do
        true = :ets.insert(@access_tokens, {{:revoked, jti}, true})
      end

      :ok
    end

    def access_token_revoked?(jti) do
      :ets.lookup(@access_tokens, {:revoked, jti}) != []
    end
  end

  # One principal kind so `Attesto.Token.mint/3` has a kind to issue under.
  @client_kind Attesto.PrincipalKind.new("client", "oc_",
                 required_claims: [{"client_id", :non_empty_string}]
               )

  # Opaque client values; only the configured callbacks interpret them. A
  # client carrying `public?: true` is a public client (RFC 6749 §2.1): it
  # authenticates without a secret and leans on PKCE.
  @public_client %{id: "public-1", public?: true}
  @confidential_client %{id: "confidential-1", secret: "s3cr3t"}

  setup do
    Application.put_env(:attesto_phoenix, __MODULE__.Keystore, signing_pem: @signing_pem)
    on_exit(fn -> Application.delete_env(:attesto_phoenix, __MODULE__.Keystore) end)

    clients =
      Map.new([@public_client, @confidential_client], &{&1.id, &1})

    base = [
      issuer: "https://issuer.example",
      # Derived into the protocol `Attesto.Config` by the minting paths; the
      # core requires a non-empty audience, so the token-minting tests need it.
      audience: "https://issuer.example",
      keystore: __MODULE__.Keystore,
      repo: __MODULE__.Repo,
      # RFC 6749 §2.3: lookup carries existence and the revocation gate. A
      # `revoked-1` lookup reports `{:error, :revoked}`.
      load_client: fn
        "revoked-1" -> {:error, :revoked}
        id -> client_lookup(clients, id)
      end,
      # RFC 6749 §2.3.1: constant-time secret check.
      verify_client_secret: fn
        %{secret: s}, given -> s == given
        _no_secret, _given -> false
      end,
      # RFC 6749 §2.1: the public/confidential discriminator. Only a client
      # flagged `public?: true` may authenticate without a secret.
      client_public?: fn client -> Map.get(client, :public?, false) end,
      # RFC 6749 §3.3: grant exactly what was requested (the tests don't
      # exercise scope policy, only that the granted scope round-trips).
      authorize_scope: fn _client, requested -> {:ok, requested} end,
      load_principal: fn _ -> {:error, :not_found} end,
      # The endpoint is exercised over plain Plug.Test conns, so disable the
      # transport requirement for these protocol-framing tests.
      require_https: false,
      replay_check: fn _key, _ttl -> :ok end
    ]

    put_config(base)
    :ok
  end

  describe "client authentication (RFC 6749 §2.3)" do
    test "rejects a request with no client credentials" do
      conn = post_token(%{"grant_type" => "client_credentials"})

      assert conn.status == 400
      assert body(conn)["error"] == "invalid_client"
    end

    test "rejects an unknown client without revealing its absence" do
      conn =
        post_token(%{
          "grant_type" => "client_credentials",
          "client_id" => "does-not-exist",
          "client_secret" => "whatever"
        })

      assert conn.status == 400
      # RFC 6749 §2.3 / OWASP: identical message to the wrong-secret path.
      assert body(conn)["error"] == "invalid_client"
      assert body(conn)["error_description"] == "client authentication failed"
    end

    test "rejects a wrong client secret" do
      conn =
        post_token(%{
          "grant_type" => "client_credentials",
          "client_id" => "confidential-1",
          "client_secret" => "wrong"
        })

      assert conn.status == 400
      assert body(conn)["error"] == "invalid_client"
      assert body(conn)["error_description"] == "client authentication failed"
    end

    test "rejects a revoked client (RFC 7009)" do
      conn =
        post_token(%{
          "grant_type" => "client_credentials",
          "client_id" => "revoked-1",
          "client_secret" => "anything"
        })

      assert conn.status == 400
      assert body(conn)["error"] == "invalid_client"
      # Same generic message as unknown/wrong-secret: no existence oracle.
      assert body(conn)["error_description"] == "client authentication failed"
    end

    test "accepts HTTP Basic credentials (RFC 6749 §2.3.1)" do
      credentials = Base.encode64("confidential-1:s3cr3t")

      conn =
        :post
        |> conn(@endpoint_path, %{"grant_type" => "unsupported"})
        |> put_req_header("authorization", "Basic " <> credentials)
        |> TokenController.create(%{"grant_type" => "unsupported"})

      # Authentication succeeded; only the grant type is rejected downstream.
      assert body(conn)["error"] == "unsupported_grant_type"
    end

    test "url-decodes Basic credentials per application/x-www-form-urlencoded" do
      clients = %{"sp ace" => %{id: "sp ace", secret: "p:w"}}

      put_config(
        load_client: fn id -> client_lookup(clients, id) end,
        verify_client_secret: fn
          %{secret: s}, given -> s == given
          _no_secret, _given -> false
        end
      )

      credentials = Base.encode64("sp%20ace:p%3Aw")

      conn =
        :post
        |> conn(@endpoint_path, %{"grant_type" => "unsupported"})
        |> put_req_header("authorization", "Basic " <> credentials)
        |> TokenController.create(%{"grant_type" => "unsupported"})

      assert body(conn)["error"] == "unsupported_grant_type"
    end

    test "rejects credentials presented by both Basic and body (RFC 6749 §2.3)" do
      credentials = Base.encode64("confidential-1:s3cr3t")
      params = %{"grant_type" => "client_credentials", "client_id" => "confidential-1"}

      conn =
        :post
        |> conn(@endpoint_path, params)
        |> put_req_header("authorization", "Basic " <> credentials)
        |> TokenController.create(params)

      assert conn.status == 400
      assert body(conn)["error"] == "invalid_request"
    end

    test "accepts private_key_jwt client authentication" do
      client_key = JOSE.JWK.generate_key({:ec, "P-256"})
      client_jwks = %{"keys" => [public_jwk(client_key)]}

      put_config(client_jwks: fn %{id: "confidential-1"} -> client_jwks end)

      assertion = client_assertion(client_key, "confidential-1")

      conn =
        post_token(%{
          "grant_type" => "unsupported",
          "client_assertion_type" => Attesto.ClientAssertion.assertion_type(),
          "client_assertion" => assertion
        })

      # Authentication succeeded; only the grant type is rejected downstream.
      assert body(conn)["error"] == "unsupported_grant_type"
    end

    test "accepts private_key_jwt assertion audience set to issuer" do
      client_key = JOSE.JWK.generate_key({:ec, "P-256"})
      client_jwks = %{"keys" => [public_jwk(client_key)]}

      put_config(client_jwks: fn %{id: "confidential-1"} -> client_jwks end)

      assertion =
        client_assertion(client_key, "confidential-1", %{"aud" => "https://issuer.example"})

      conn =
        post_token(%{
          "grant_type" => "unsupported",
          "client_assertion_type" => Attesto.ClientAssertion.assertion_type(),
          "client_assertion" => assertion
        })

      assert body(conn)["error"] == "unsupported_grant_type"
    end

    test "rejects private_key_jwt assertion audience outside issuer and token endpoint" do
      client_key = JOSE.JWK.generate_key({:ec, "P-256"})
      client_jwks = %{"keys" => [public_jwk(client_key)]}

      put_config(client_jwks: fn %{id: "confidential-1"} -> client_jwks end)

      assertion =
        client_assertion(client_key, "confidential-1", %{"aud" => "https://other.example"})

      conn =
        post_token(%{
          "grant_type" => "unsupported",
          "client_assertion_type" => Attesto.ClientAssertion.assertion_type(),
          "client_assertion" => assertion
        })

      assert conn.status == 400
      assert body(conn)["error"] == "invalid_client"
    end

    test "rejects replayed private_key_jwt assertions" do
      client_key = JOSE.JWK.generate_key({:ec, "P-256"})
      client_jwks = %{"keys" => [public_jwk(client_key)]}

      put_config(
        client_jwks: fn %{id: "confidential-1"} -> client_jwks end,
        replay_check: replay_once()
      )

      assertion = client_assertion(client_key, "confidential-1")

      params = %{
        "grant_type" => "unsupported",
        "client_assertion_type" => Attesto.ClientAssertion.assertion_type(),
        "client_assertion" => assertion
      }

      first = post_token(params)
      assert body(first)["error"] == "unsupported_grant_type"

      second = post_token(params)
      assert second.status == 400
      assert body(second)["error"] == "invalid_client"
      assert body(second)["error_description"] == "client authentication failed"
    end

    test "rejects client_secret_basic when configured for private_key_jwt only" do
      put_config(token_endpoint_auth_methods_supported: ["private_key_jwt"])

      credentials = Base.encode64("confidential-1:s3cr3t")

      conn =
        :post
        |> conn(@endpoint_path, %{"grant_type" => "client_credentials"})
        |> put_req_header("authorization", "Basic " <> credentials)
        |> TokenController.create(%{"grant_type" => "client_credentials"})

      assert conn.status == 400
      assert body(conn)["error"] == "invalid_client"
    end

    test "allows private_key_jwt when configured for private_key_jwt only" do
      client_key = JOSE.JWK.generate_key({:ec, "P-256"})
      client_jwks = %{"keys" => [public_jwk(client_key)]}

      put_config(
        token_endpoint_auth_methods_supported: ["private_key_jwt"],
        client_jwks: fn %{id: "confidential-1"} -> client_jwks end
      )

      assertion = client_assertion(client_key, "confidential-1")

      conn =
        post_token(%{
          "grant_type" => "unsupported",
          "client_assertion_type" => Attesto.ClientAssertion.assertion_type(),
          "client_assertion" => assertion
        })

      assert body(conn)["error"] == "unsupported_grant_type"
    end

    test "rejects private_key_jwt with a mismatched trusted client key" do
      assertion = client_assertion(JOSE.JWK.generate_key({:ec, "P-256"}), "confidential-1")
      other_key = JOSE.JWK.generate_key({:ec, "P-256"})

      put_config(
        client_jwks: fn %{id: "confidential-1"} -> %{"keys" => [public_jwk(other_key)]} end
      )

      conn =
        post_token(%{
          "grant_type" => "client_credentials",
          "client_assertion_type" => Attesto.ClientAssertion.assertion_type(),
          "client_assertion" => assertion
        })

      assert conn.status == 400
      assert body(conn)["error"] == "invalid_client"
      assert body(conn)["error_description"] == "client authentication failed"
    end

    test "rejects a malformed Basic header" do
      conn =
        :post
        |> conn(@endpoint_path, %{"grant_type" => "client_credentials"})
        |> put_req_header("authorization", "Basic not-base64!!")
        |> TokenController.create(%{"grant_type" => "client_credentials"})

      assert conn.status == 400
      assert body(conn)["error"] == "invalid_client"
    end

    test "rejects an unsupported authorization scheme" do
      conn =
        :post
        |> conn(@endpoint_path, %{"grant_type" => "client_credentials"})
        |> put_req_header("authorization", "Bearer abc")
        |> TokenController.create(%{"grant_type" => "client_credentials"})

      assert conn.status == 400
      assert body(conn)["error"] == "invalid_client"
    end
  end

  describe "grant-type validation (RFC 6749 §4)" do
    test "rejects a missing grant_type" do
      conn = post_token(%{"client_id" => "confidential-1", "client_secret" => "s3cr3t"})

      assert conn.status == 400
      assert body(conn)["error"] == "invalid_request"
      assert body(conn)["error_description"] == "missing grant_type"
    end

    test "rejects an unsupported grant_type (RFC 6749 §5.2)" do
      conn =
        post_token(%{
          "grant_type" => "password",
          "client_id" => "confidential-1",
          "client_secret" => "s3cr3t"
        })

      assert conn.status == 400
      assert body(conn)["error"] == "unsupported_grant_type"
    end

    test "authorization_code without a code_verifier is rejected (PKCE mandatory)" do
      conn =
        post_token(%{
          "grant_type" => "authorization_code",
          "client_id" => "public-1",
          "code" => "abc",
          "redirect_uri" => "https://client.example/cb"
        })

      assert conn.status == 400
      assert body(conn)["error"] == "invalid_request"
      assert body(conn)["error_description"] =~ "code_verifier"
    end

    test "confidential authorization_code may omit code_verifier when host relaxes PKCE" do
      enable_minting()
      code_store = start_unbound_confidential_code_store("oc_sub-1", ["openid"])
      put_config(code_store: code_store, require_pkce: false)

      conn =
        post_token(%{
          "grant_type" => "authorization_code",
          "client_id" => "confidential-1",
          "client_secret" => "s3cr3t",
          "code" => Process.get(:auth_code),
          "redirect_uri" => @redirect_uri
        })

      assert conn.status == 200
      assert is_binary(body(conn)["access_token"])
      assert is_binary(body(conn)["id_token"])
    end

    test "refresh_token grant without a token is rejected" do
      conn =
        post_token(%{
          "grant_type" => "refresh_token",
          "client_id" => "confidential-1",
          "client_secret" => "s3cr3t"
        })

      assert conn.status == 400
      assert body(conn)["error"] == "invalid_request"
      assert body(conn)["error_description"] =~ "refresh_token"
    end

    test "rejects grants not registered for the authenticated client" do
      put_config(client_grant_types: fn %{id: "confidential-1"} -> ["authorization_code"] end)

      conn =
        post_token(%{
          "grant_type" => "client_credentials",
          "client_id" => "confidential-1",
          "client_secret" => "s3cr3t"
        })

      assert conn.status == 400
      assert body(conn)["error"] == "unsupported_grant_type"
    end
  end

  describe "response framing" do
    test "every response carries no-store cache headers (RFC 7234 §5.2)" do
      conn = post_token(%{"grant_type" => "client_credentials"})

      assert get_resp_header(conn, "cache-control") == ["no-store"]
      assert get_resp_header(conn, "pragma") == ["no-cache"]
    end

    test "the use_dpop_nonce error also carries no-store headers" do
      start_nonce_store()

      put_config(
        dpop_enabled: true,
        dpop_nonce_required: true,
        nonce_store: Attesto.DPoP.NonceStore.ETS
      )

      conn = post_dpop("client_credentials", dpop_proof(nonce: nil))

      assert body(conn)["error"] == "use_dpop_nonce"
      assert get_resp_header(conn, "cache-control") == ["no-store"]
      assert get_resp_header(conn, "pragma") == ["no-cache"]
    end
  end

  describe "denial events" do
    test "emits token_denied for invalid client authentication" do
      capture_events()

      conn =
        post_token(%{
          "grant_type" => "client_credentials",
          "client_id" => "confidential-1",
          "client_secret" => "wrong",
          "scope" => "read"
        })

      assert conn.status == 400

      assert_receive {:event,
                      %AttestoPhoenix.Event{
                        name: :token_denied,
                        client_id: "confidential-1",
                        grant_type: "client_credentials",
                        scope: "read",
                        result: "invalid_client",
                        metadata: metadata
                      }}

      assert metadata.error == "invalid_client"
      assert metadata.http_status == 400
      assert metadata.sender_constraint == %{dpop_present: false, mtls_cert_present: false}
    end

    test "emits token_denied when a valid client omits grant_type" do
      capture_events()

      conn =
        post_token(%{
          "client_id" => "confidential-1",
          "client_secret" => "s3cr3t",
          "scope" => "read"
        })

      assert conn.status == 400

      assert_receive {:event,
                      %AttestoPhoenix.Event{
                        name: :token_denied,
                        client_id: "confidential-1",
                        grant_type: nil,
                        scope: "read",
                        result: "invalid_request"
                      }}
    end

    test "emits token_denied for unsupported grants after client authentication" do
      capture_events()

      conn =
        post_token(%{
          "grant_type" => "password",
          "client_id" => "confidential-1",
          "client_secret" => "s3cr3t"
        })

      assert conn.status == 400

      assert_receive {:event,
                      %AttestoPhoenix.Event{
                        name: :token_denied,
                        client_id: "confidential-1",
                        grant_type: "password",
                        result: "unsupported_grant_type"
                      }}
    end

    test "emits token_denied for invalid scope decisions" do
      capture_events()
      enable_minting()
      put_config(authorize_scope: fn _client, _requested -> {:error, :invalid_scope} end)

      conn =
        post_token(%{
          "grant_type" => "client_credentials",
          "client_id" => "public-1",
          "scope" => "admin"
        })

      assert conn.status == 400

      assert_receive {:event,
                      %AttestoPhoenix.Event{
                        name: :token_denied,
                        client_id: "public-1",
                        grant_type: "client_credentials",
                        scope: "admin",
                        result: "invalid_scope"
                      }}
    end
  end

  # FIX 1 - PUBLIC-CLIENT ENFORCEMENT (RFC 6749 §2.1 / §2.3.1).
  describe "public-client enforcement (RFC 6749 §2.1)" do
    test "a confidential client cannot authenticate with client_id and no secret" do
      enable_minting()

      # `confidential-1` is NOT public; presenting only its client_id (no
      # secret) must be rejected, not admitted as a public client.
      conn =
        post_token(%{
          "grant_type" => "client_credentials",
          "client_id" => "confidential-1"
        })

      assert conn.status == 400
      assert body(conn)["error"] == "invalid_client"
      assert body(conn)["error_description"] == "client authentication failed"
    end

    test "a public client is admitted secretless and gets a token" do
      enable_minting()

      conn =
        post_token(%{
          "grant_type" => "client_credentials",
          "client_id" => "public-1",
          "scope" => "read"
        })

      assert conn.status == 200
      assert is_binary(body(conn)["access_token"])
      assert body(conn)["token_type"] == "Bearer"
    end

    test "fails closed when :client_public? is not configured" do
      enable_minting()
      # Remove the discriminator: every client must then be treated as
      # confidential, so a secretless request is rejected.
      put_config(client_public?: nil)

      conn =
        post_token(%{
          "grant_type" => "client_credentials",
          "client_id" => "public-1"
        })

      assert conn.status == 400
      assert body(conn)["error"] == "invalid_client"
    end
  end

  # FIX 2 - mTLS BINDING (RFC 8705).
  describe "mTLS certificate binding (RFC 8705)" do
    test "binds cnf.x5t#S256 to the presented certificate thumbprint" do
      enable_minting()
      der = self_signed_cert_der()
      {:ok, thumbprint} = Attesto.MTLS.compute_thumbprint(der)

      put_config(
        mtls_enabled: true,
        cert_der: fn _conn -> der end,
        client_requires_mtls?: fn _client -> true end
      )

      conn =
        post_token(%{
          "grant_type" => "client_credentials",
          "client_id" => "public-1",
          "scope" => "read"
        })

      assert conn.status == 200
      # RFC 8705 §3.1: mTLS-bound tokens keep the Bearer type.
      assert body(conn)["token_type"] == "Bearer"

      claims = peek_claims(body(conn)["access_token"])
      assert get_in(claims, ["cnf", "x5t#S256"]) == thumbprint
    end

    test "an mTLS-required client calling without a certificate is rejected, not downgraded" do
      enable_minting()

      put_config(
        mtls_enabled: true,
        cert_der: fn _conn -> nil end,
        client_requires_mtls?: fn _client -> true end
      )

      conn =
        post_token(%{
          "grant_type" => "client_credentials",
          "client_id" => "public-1"
        })

      assert conn.status == 400
      assert body(conn)["error"] == "invalid_client"
      assert body(conn)["error_description"] =~ "certificate"
    end
  end

  # FIX 3 - DPoP NONCE (RFC 9449 §8/§9).
  describe "DPoP nonce enforcement (RFC 9449 §8)" do
    test "a required-but-absent nonce yields use_dpop_nonce with a fresh DPoP-Nonce header" do
      enable_minting()
      start_nonce_store()

      put_config(
        dpop_enabled: true,
        dpop_nonce_required: true,
        nonce_store: Attesto.DPoP.NonceStore.ETS
      )

      conn = post_dpop("client_credentials", dpop_proof(nonce: nil))

      assert conn.status == 400
      assert body(conn)["error"] == "use_dpop_nonce"
      assert [nonce] = get_resp_header(conn, "dpop-nonce")
      assert nonce != ""
    end

    test "an invalid nonce is rejected with a fresh DPoP-Nonce header" do
      enable_minting()
      start_nonce_store()

      put_config(
        dpop_enabled: true,
        dpop_nonce_required: true,
        nonce_store: Attesto.DPoP.NonceStore.ETS
      )

      conn = post_dpop("client_credentials", dpop_proof(nonce: "stale-nonce"))

      assert body(conn)["error"] == "use_dpop_nonce"
      assert [_fresh] = get_resp_header(conn, "dpop-nonce")
    end

    test "a valid server-issued nonce lets the proof through and mints a DPoP token" do
      enable_minting()
      start_nonce_store()

      nonce = Attesto.DPoP.NonceStore.ETS.issue()

      put_config(
        dpop_enabled: true,
        dpop_nonce_required: true,
        nonce_store: Attesto.DPoP.NonceStore.ETS
      )

      conn = post_dpop("client_credentials", dpop_proof(nonce: nonce, scope: "read"))

      assert conn.status == 200
      assert body(conn)["token_type"] == "DPoP"
    end

    test "a DPoP-required client calling without proof is rejected, not downgraded" do
      enable_minting()

      put_config(
        dpop_enabled: true,
        client_requires_dpop?: fn _client -> true end
      )

      conn =
        post_token(%{
          "grant_type" => "client_credentials",
          "client_id" => "confidential-1",
          "client_secret" => "s3cr3t",
          "scope" => "read"
        })

      assert conn.status == 400
      assert body(conn)["error"] == "invalid_dpop_proof"
      assert body(conn)["error_description"] =~ "DPoP"
    end

    test "a DPoP-required authorization-code client calling without proof is rejected" do
      enable_minting()
      code_store = start_code_store("oc_sub-1", ["openid"])

      put_config(
        code_store: code_store,
        dpop_enabled: true,
        client_requires_dpop?: fn _client -> true end
      )

      conn = post_auth_code()

      assert conn.status == 400
      assert body(conn)["error"] == "invalid_dpop_proof"
      assert body(conn)["error_description"] =~ "DPoP"
    end

    test "a DPoP-bound authorization code rejects a different token proof key" do
      enable_minting()
      {_bound_proof, bound_jkt} = dpop_proof_and_jkt([])
      code_store = start_dpop_code_store("oc_sub-1", ["openid"], bound_jkt)
      put_config(code_store: code_store, dpop_enabled: true)

      {wrong_proof, _wrong_jkt} = dpop_proof_and_jkt([])

      conn =
        post_dpop_auth_code(
          %{
            "client_id" => "public-1",
            "code" => Process.get(:auth_code),
            "code_verifier" => @code_verifier,
            "redirect_uri" => @redirect_uri
          },
          wrong_proof
        )

      assert conn.status == 400
      assert body(conn)["error"] == "invalid_grant"
    end

    test "a DPoP-bound authorization code redeems with the matching token proof key" do
      enable_minting()
      {proof, jkt} = dpop_proof_and_jkt([])
      code_store = start_dpop_code_store("oc_sub-1", ["openid"], jkt)
      put_config(code_store: code_store, dpop_enabled: true)

      conn =
        post_dpop_auth_code(
          %{
            "client_id" => "public-1",
            "code" => Process.get(:auth_code),
            "code_verifier" => @code_verifier,
            "redirect_uri" => @redirect_uri
          },
          proof
        )

      assert conn.status == 200
      assert body(conn)["token_type"] == "DPoP"
    end
  end

  # FIX 4 - REVOCATION via load_client (the documented control is the lookup).
  describe "client revocation via :load_client (RFC 7009)" do
    test "a revoked client is rejected on the public (secretless) path too" do
      enable_minting()
      put_config(client_public?: fn _client -> true end)

      conn =
        post_token(%{
          "grant_type" => "client_credentials",
          "client_id" => "revoked-1"
        })

      assert conn.status == 400
      assert body(conn)["error"] == "invalid_client"
      assert body(conn)["error_description"] == "client authentication failed"
    end
  end

  describe "token exchange grant (RFC 8693)" do
    test "exchanges an Attesto access token into a downscoped access token" do
      enable_minting()

      {:ok, %{access_token: subject_token}} =
        Attesto.Token.mint(attesto_config(), %{
          kind: "client",
          sub: "oc_subject",
          scopes: ["documents.read", "documents.write"],
          claims: %{"client_id" => "subject-client"}
        })

      conn =
        post_token(%{
          "grant_type" => "urn:ietf:params:oauth:grant-type:token-exchange",
          "client_id" => "confidential-1",
          "client_secret" => "s3cr3t",
          "subject_token_type" => "urn:ietf:params:oauth:token-type:access_token",
          "subject_token" => subject_token,
          "scope" => "documents.read"
        })

      assert conn.status == 200
      response = body(conn)
      assert response["issued_token_type"] == "urn:ietf:params:oauth:token-type:access_token"
      assert response["scope"] == "documents.read"
      assert {:ok, claims} = Attesto.Token.verify(attesto_config(), response["access_token"])
      assert claims["sub"] == "oc_subject"
      assert claims["scope"] == "documents.read"
    end
  end

  # FIX 5 - INITIAL REFRESH-TOKEN ISSUANCE (RFC 6749 §4.1.4 / §6).
  describe "initial refresh-token issuance (RFC 6749 §6)" do
    test "no refresh token without a configured :refresh_store" do
      enable_minting()

      conn =
        post_token(%{
          "grant_type" => "client_credentials",
          "client_id" => "public-1",
          "scope" => "read offline_access"
        })

      # client_credentials never issues a refresh token; this also confirms
      # the access-token path is unaffected.
      assert conn.status == 200
      refute Map.has_key?(body(conn), "refresh_token")
    end

    test "issues a refresh token on authorization_code when offline_access is granted" do
      enable_minting()
      start_refresh_store()
      code_store = start_code_store("oc_sub-1", ["read", "offline_access"])

      put_config(
        refresh_store: Attesto.RefreshStore.ETS,
        code_store: code_store
      )

      conn = post_auth_code()

      assert conn.status == 200
      assert is_binary(body(conn)["access_token"])
      assert is_binary(body(conn)["refresh_token"])
    end

    test "no refresh token when offline_access is absent and no host gate is set" do
      enable_minting()
      start_refresh_store()
      code_store = start_code_store("oc_sub-1", ["read"])

      put_config(
        refresh_store: Attesto.RefreshStore.ETS,
        code_store: code_store
      )

      conn = post_auth_code()

      assert conn.status == 200
      refute Map.has_key?(body(conn), "refresh_token")
    end

    test "an :issue_refresh_token? host gate overrides the offline_access default" do
      enable_minting()
      start_refresh_store()
      code_store = start_code_store("oc_sub-1", ["read"])

      put_config(
        refresh_store: Attesto.RefreshStore.ETS,
        code_store: code_store,
        issue_refresh_token?: fn _client, _scope -> true end
      )

      conn = post_auth_code()

      assert conn.status == 200
      assert is_binary(body(conn)["refresh_token"])
    end

    test "confidential DPoP refresh rotation may use a fresh proof key" do
      enable_minting()
      start_refresh_store()
      {initial_proof, initial_jkt} = dpop_proof_and_jkt([])

      code_store =
        start_dpop_confidential_code_store("oc_sub-1", ["openid", "offline_access"], initial_jkt)

      put_config(
        refresh_store: Attesto.RefreshStore.ETS,
        code_store: code_store,
        dpop_enabled: true,
        require_pkce: false
      )

      initial = post_dpop_confidential_auth_code(initial_proof)

      assert initial.status == 200
      refresh_token = body(initial)["refresh_token"]
      assert is_binary(refresh_token)

      {refresh_proof, refresh_jkt} = dpop_proof_and_jkt([])
      rotated = post_dpop_confidential_refresh(refresh_token, refresh_proof)

      assert rotated.status == 200
      assert is_binary(body(rotated)["refresh_token"])
      assert peek_claims(body(rotated)["access_token"])["cnf"]["jkt"] == refresh_jkt
    end

    test "public DPoP refresh rotation still requires the original proof key" do
      enable_minting()
      start_refresh_store()
      {initial_proof, initial_jkt} = dpop_proof_and_jkt([])
      code_store = start_dpop_code_store("oc_sub-1", ["openid", "offline_access"], initial_jkt)

      put_config(
        refresh_store: Attesto.RefreshStore.ETS,
        code_store: code_store,
        dpop_enabled: true
      )

      initial =
        post_dpop_auth_code(
          %{
            "client_id" => "public-1",
            "code" => Process.get(:auth_code),
            "code_verifier" => @code_verifier,
            "redirect_uri" => @redirect_uri
          },
          initial_proof
        )

      assert initial.status == 200
      refresh_token = body(initial)["refresh_token"]
      assert is_binary(refresh_token)

      {wrong_proof, _wrong_jkt} = dpop_proof_and_jkt([])
      rotated = post_dpop_public_refresh(refresh_token, wrong_proof)

      assert rotated.status == 400
      assert body(rotated)["error"] == "invalid_grant"
    end
  end

  # OAuth 2.0 Security BCP §4.13 / RFC 6749 §4.1.2: re-presenting an
  # already-redeemed authorization code is the reuse attack signal. The server
  # MUST revoke the refresh-token family the first redemption spawned and
  # answer invalid_grant (no oracle).
  describe "authorization-code reuse detection (OAuth 2.0 Security BCP §4.13)" do
    test "reusing a code revokes the descendant family and returns invalid_grant" do
      enable_minting()
      start_refresh_store()
      # The code is linked to "fam-reuse"; the initial refresh token is minted
      # into that family, and reuse detection later revokes it by that id.
      code_store = start_family_code_store(["offline_access"], "fam-reuse")

      put_config(
        refresh_store: Attesto.RefreshStore.ETS,
        code_store: code_store
      )

      # First redemption succeeds and hands back a refresh token in fam-reuse.
      first = post_auth_code()
      assert first.status == 200
      refresh_token = body(first)["refresh_token"]
      assert is_binary(refresh_token)

      # Sanity: the issued token is live in fam-reuse before the replay.
      assert {:ok, %{family_id: "fam-reuse"}} =
               Attesto.RefreshStore.ETS.get(Attesto.Secret.hash(refresh_token))

      # Second redemption of the SAME code is reuse: invalid_grant on the wire.
      second = post_auth_code()
      assert second.status == 400
      assert body(second)["error"] == "invalid_grant"

      # The whole family is revoked: its tokens are gone from the store, so the
      # refresh token from the first redemption can no longer rotate.
      assert Attesto.RefreshStore.ETS.get(Attesto.Secret.hash(refresh_token)) == :error

      rotate =
        post_token(%{
          "grant_type" => "refresh_token",
          "client_id" => "public-1",
          "refresh_token" => refresh_token
        })

      assert rotate.status == 400
      assert body(rotate)["error"] == "invalid_grant"
    end

    test "reuse with no :refresh_store configured still fails closed with invalid_grant" do
      enable_minting()
      # No refresh store: the grant minted no family, so there is nothing to
      # revoke, but the replay must still be rejected (single-use + reuse
      # tombstone in the code store).
      code_store = start_family_code_store(["read"], "fam-orphan")
      put_config(code_store: code_store)

      first = post_auth_code()
      assert first.status == 200
      refute Map.has_key?(body(first), "refresh_token")

      second = post_auth_code()
      assert second.status == 400
      assert body(second)["error"] == "invalid_grant"
    end

    test "reusing a code revokes the access token issued by the first redemption" do
      enable_minting()
      code_store = start_family_code_store(["openid"], "fam-access")
      put_config(code_store: code_store)

      first = post_auth_code()
      assert first.status == 200
      access_token = body(first)["access_token"]
      jti = peek_claims(access_token)["jti"]
      refute code_store.access_token_revoked?(jti)

      second = post_auth_code()
      assert second.status == 400
      assert body(second)["error"] == "invalid_grant"

      assert code_store.access_token_revoked?(jti)
    end
  end

  # OpenID Connect Core §3.1.3.3: an authorization-code grant whose granted
  # scope contains `openid` additionally returns an ID Token in the token
  # response; a non-openid grant returns the access token alone.
  describe "OpenID Connect ID Token issuance (OIDC Core §3.1.3.3)" do
    test "openid scope yields an id_token with aud=client_id and the request nonce" do
      enable_minting()
      code_store = start_openid_code_store(["openid", "read"], %{"nonce" => "n-0S6_WzA2Mj"})
      put_config(code_store: code_store)

      conn = post_auth_code()

      assert conn.status == 200
      assert is_binary(body(conn)["access_token"])
      assert is_binary(body(conn)["id_token"])

      # OIDC Core §3.1.3.7: the ID Token verifies under the same keystore,
      # its `aud` is the OAuth client_id, and the Authentication Request
      # nonce round-trips into the `nonce` claim (item 11).
      {:ok, claims} =
        Attesto.IDToken.verify(id_token_config(), body(conn)["id_token"],
          client_id: "public-1",
          nonce: "n-0S6_WzA2Mj"
        )

      assert claims["aud"] == "public-1"
      assert claims["sub"] == "oc_sub-1"
      assert claims["nonce"] == "n-0S6_WzA2Mj"
      # OIDC Core §3.1.3.6 / §3.3.2.11: the access-token and code hashes are
      # present when the exchange supplies the artifacts to bind.
      assert is_binary(claims["at_hash"])
      assert is_binary(claims["c_hash"])
    end

    test "carries auth_time/acr/amr from the code's claims into the id_token" do
      enable_minting()

      code_store =
        start_openid_code_store(
          ["openid"],
          %{
            "auth_time" => 1_700_000_000,
            "acr" => "urn:mace:incommon:iap:silver",
            "amr" => ["pwd", "otp"]
          }
        )

      put_config(code_store: code_store)

      conn = post_auth_code()

      assert conn.status == 200

      {:ok, claims} =
        Attesto.IDToken.verify(id_token_config(), body(conn)["id_token"], client_id: "public-1")

      assert claims["auth_time"] == 1_700_000_000
      assert claims["acr"] == "urn:mace:incommon:iap:silver"
      assert claims["amr"] == ["pwd", "otp"]
    end

    test "a non-openid authorization_code grant returns no id_token" do
      enable_minting()
      code_store = start_openid_code_store(["read"], %{})
      put_config(code_store: code_store)

      conn = post_auth_code()

      assert conn.status == 200
      assert is_binary(body(conn)["access_token"])
      refute Map.has_key?(body(conn), "id_token")
    end

    test "openid + offline_access returns both an id_token and a refresh token" do
      enable_minting()
      start_refresh_store()
      code_store = start_openid_code_store(["openid", "offline_access"], %{"nonce" => "n-xyz"})

      put_config(
        code_store: code_store,
        refresh_store: Attesto.RefreshStore.ETS
      )

      conn = post_auth_code()

      assert conn.status == 200
      assert is_binary(body(conn)["id_token"])
      assert is_binary(body(conn)["refresh_token"])
    end

    # OIDC Core §5.4 / §5.5: host-sourced userinfo and claims-param-requested
    # claims are carried into the ID Token via the `:build_userinfo_claims`
    # callback, while the standard protocol claims still win.
    test "carries host userinfo and claims-param-requested claims into the id_token" do
      enable_minting()

      code_store =
        start_openid_code_store(["openid"], %{"claims" => %{"id_token" => %{"name" => nil}}})

      put_config(
        code_store: code_store,
        # The host's claim source: a fixed email plus any top-level claim the
        # OIDC `claims` request parameter asked for under `id_token`.
        build_userinfo_claims: fn _client, subject, _scope, requested ->
          base = %{"email" => "#{subject}@example.test"}

          extra =
            case requested do
              %{"id_token" => members} when is_map(members) ->
                Map.new(members, fn {name, _spec} -> {name, "claim-#{name}"} end)

              _ ->
                %{}
            end

          Map.merge(base, extra)
        end
      )

      conn = post_auth_code()
      assert conn.status == 200
      access_claims = peek_claims(body(conn)["access_token"])
      assert access_claims["claims"] == %{"id_token" => %{"name" => :null}}

      {:ok, claims} =
        Attesto.IDToken.verify(id_token_config(), body(conn)["id_token"], client_id: "public-1")

      # From the host's base userinfo claims.
      assert claims["email"] == "oc_sub-1@example.test"
      # From the OIDC claims request parameter the host honoured.
      assert claims["name"] == "claim-name"
      # OIDC Core §2: the host cannot override standard protocol claims.
      assert claims["sub"] == "oc_sub-1"
      assert claims["aud"] == "public-1"
    end

    test "an id_token carries no extra claims when no :build_userinfo_claims is configured" do
      enable_minting()
      code_store = start_openid_code_store(["openid"], %{})
      put_config(code_store: code_store)

      conn = post_auth_code()
      assert conn.status == 200

      {:ok, claims} =
        Attesto.IDToken.verify(id_token_config(), body(conn)["id_token"], client_id: "public-1")

      refute Map.has_key?(claims, "email")
    end
  end

  # ── Helpers ──────────────────────────────────────────────────────────────

  # Add the claim-shaped config the minting paths need: a keystore, a
  # principal kind, and a principal builder. The base setup already points
  # `keystore:` at this module's Keystore.
  defp enable_minting do
    put_config(
      principal_kinds: [@client_kind],
      build_principal: fn client, subject, scope ->
        %{
          kind: "client",
          sub: ensure_sub(subject),
          scopes: scope,
          claims: %{"client_id" => Map.get(client, :id, "unknown")}
        }
      end,
      client_id: fn client -> Map.get(client, :id) end
    )
  end

  defp capture_events do
    test_pid = self()
    put_config(on_event: fn event -> send(test_pid, {:event, event}) end)
  end

  defp attesto_config do
    :attesto_phoenix
    |> AttestoPhoenix.Config.from_otp_app(AttestoPhoenix.Config)
    |> AttestoPhoenix.Config.to_attesto_config(principal_kinds: [@client_kind])
  end

  # `client_credentials` uses the client_id as `sub`; the test client ids are
  # not prefixed, so namespace them to satisfy the principal kind's prefix.
  defp ensure_sub("oc_" <> _ = sub), do: sub
  defp ensure_sub(sub), do: "oc_" <> to_string(sub)

  # The bundled ETS stores' behaviour callbacks delegate to the default
  # (module-named) table, so they are started under their default names and
  # referenced by module. `ensure_started/1` tolerates a store already running
  # from an earlier test in this serial (`async: false`) run and clears its
  # state so each test sees an empty store.
  defp start_refresh_store, do: ensure_started(Attesto.RefreshStore.ETS)

  defp start_nonce_store, do: ensure_started(Attesto.DPoP.NonceStore.ETS)

  defp ensure_started(store) do
    case start_supervised(store) do
      {:ok, _pid} -> :ok
      {:error, {:already_started, _pid}} -> :ok
    end

    store.reset()
    store
  end

  # A pre-seeded code store: redeeming the issued code returns the given grant.
  defp start_code_store(subject, scope) do
    store = ensure_started(Attesto.CodeStore.ETS)

    {:ok, code} =
      Attesto.AuthorizationCode.issue(store, %{
        client_id: "public-1",
        redirect_uri: @redirect_uri,
        scope: scope,
        subject: subject,
        code_challenge: @code_challenge,
        code_challenge_method: "S256"
      })

    Process.put(:auth_code, code)
    store
  end

  defp start_unbound_confidential_code_store(subject, scope) do
    store = ensure_started(Attesto.CodeStore.ETS)

    {:ok, code} =
      Attesto.AuthorizationCode.issue(store, %{
        client_id: "confidential-1",
        redirect_uri: @redirect_uri,
        scope: scope,
        subject: subject,
        claims: %{"nonce" => "n-confidential"}
      })

    Process.put(:auth_code, code)
    store
  end

  defp start_dpop_confidential_code_store(subject, scope, dpop_jkt) do
    store = ensure_started(Attesto.CodeStore.ETS)

    {:ok, code} =
      Attesto.AuthorizationCode.issue(store, %{
        client_id: "confidential-1",
        redirect_uri: @redirect_uri,
        scope: scope,
        subject: subject,
        dpop_jkt: dpop_jkt,
        claims: %{"nonce" => "n-confidential"}
      })

    Process.put(:auth_code, code)
    store
  end

  # A code store pre-seeded with an OpenID Connect authorization code: the
  # granted scope drives ID Token issuance, and `claims` carries the
  # Authentication Request context (nonce, auth_time, acr, amr) the ID Token
  # binds (OIDC Core §2, §3.1.3.7).
  defp start_openid_code_store(scope, claims) do
    store = ensure_started(Attesto.CodeStore.ETS)

    {:ok, code} =
      Attesto.AuthorizationCode.issue(store, %{
        client_id: "public-1",
        redirect_uri: @redirect_uri,
        scope: scope,
        subject: "oc_sub-1",
        code_challenge: @code_challenge,
        code_challenge_method: "S256",
        claims: claims
      })

    Process.put(:auth_code, code)
    store
  end

  defp start_dpop_code_store(subject, scope, dpop_jkt) do
    store = ensure_started(Attesto.CodeStore.ETS)

    {:ok, code} =
      Attesto.AuthorizationCode.issue(store, %{
        client_id: "public-1",
        redirect_uri: @redirect_uri,
        scope: scope,
        subject: subject,
        code_challenge: @code_challenge,
        code_challenge_method: "S256",
        dpop_jkt: dpop_jkt,
        claims: %{"nonce" => "n-dpop"}
      })

    Process.put(:auth_code, code)
    store
  end

  # A code store pre-seeded with a `family_id`-linked code (OAuth 2.0 Security
  # BCP §4.13): the initial refresh token is minted into this family, so a
  # later replay of the code carries the `family_id` reuse detection revokes.
  # The reuse-tracking `ReuseCodeStore` implements the optional `take/1` +
  # `mark_consumed/2` pair, so a second redemption surfaces
  # `{:error, {:reuse, meta}}` from `Attesto.AuthorizationCode.redeem/4` to the
  # controller (the bundled `Attesto.CodeStore.ETS` does not track reuse).
  defp start_family_code_store(scope, family_id) do
    :ok = ReuseCodeStore.reset()

    {:ok, code} =
      Attesto.AuthorizationCode.issue(ReuseCodeStore, %{
        client_id: "public-1",
        redirect_uri: @redirect_uri,
        scope: scope,
        subject: "oc_sub-1",
        code_challenge: @code_challenge,
        code_challenge_method: "S256",
        family_id: family_id
      })

    Process.put(:auth_code, code)
    ReuseCodeStore
  end

  # An `Attesto.Config` over this module's keystore for verifying minted ID
  # Tokens (OIDC Core §3.1.3.7). `audience` is irrelevant to an ID Token (its
  # `aud` is the client_id) but the core requires a non-empty one.
  defp id_token_config do
    Attesto.Config.new(
      issuer: "https://issuer.example",
      audience: "https://issuer.example",
      keystore: __MODULE__.Keystore,
      principal_kinds: [@client_kind]
    )
  end

  defp post_auth_code do
    post_token(%{
      "grant_type" => "authorization_code",
      "client_id" => "public-1",
      "code" => Process.get(:auth_code),
      "code_verifier" => @code_verifier,
      "redirect_uri" => @redirect_uri
    })
  end

  # Build a signed DPoP proof (RFC 9449 §4.2) for POST @endpoint_path. The
  # proof key is freshly generated per call; `nonce` is included when given.
  defp dpop_proof(opts) do
    {proof, _jkt} = dpop_proof_and_jkt(opts)
    proof
  end

  defp dpop_proof_and_jkt(opts) do
    nonce = Keyword.get(opts, :nonce)
    jwk = JOSE.JWK.generate_key({:ec, "P-256"})
    {_, pub_map} = JOSE.JWK.to_public_map(jwk)

    payload =
      %{
        "htm" => "POST",
        "htu" => "https://issuer.example" <> @endpoint_path,
        "iat" => System.system_time(:second),
        "jti" => Base.url_encode64(:crypto.strong_rand_bytes(16), padding: false)
      }
      |> maybe_put("nonce", nonce)

    header = %{"alg" => "ES256", "typ" => "dpop+jwt", "jwk" => pub_map}
    {_, compact} = JOSE.JWS.compact(JOSE.JWT.sign(jwk, header, payload))
    {compact, Attesto.DPoP.compute_jkt(pub_map)}
  end

  defp maybe_put(map, _k, nil), do: map
  defp maybe_put(map, k, v), do: Map.put(map, k, v)

  # POST with a DPoP header over an https-effective conn (so the proof's
  # https-only htu matches and DPoP binding is reachable).
  defp post_dpop(grant_type, proof) do
    params = %{"grant_type" => grant_type, "client_id" => "public-1", "scope" => "read"}
    %Plug.Conn{} = base = conn(:post, @endpoint_path, params)

    %Plug.Conn{base | scheme: :https, host: "issuer.example", port: 443}
    |> put_req_header("dpop", proof)
    |> TokenController.create(params)
  end

  defp post_dpop_auth_code(params, proof) do
    params = Map.put(params, "grant_type", "authorization_code")
    %Plug.Conn{} = base = conn(:post, @endpoint_path, params)

    %Plug.Conn{base | scheme: :https, host: "issuer.example", port: 443}
    |> put_req_header("dpop", proof)
    |> TokenController.create(params)
  end

  defp post_dpop_confidential_auth_code(proof) do
    params = %{
      "grant_type" => "authorization_code",
      "code" => Process.get(:auth_code),
      "redirect_uri" => @redirect_uri
    }

    %Plug.Conn{} = base = conn(:post, @endpoint_path, params)

    %Plug.Conn{base | scheme: :https, host: "issuer.example", port: 443}
    |> put_req_header("authorization", "Basic " <> Base.encode64("confidential-1:s3cr3t"))
    |> put_req_header("dpop", proof)
    |> TokenController.create(params)
  end

  defp post_dpop_confidential_refresh(refresh_token, proof) do
    params = %{
      "grant_type" => "refresh_token",
      "refresh_token" => refresh_token,
      "scope" => "openid offline_access"
    }

    %Plug.Conn{} = base = conn(:post, @endpoint_path, params)

    %Plug.Conn{base | scheme: :https, host: "issuer.example", port: 443}
    |> put_req_header("authorization", "Basic " <> Base.encode64("confidential-1:s3cr3t"))
    |> put_req_header("dpop", proof)
    |> TokenController.create(params)
  end

  defp post_dpop_public_refresh(refresh_token, proof) do
    params = %{
      "grant_type" => "refresh_token",
      "client_id" => "public-1",
      "refresh_token" => refresh_token,
      "scope" => "openid offline_access"
    }

    %Plug.Conn{} = base = conn(:post, @endpoint_path, params)

    %Plug.Conn{base | scheme: :https, host: "issuer.example", port: 443}
    |> put_req_header("dpop", proof)
    |> TokenController.create(params)
  end

  defp peek_claims(jwt) do
    config =
      Attesto.Config.new(
        issuer: "https://issuer.example",
        audience: "https://issuer.example",
        keystore: __MODULE__.Keystore,
        principal_kinds: [@client_kind]
      )

    {:ok, claims} = Attesto.Token.peek_signed_claims(config, jwt)
    claims
  end

  # A self-signed X.509 certificate DER for the mTLS thumbprint path, built
  # with OTP's test-root helper so `Attesto.MTLS.compute_thumbprint/1` accepts
  # it as a parseable certificate.
  defp self_signed_cert_der do
    %{cert: der} = :public_key.pkix_test_root_cert(~c"CN=attesto-test", [])
    der
  end

  defp post_token(params) do
    :post
    |> conn(@endpoint_path, params)
    |> TokenController.create(params)
  end

  defp body(conn), do: JSON.decode!(conn.resp_body)

  defp client_assertion(jwk, client_id, overrides \\ %{}) do
    now = System.system_time(:second)

    claims =
      Map.merge(
        %{
          "iss" => client_id,
          "sub" => client_id,
          "aud" => "https://issuer.example/oauth/token",
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

  defp client_lookup(clients, id) do
    case Map.fetch(clients, id) do
      {:ok, client} -> {:ok, client}
      :error -> {:error, :not_found}
    end
  end

  # `AttestoPhoenix.config/0` resolves a validated `%AttestoPhoenix.Config{}`
  # from the host `:otp_app` config (via `AttestoPhoenix.Config.from_otp_app/2`).
  # The tests point the otp_app at this library and install the config under
  # both the main-module key and the Config-module key so resolution finds it
  # whichever key the resolver uses; overrides are merged so a single test can
  # override one callback.
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
