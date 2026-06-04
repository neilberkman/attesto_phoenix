defmodule AttestoPhoenix.Controller.AuthorizeControllerTest do
  @moduledoc """
  Tests for the authorization endpoint (RFC 6749 §3.1, OIDC Core §3.1.2).

  The route is not mounted yet, so the controller action is exercised directly
  against a built `Plug.Conn`. Host policy (client lookup, registered redirect
  URIs, login, consent, code persistence) is supplied through stub callbacks on
  `AttestoPhoenix.Config`, exactly as a real deployment would wire it.
  """
  use ExUnit.Case, async: false

  import Plug.Conn
  import Phoenix.ConnTest

  alias Attesto.AuthorizationCode
  alias Attesto.RequestObject.Policy
  alias AttestoPhoenix.Controller.AuthorizeController
  alias AttestoPhoenix.Store.PAR.ETS, as: PARStore

  # A fixed S256 PKCE pair (RFC 7636 §4.2): the challenge is the
  # BASE64URL-no-pad encoding of SHA-256(verifier). Computed inline here (the
  # transform is fixed by the RFC) so the test does not depend on a core helper.
  @code_verifier "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
  @code_challenge Base.url_encode64(:crypto.hash(:sha256, @code_verifier), padding: false)
  @redirect_uri "https://client.example.com/callback"
  @client_id "test-client"

  defmodule TestStore do
    @moduledoc false
    @behaviour Attesto.CodeStore

    def start_link do
      Agent.start_link(fn -> %{} end, name: __MODULE__)
    end

    @impl true
    def put(record) do
      Agent.update(__MODULE__, &Map.put(&1, record.code_hash, record))
      :ok
    end

    @impl true
    def take(code_hash) do
      Agent.get_and_update(__MODULE__, fn state ->
        case Map.fetch(state, code_hash) do
          {:ok, record} -> {{:ok, record}, Map.delete(state, code_hash)}
          :error -> {:error, state}
        end
      end)
    end

    # Test-only peek that does not consume the code.
    def peek(code) do
      Agent.get(__MODULE__, &Map.get(&1, Attesto.Secret.hash(code)))
    end
  end

  setup do
    {:ok, _} = start_supervised(%{id: TestStore, start: {TestStore, :start_link, []}})

    config = base_config()

    Application.put_env(:attesto_phoenix, :otp_app, :attesto_phoenix)
    Application.put_env(:attesto_phoenix, AttestoPhoenix.Config, config)

    on_exit(fn -> Application.delete_env(:attesto_phoenix, AttestoPhoenix.Config) end)

    %{config: config}
  end

  defp base_config(overrides \\ []) do
    Keyword.merge(
      [
        issuer: "https://issuer.example.com",
        audience: "https://issuer.example.com",
        keystore: __MODULE__.TestKeystore,
        repo: __MODULE__.NoRepo,
        load_client: &__MODULE__.load_client/1,
        verify_client_secret: &__MODULE__.verify_secret/2,
        load_principal: &__MODULE__.load_principal/1,
        client_id: &__MODULE__.client_id/1,
        client_redirect_uris: &__MODULE__.client_redirect_uris/1,
        authenticate_resource_owner: &__MODULE__.authenticate/3,
        consent: &__MODULE__.consent/3,
        code_store: TestStore,
        authorization_code_ttl: 60,
        require_https: true,
        # A real AS configures principal kinds; needed for the derived
        # Attesto.Config when the authorization endpoint signs JARM responses.
        principal_kinds: [Attesto.PrincipalKind.new("user", "usr_")]
      ],
      overrides
    )
  end

  defp put_config(overrides) do
    Application.put_env(:attesto_phoenix, AttestoPhoenix.Config, base_config(overrides))
  end

  defp valid_params(extra \\ %{}) do
    Map.merge(
      %{
        "response_type" => "code",
        "client_id" => @client_id,
        "redirect_uri" => @redirect_uri,
        "scope" => "openid profile",
        "state" => "xyz",
        "nonce" => "n-0S6_WzA2Mj",
        "code_challenge" => @code_challenge,
        "code_challenge_method" => "S256"
      },
      extra
    )
  end

  defp call(params) do
    build_conn()
    |> Map.put(:scheme, :https)
    |> AuthorizeController.authorize(params)
  end

  defp location(conn) do
    conn |> get_resp_header("location") |> List.first()
  end

  defp location_query(conn) do
    case conn |> location() |> URI.parse() |> Map.get(:query) do
      nil -> %{}
      query -> URI.decode_query(query)
    end
  end

  # Verify a JARM response JWT the way a client would: strictly, against the
  # authorization server's signing key (TestKeystore is RSA/RS256), returning
  # the claims.
  defp decode_jarm(jwt) do
    jwk = __MODULE__.TestKeystore.signing_pem() |> Attesto.Key.jwk()

    assert {true, %JOSE.JWT{fields: claims}, %JOSE.JWS{}} =
             JOSE.JWT.verify_strict(jwk, ["RS256"], jwt)

    claims
  end

  # ── Valid flow ───────────────────────────────────────────────────────────

  describe "valid authorization request" do
    test "issues a code and 302-redirects to the redirect_uri with code+state" do
      conn = call(valid_params())

      assert conn.status == 302
      query = location_query(conn)

      assert location(conn) =~ @redirect_uri
      assert is_binary(query["code"])
      assert query["state"] == "xyz"
    end

    test "the issued code is redeemable and carries nonce + auth_time/acr/amr claims" do
      conn = call(valid_params())
      code = location_query(conn)["code"]

      # The stored code carries the OIDC claims the token endpoint needs to mint
      # the ID token (OIDC Core §3.1.3.6).
      record = TestStore.peek(code)
      assert record.data.claims["nonce"] == "n-0S6_WzA2Mj"
      assert record.data.claims["auth_time"] == 1_700_000_000
      assert record.data.claims["acr"] == "urn:mace:incommon:iap:silver"
      assert record.data.claims["amr"] == ["pwd"]

      # And it redeems against the same PKCE verifier and redirect_uri.
      assert {:ok, grant} =
               AuthorizationCode.redeem(TestStore, code, %{
                 redirect_uri: @redirect_uri,
                 code_verifier: @code_verifier,
                 client_id: @client_id
               })

      assert grant.subject == "user-42"
      assert grant.scope == ["openid", "profile"]
    end

    test "the issued code preserves the OIDC claims request object" do
      claims = %{"userinfo" => %{"name" => %{"essential" => true}}}
      conn = call(valid_params(%{"claims" => JSON.encode!(claims)}))
      code = location_query(conn)["code"]

      record = TestStore.peek(code)
      assert record.data.claims["claims"] == claims
    end

    test "preserves an existing query component in the redirect_uri" do
      put_config(client_redirect_uris: fn _ -> ["https://client.example.com/cb?ui=1"] end)

      conn = call(valid_params(%{"redirect_uri" => "https://client.example.com/cb?ui=1"}))

      assert conn.status == 302
      query = location_query(conn)
      assert query["ui"] == "1"
      assert is_binary(query["code"])
    end

    test "omits state when the request carried none" do
      conn = call(valid_params(%{}) |> Map.delete("state"))

      assert conn.status == 302
      refute Map.has_key?(location_query(conn), "state")
    end

    test "can include RFC 9207 iss in successful authorization responses" do
      put_config(authorization_response_iss: true)

      conn = call(valid_params())

      assert conn.status == 302
      assert location_query(conn)["iss"] == "https://issuer.example.com"
    end
  end

  # ── JARM (FAPI 2.0 Message Signing §5.4) ─────────────────────────────────

  describe "JARM response modes" do
    test "query.jwt returns a single signed response JWT, not plain code/state" do
      conn = call(valid_params(%{"response_mode" => "query.jwt"}))

      assert conn.status == 302
      query = location_query(conn)

      # Only `response` is in the query; code/state/iss ride inside the JWT.
      assert is_binary(query["response"])
      refute Map.has_key?(query, "code")
      refute Map.has_key?(query, "state")

      claims = decode_jarm(query["response"])
      assert claims["iss"] == "https://issuer.example.com"
      assert claims["aud"] == @client_id
      assert is_binary(claims["code"])
      assert claims["state"] == "xyz"
      assert is_integer(claims["exp"])
    end

    test "the `jwt` shorthand resolves to query.jwt for the code flow (JARM §2.3.2)" do
      conn = call(valid_params(%{"response_mode" => "jwt"}))

      assert conn.status == 302
      query = location_query(conn)
      assert is_binary(query["response"])
      assert decode_jarm(query["response"])["code"] |> is_binary()
    end

    test "fragment.jwt delivers the response JWT in the URL fragment" do
      conn = call(valid_params(%{"response_mode" => "fragment.jwt"}))

      assert conn.status == 302
      fragment = conn |> location() |> URI.parse() |> Map.get(:fragment)
      assert %{"response" => jwt} = URI.decode_query(fragment)
      assert decode_jarm(jwt)["code"] |> is_binary()
    end

    test "form_post.jwt renders an auto-submitting HTML form posting the response" do
      conn = call(valid_params(%{"response_mode" => "form_post.jwt"}))

      assert conn.status == 200
      assert get_resp_header(conn, "content-type") == ["text/html; charset=utf-8"]
      assert conn.resp_body =~ ~s(method="post")
      assert conn.resp_body =~ ~s(action="https://client.example.com/callback")
      assert conn.resp_body =~ ~s(name="response")
      assert [_, jwt] = Regex.run(~r/name="response" value="([^"]+)"/, conn.resp_body)
      assert decode_jarm(jwt)["code"] |> is_binary()
    end

    test "a redirectable error is itself returned as a signed JWT under query.jwt" do
      # An invalid scope token is a redirectable invalid_scope; under a JARM mode
      # the error must be returned as a signed response JWT, not plain params.
      conn = call(valid_params(%{"response_mode" => "query.jwt", "scope" => ~s(open"id)}))

      assert conn.status == 302
      query = location_query(conn)
      assert is_binary(query["response"])
      refute Map.has_key?(query, "error")

      claims = decode_jarm(query["response"])
      assert claims["error"] == "invalid_scope"
      assert claims["aud"] == @client_id
      assert claims["state"] == "xyz"
    end
  end

  describe "PAR-required policy" do
    test "rejects direct authorization requests when PAR is required" do
      put_config(
        require_pushed_authorization_requests: true,
        par_store: PARStore
      )

      conn = call(valid_params())

      assert conn.status == 302
      query = location_query(conn)
      assert query["error"] == "invalid_request"
      assert query["state"] == "xyz"
      refute Map.has_key?(query, "code")
    end

    test "accepts authorization requests resolved from a PAR request_uri" do
      request_uri = "urn:ietf:params:oauth:request_uri:test"

      put_config(
        require_pushed_authorization_requests: true,
        par_store: PARStore
      )

      :ok = PARStore.put(request_uri, valid_params(), 60)

      conn = call(%{"client_id" => @client_id, "request_uri" => request_uri})

      assert conn.status == 302
      query = location_query(conn)
      assert is_binary(query["code"])
      assert query["state"] == "xyz"
    end

    test "ignores front-channel state outside a resolved PAR request" do
      request_uri = "urn:ietf:params:oauth:request_uri:state-outside-par"

      put_config(
        require_pushed_authorization_requests: true,
        par_store: PARStore
      )

      :ok = PARStore.put(request_uri, valid_params() |> Map.delete("state"), 60)

      conn =
        call(%{
          "client_id" => @client_id,
          "request_uri" => request_uri,
          "state" => "front-channel-state"
        })

      assert conn.status == 302
      query = location_query(conn)
      assert is_binary(query["code"])
      refute Map.has_key?(query, "state")
    end

    test "carries a PAR DPoP thumbprint into the issued authorization code" do
      request_uri = "urn:ietf:params:oauth:request_uri:dpop-bound"
      jkt = Attesto.Secret.hash("par-proof-key")

      put_config(
        require_pushed_authorization_requests: true,
        par_store: PARStore
      )

      :ok = PARStore.put(request_uri, Map.put(valid_params(), "dpop_jkt", jkt), 60)

      conn = call(%{"client_id" => @client_id, "request_uri" => request_uri})

      assert conn.status == 302
      code = location_query(conn)["code"]
      assert TestStore.peek(code).data.dpop_jkt == jkt
    end

    test "uses the bound client and ignores other front-channel params when the client_id matches" do
      request_uri = "urn:ietf:params:oauth:request_uri:bound-client"

      put_config(
        require_pushed_authorization_requests: true,
        par_store: PARStore
      )

      :ok = PARStore.put(request_uri, valid_params(), 60)

      conn = call(%{"client_id" => @client_id, "request_uri" => request_uri})

      assert conn.status == 302
      code = location_query(conn)["code"]
      assert is_binary(code)
      assert TestStore.peek(code).data.client_id == @client_id
    end

    test "rejects a front-channel client_id that does not match the request_uri's bound client" do
      # RFC 9126 §2.2 / FAPI2SPFinalPAREnsureRequestUriIsBoundToClient: the
      # request_uri is bound to the client that pushed it; a different client
      # replaying the reference (mismatched front-channel client_id) is rejected,
      # non-redirectable (the bound redirect_uri is not trusted for this caller).
      request_uri = "urn:ietf:params:oauth:request_uri:bound-client"

      put_config(
        require_pushed_authorization_requests: true,
        par_store: PARStore
      )

      :ok = PARStore.put(request_uri, valid_params(), 60)

      conn = call(%{"client_id" => "front-channel-client", "request_uri" => request_uri})

      # Non-redirectable direct error: a 400 means no authorization code was issued.
      assert conn.status == 400
      assert JSON.decode!(conn.resp_body)["error"] == "invalid_request"
    end

    test "does not consume a PAR request_uri before host re-entry completes" do
      request_uri = "urn:ietf:params:oauth:request_uri:reentry"

      put_config(
        require_pushed_authorization_requests: true,
        par_store: PARStore
      )

      :ok = PARStore.put(request_uri, valid_params(), 60)

      first = call(%{"client_id" => @client_id, "request_uri" => request_uri})
      second = call(%{"client_id" => @client_id, "request_uri" => request_uri})

      assert first.status == 302
      assert second.status == 302

      first_query = first |> location_query()
      second_query = second |> location_query()

      assert is_binary(first_query["code"])
      assert is_binary(second_query["code"])
      refute first_query["error"]
      refute second_query["error"]
    end

    test "an unknown/expired PAR request_uri is a direct invalid_request_uri" do
      # RFC 9126 §2.2 / FAPI2SPFinalPARAttemptToUseExpiredRequestUri: a PAR
      # `urn:ietf:params:oauth:request_uri:` reference that is not in the store
      # (expired or never issued) must be rejected as invalid_request_uri, never
      # treated as an absent reference (which would surface the wrong error).
      put_config(require_pushed_authorization_requests: true, par_store: PARStore)

      conn =
        call(%{
          "client_id" => @client_id,
          "request_uri" => "urn:ietf:params:oauth:request_uri:does-not-exist"
        })

      assert conn.status == 400
      assert JSON.decode!(conn.resp_body)["error"] == "invalid_request_uri"
    end
  end

  # ── Direct (non-redirectable) errors (OIDC Core §3.1.2.6) ─────────────────

  describe "direct errors (never a redirect)" do
    test "unknown client_id renders a direct 400, not a redirect" do
      conn = call(valid_params(%{"client_id" => "ghost"}))

      assert conn.status == 400
      assert get_resp_header(conn, "location") == []
      assert %{"error" => "invalid_request"} = json_response(conn, 400)
    end

    test "missing client_id renders a direct 400" do
      conn = call(valid_params(%{}) |> Map.delete("client_id"))

      assert conn.status == 400
      assert get_resp_header(conn, "location") == []
    end

    test "unregistered redirect_uri renders a direct 400, not a redirect" do
      conn = call(valid_params(%{"redirect_uri" => "https://evil.example.com/cb"}))

      assert conn.status == 400
      assert get_resp_header(conn, "location") == []
    end

    test "unregistered redirect_uri renders an HTML error page for browser requests" do
      conn =
        build_conn()
        |> Map.put(:scheme, :https)
        |> put_req_header("accept", "text/html")
        |> AuthorizeController.authorize(
          valid_params(%{"redirect_uri" => "https://evil.example.com/cb"})
        )

      assert conn.status == 400
      assert get_resp_header(conn, "location") == []
      assert get_resp_header(conn, "content-type") == ["text/html; charset=utf-8"]
      assert conn.resp_body =~ "Authorization request error"
      assert conn.resp_body =~ "redirect_uri is not registered for this client"
    end

    test "missing redirect_uri renders a direct 400" do
      conn = call(valid_params(%{}) |> Map.delete("redirect_uri"))

      assert conn.status == 400
      assert get_resp_header(conn, "location") == []
    end

    test "insecure transport renders a direct 400 when HTTPS is required" do
      conn =
        build_conn()
        |> Map.put(:scheme, :http)
        |> AuthorizeController.authorize(valid_params())

      assert conn.status == 400
      assert get_resp_header(conn, "location") == []
    end
  end

  # ── Redirectable errors (RFC 6749 §4.1.2.1) ───────────────────────────────

  describe "redirectable errors (back to the validated redirect_uri)" do
    test "bad response_type redirects with unsupported_response_type + state" do
      conn = call(valid_params(%{"response_type" => "token"}))

      assert conn.status == 302
      query = location_query(conn)
      assert query["error"] == "unsupported_response_type"
      assert query["state"] == "xyz"
      assert location(conn) =~ @redirect_uri
    end

    test "missing PKCE challenge redirects with invalid_request" do
      conn = call(valid_params(%{}) |> Map.delete("code_challenge"))

      assert conn.status == 302
      assert location_query(conn)["error"] == "invalid_request"
    end

    test "a request object failing the FAPI Message Signing policy is rejected at /authorize" do
      # Guards that the controller threads :request_object_policy into
      # AuthorizationRequest.validate/2: under the FAPI profile this object
      # (no nbf) must be rejected; the default generic policy would accept it.
      request_key = JOSE.JWK.generate_key({:ec, "P-256"})
      {_kty, pub} = JOSE.JWK.to_public_map(request_key)
      client_jwk = Map.merge(pub, %{"kid" => "rk", "alg" => "ES256"})

      put_config(
        client_jwks: fn _client -> %{"keys" => [client_jwk]} end,
        request_object_policy: Policy.fapi_message_signing()
      )

      claims = %{
        "iss" => @client_id,
        "aud" => "https://issuer.example.com",
        "client_id" => @client_id,
        "redirect_uri" => @redirect_uri,
        "response_type" => "code",
        "scope" => "openid",
        "code_challenge" => @code_challenge,
        "code_challenge_method" => "S256"
      }

      header = %{"alg" => "ES256", "kid" => "rk", "typ" => "oauth-authz-req+jwt"}
      {_header, request} = request_key |> JOSE.JWT.sign(header, claims) |> JOSE.JWS.compact()

      conn =
        call(%{"client_id" => @client_id, "redirect_uri" => @redirect_uri, "request" => request})

      assert conn.status == 302
      assert location_query(conn)["error"] == "invalid_request_object"
    end

    test "can include RFC 9207 iss in authorization error responses" do
      put_config(authorization_response_iss: true)

      conn = call(valid_params(%{}) |> Map.delete("code_challenge"))

      assert conn.status == 302
      query = location_query(conn)
      assert query["error"] == "invalid_request"
      assert query["iss"] == "https://issuer.example.com"
    end

    test "PKCE plain method redirects with invalid_request (no downgrade)" do
      conn = call(valid_params(%{"code_challenge_method" => "plain"}))

      assert conn.status == 302
      assert location_query(conn)["error"] == "invalid_request"
    end

    test "invalid scope token redirects with invalid_scope" do
      conn = call(valid_params(%{"scope" => "openid \"bad\""}))

      assert conn.status == 302
      assert location_query(conn)["error"] == "invalid_scope"
    end

    test "unsupported request_uri redirects with request_uri_not_supported when no PAR store is configured" do
      conn = call(valid_params(%{"request_uri" => "https://client.example.com/request.jwt"}))

      assert conn.status == 302
      query = location_query(conn)
      assert query["error"] == "request_uri_not_supported"
      assert query["state"] == "xyz"
      refute Map.has_key?(query, "code")
    end

    test "no code is issued when a redirectable error fires" do
      conn = call(valid_params(%{"response_type" => "token"}))

      refute Map.has_key?(location_query(conn), "code")
    end
  end

  # ── Login / consent host hooks ────────────────────────────────────────────

  describe "host login/consent hooks" do
    test "an unauthenticated owner has the connection handed to the host (no code)" do
      put_config(
        authenticate_resource_owner: fn conn, _request, _opts ->
          {:halt,
           conn |> Plug.Conn.put_resp_header("location", "/login") |> Plug.Conn.send_resp(302, "")}
        end
      )

      conn = call(valid_params())

      # Host redirected to its own login page; no authorization code issued.
      assert location(conn) == "/login"
      refute Map.has_key?(location_query(conn), "code")
    end

    test "denied consent redirects with access_denied" do
      put_config(consent: fn _conn, _request, _subject -> {:denied, :user_refused} end)

      conn = call(valid_params())

      assert conn.status == 302
      assert location_query(conn)["error"] == "access_denied"
      assert location_query(conn)["state"] == "xyz"
    end

    test "consent halting hands the connection to the host (no code)" do
      put_config(
        consent: fn conn, _request, _subject ->
          {:halt,
           conn
           |> Plug.Conn.put_resp_header("location", "/consent")
           |> Plug.Conn.send_resp(302, "")}
        end
      )

      conn = call(valid_params())

      assert location(conn) == "/consent"
      refute Map.has_key?(location_query(conn), "code")
    end

    test "missing authenticate_resource_owner callback fails closed with server_error" do
      put_config(authenticate_resource_owner: nil)

      conn = call(valid_params())

      assert conn.status == 302
      assert location_query(conn)["error"] == "server_error"
    end

    test "absent consent callback implicitly grants consent and issues a code" do
      put_config(consent: nil)

      conn = call(valid_params())

      assert conn.status == 302
      assert is_binary(location_query(conn)["code"])
    end
  end

  # ── nonce policy (OIDC Core §3.1.2.1) ──────────────────────────────────────

  describe "require_nonce policy" do
    test "an OIDC request without a nonce is rejected when require_nonce is set" do
      put_config(require_nonce: true)

      conn = call(valid_params(%{}) |> Map.delete("nonce"))

      assert conn.status == 302
      query = location_query(conn)
      assert query["error"] == "invalid_request"
      assert query["state"] == "xyz"
      # The error is redirectable (the redirect_uri is trusted), never a code.
      refute Map.has_key?(query, "code")
    end

    test "an OIDC request with a nonce still succeeds when require_nonce is set" do
      put_config(require_nonce: true)

      conn = call(valid_params())

      assert conn.status == 302
      assert is_binary(location_query(conn)["code"])
    end

    test "a non-OIDC request without a nonce is unaffected by require_nonce" do
      # No `openid` scope => not an OpenID Connect Authentication Request, so the
      # nonce requirement does not apply (RFC 6749 keeps the code at SHOULD).
      put_config(require_nonce: true)

      conn = call(valid_params(%{"scope" => "profile"}) |> Map.delete("nonce"))

      assert conn.status == 302
      assert is_binary(location_query(conn)["code"])
    end

    test "an OIDC request without a nonce succeeds when require_nonce is unset (default)" do
      conn = call(valid_params(%{}) |> Map.delete("nonce"))

      assert conn.status == 302
      assert is_binary(location_query(conn)["code"])
    end
  end

  # ── prompt handling (OIDC Core §3.1.2.1 / §3.1.2.6) ────────────────────────

  describe "prompt=none (no interactive UI)" do
    test "the host is told the request is non-interactive" do
      call(valid_params(%{"prompt" => "none"}))

      assert_received {:auth_opts, auth_opts}
      assert auth_opts.interactive == false
      assert auth_opts.prompt == ["none"]
    end

    test "an already-authenticated subject still issues a code under prompt=none" do
      conn = call(valid_params(%{"prompt" => "none"}))

      assert conn.status == 302
      assert is_binary(location_query(conn)["code"])
    end

    test "a host that cannot authenticate silently ({:none}) yields login_required" do
      put_config(authenticate_resource_owner: fn _conn, _request, _opts -> {:none} end)

      conn = call(valid_params(%{"prompt" => "none"}))

      assert conn.status == 302
      query = location_query(conn)
      assert query["error"] == "login_required"
      assert query["state"] == "xyz"
      refute Map.has_key?(query, "code")
    end

    test "a host halt to login UI is converted to login_required under prompt=none" do
      # The host MUST NOT render UI under prompt=none; even if it tries to halt
      # to its login page, the controller reports login_required instead.
      put_config(
        authenticate_resource_owner: fn conn, _request, _opts ->
          {:halt,
           conn |> Plug.Conn.put_resp_header("location", "/login") |> Plug.Conn.send_resp(302, "")}
        end
      )

      conn = call(valid_params(%{"prompt" => "none"}))

      assert location(conn) =~ @redirect_uri
      assert location_query(conn)["error"] == "login_required"
    end

    test "a consent halt is converted to consent_required under prompt=none" do
      put_config(
        consent: fn conn, _request, _subject ->
          {:halt,
           conn
           |> Plug.Conn.put_resp_header("location", "/consent")
           |> Plug.Conn.send_resp(302, "")}
        end
      )

      conn = call(valid_params(%{"prompt" => "none"}))

      assert location(conn) =~ @redirect_uri
      assert location_query(conn)["error"] == "consent_required"
    end

    test "denied consent is consent_required (not access_denied) under prompt=none" do
      put_config(consent: fn _conn, _request, _subject -> {:denied, :user_refused} end)

      conn = call(valid_params(%{"prompt" => "none"}))

      assert location_query(conn)["error"] == "consent_required"
    end

    test "a host {:error, :interaction_required} is reported by redirect" do
      put_config(
        authenticate_resource_owner: fn _conn, _request, _opts ->
          {:error, :interaction_required}
        end
      )

      conn = call(valid_params(%{"prompt" => "none"}))

      assert location_query(conn)["error"] == "interaction_required"
    end
  end

  describe "prompt=login (force re-authentication)" do
    test "the host is told to force re-auth" do
      call(valid_params(%{"prompt" => "login"}))

      assert_received {:auth_opts, auth_opts}
      assert auth_opts.force_reauth == true
      assert auth_opts.interactive == true
    end

    test "the freshly established auth_time rides into the code claims" do
      conn = call(valid_params(%{"prompt" => "login"}))
      code = location_query(conn)["code"]

      # The stub bumps auth_time when force_reauth is set; that fresh value is
      # what the ID token must reflect (OIDC Core §2).
      record = TestStore.peek(code)
      assert record.data.claims["auth_time"] == 1_700_009_999
    end
  end

  # ── max_age / auth_time (OIDC Core §3.1.2.1) ───────────────────────────────

  describe "max_age" do
    test "max_age is threaded to the host auth callback" do
      call(valid_params(%{"max_age" => "300"}))

      assert_received {:auth_opts, auth_opts}
      assert auth_opts.max_age == 300
    end

    test "an absent max_age is nil in the auth callback opts" do
      call(valid_params())

      assert_received {:auth_opts, auth_opts}
      assert auth_opts.max_age == nil
    end

    test "a max_age that forces re-auth carries the fresh auth_time into the code" do
      # max_age=0 means the existing authentication is always too old; the stub
      # re-authenticates and returns the fresh auth_time, which the issued code
      # must carry so the ID token's auth_time reflects the re-auth.
      conn = call(valid_params(%{"max_age" => "0"}))
      code = location_query(conn)["code"]

      record = TestStore.peek(code)
      assert record.data.claims["auth_time"] == 1_700_009_999
    end
  end

  # ── family_id (OAuth 2.0 Security BCP §4.13 / §4.14) ───────────────────────

  describe "family_id" do
    test "a non-empty family_id is threaded into the issued code" do
      conn = call(valid_params())
      code = location_query(conn)["code"]

      record = TestStore.peek(code)
      assert is_binary(record.data.family_id)
      assert record.data.family_id != ""
    end

    test "each issued code gets a distinct family_id" do
      code1 = call(valid_params()) |> location_query() |> Map.get("code")
      code2 = call(valid_params()) |> location_query() |> Map.get("code")

      family1 = TestStore.peek(code1).data.family_id
      family2 = TestStore.peek(code2).data.family_id

      assert family1 != family2
    end

    test "the family_id survives redemption onto the grant" do
      conn = call(valid_params())
      code = location_query(conn)["code"]
      family_id = TestStore.peek(code).data.family_id

      assert {:ok, grant} =
               AuthorizationCode.redeem(TestStore, code, %{
                 redirect_uri: @redirect_uri,
                 code_verifier: @code_verifier,
                 client_id: @client_id
               })

      assert grant.family_id == family_id
    end
  end

  # ── Stub host callbacks ────────────────────────────────────────────────────

  # The authorization endpoint never mints a token, so the signing key is never
  # exercised here. `AttestoPhoenix.Config` only requires `:keystore` to be
  # present (non-nil); this minimal keystore satisfies that without any
  # committed key material.
  defmodule TestKeystore do
    @moduledoc false
    @behaviour Attesto.Keystore

    @pem JOSE.JWK.generate_key({:rsa, 2048}) |> JOSE.JWK.to_pem() |> elem(1)

    @impl true
    def signing_pem, do: @pem

    @impl true
    def verification_pems, do: [@pem]
  end

  defmodule NoRepo do
    @moduledoc false
  end

  def load_client(@client_id), do: {:ok, %{id: @client_id}}
  def load_client(_), do: {:error, :not_found}

  def verify_secret(_, _), do: false

  def load_principal(_), do: {:error, :not_found}

  def client_id(%{id: id}), do: id

  def client_redirect_uris(%{id: @client_id}), do: [@redirect_uri]
  def client_redirect_uris(_), do: []

  # The default stub establishes a fixed subject. It echoes the `auth_opts`
  # the controller threaded in (prompt/force_reauth/interactive/max_age) into
  # the test process so the prompt/max_age tests can assert the controller
  # passed the right directives, and bumps `auth_time` when a re-auth was asked
  # for (prompt=login or a max_age the existing auth_time would violate).
  @established_auth_time 1_700_000_000
  @reauth_auth_time 1_700_009_999

  def authenticate(_conn, _request, auth_opts) do
    send(self(), {:auth_opts, auth_opts})

    auth_time =
      if auth_opts.force_reauth or max_age_violated?(auth_opts.max_age) do
        @reauth_auth_time
      else
        @established_auth_time
      end

    {:authenticated,
     %{
       subject: "user-42",
       auth_time: auth_time,
       acr: "urn:mace:incommon:iap:silver",
       amr: ["pwd"]
     }}
  end

  # The existing authentication is at @established_auth_time; treat a max_age of
  # 0 (or any value the fixed clock in this stub would exceed) as requiring a
  # re-auth. The tests only need the "max_age=0 forces re-auth" case.
  defp max_age_violated?(nil), do: false
  defp max_age_violated?(max_age) when is_integer(max_age), do: max_age == 0

  def consent(_conn, _request, subject), do: {:consented, subject}
end
