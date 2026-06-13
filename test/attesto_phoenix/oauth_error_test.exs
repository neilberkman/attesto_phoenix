defmodule AttestoPhoenix.OAuthErrorTest do
  use ExUnit.Case, async: true

  alias AttestoPhoenix.Config
  alias AttestoPhoenix.OAuthError

  # A host that serializes the error envelope as plain text instead of JSON,
  # used to prove the `:send_error` transport callback is honored.
  defmodule TextSender do
    def render(conn, status, body) do
      conn
      |> Plug.Conn.put_resp_content_type("text/plain")
      |> Plug.Conn.send_resp(status, body["error"])
      |> Plug.Conn.halt()
    end
  end

  # A minimal valid config. The wire helpers read the optional transport
  # callbacks (`:send_error`, `:no_store`, `:www_authenticate`, `:basic_realm`)
  # defensively via `Map.get/2`, so a host that supplies them overrides the
  # default transport.
  defp config(overrides \\ []) do
    [
      issuer: "https://issuer.example",
      keystore: __MODULE__.FakeKeystore,
      repo: __MODULE__.FakeRepo,
      load_client: fn _ -> {:error, :not_found} end,
      verify_client_secret: fn _, _ -> false end,
      load_principal: fn _ -> {:error, :not_found} end
    ]
    |> Keyword.merge(overrides)
    |> Config.new()
  end

  # Build a conn carrying a config in `conn.private`, as the router pipeline
  # would. Pass `config: nil` to exercise the no-config default-transport path.
  defp conn(opts \\ []) do
    method = Keyword.get(opts, :method, "POST")
    base = Plug.Test.conn(method, "/oauth/token")

    case Keyword.fetch(opts, :config) do
      {:ok, nil} -> base
      {:ok, cfg} -> Plug.Conn.put_private(base, :attesto_phoenix_config, cfg)
      :error -> Plug.Conn.put_private(base, :attesto_phoenix_config, config())
    end
  end

  defp body(conn), do: JSON.decode!(conn.resp_body)

  defp header(conn, name), do: Plug.Conn.get_resp_header(conn, name)

  describe "new/2,3 (RFC 6749 §5.2 error value)" do
    test "carries the code and description" do
      error = OAuthError.new(:invalid_request, "missing required parameter: grant_type")

      assert %OAuthError{} = error
      assert error.error == :invalid_request
      assert error.error_description == "missing required parameter: grant_type"
    end

    test "defaults the status from the RFC 6749 §5.2 mapping" do
      assert OAuthError.new(:invalid_request).status == 400
      assert OAuthError.new(:invalid_token).status == 401
      assert OAuthError.new(:insufficient_scope).status == 403
      assert OAuthError.new(:not_found).status == 404
    end

    test "honors an explicit status override" do
      assert OAuthError.new(:invalid_client, "x", status: 401).status == 401
    end
  end

  describe "render/2 (RFC 6749 §5.2 endpoint errors)" do
    test "writes the error envelope and the no-store headers" do
      error = OAuthError.new(:invalid_request, "Missing required parameter: grant_type.")
      conn = OAuthError.render(conn(), error)

      assert conn.status == 400
      assert conn.halted

      assert body(conn) == %{
               "error" => "invalid_request",
               "error_description" => "Missing required parameter: grant_type."
             }

      assert header(conn, "cache-control") == ["no-store"]
      assert header(conn, "pragma") == ["no-cache"]
      assert header(conn, "content-type") == ["application/json; charset=utf-8"]
    end

    test "omits error_description when none was supplied" do
      conn = OAuthError.render(conn(), OAuthError.new(:invalid_request))

      assert body(conn) == %{"error" => "invalid_request"}
    end

    test "raises invalid_client to 401 and adds the Basic challenge when Authorization was attempted" do
      conn =
        conn()
        |> Plug.Conn.put_req_header("authorization", "Basic Zm9vOmJhcg==")
        |> OAuthError.render(OAuthError.new(:invalid_client, "bad creds"))

      assert conn.status == 401
      assert header(conn, "www-authenticate") == [~s(Basic realm="OAuth")]
    end

    test "keeps invalid_client at 400 without an Authorization attempt" do
      conn = OAuthError.render(conn(), OAuthError.new(:invalid_client, "bad creds"))

      assert conn.status == 400
      assert header(conn, "www-authenticate") == []
    end

    test "honors a custom realm from the :basic_realm config key" do
      conn =
        conn(config: config(basic_realm: "tokens"))
        |> Plug.Conn.put_req_header("authorization", "Basic Zm9vOmJhcg==")
        |> OAuthError.render(OAuthError.new(:invalid_client))

      assert header(conn, "www-authenticate") == [~s(Basic realm="tokens")]
    end

    test "uses the RFC-correct default transport when no config is on the conn" do
      conn = OAuthError.render(conn(config: nil), OAuthError.new(:invalid_request))

      assert conn.status == 400
      assert header(conn, "cache-control") == ["no-store"]
      assert body(conn) == %{"error" => "invalid_request"}
    end

    test "delegates serialization to a configured {module, fun} :send_error callback" do
      conn =
        OAuthError.render(
          conn(config: config(send_error: {TextSender, :render})),
          OAuthError.new(:invalid_request)
        )

      assert conn.status == 400
      assert conn.resp_body == "invalid_request"
      assert header(conn, "content-type") == ["text/plain; charset=utf-8"]
    end
  end

  describe "unauthorized/4 (RFC 6750 §3 / RFC 9449 §7.1 challenges)" do
    test "emits a Bearer challenge with error and description" do
      conn =
        OAuthError.unauthorized(conn(), :bearer, "invalid_token", description: "The access token expired.")

      assert conn.status == 401

      assert header(conn, "www-authenticate") == [
               ~s(Bearer error="invalid_token", error_description="The access token expired.")
             ]

      assert body(conn) == %{
               "error" => "invalid_token",
               "error_description" => "The access token expired."
             }

      assert header(conn, "cache-control") == ["no-store"]
    end

    test "emits a DPoP challenge with the RFC 9449 §5.1 algs auth-param" do
      conn =
        OAuthError.unauthorized(conn(), :dpop, "invalid_dpop_proof",
          description: "Signature did not verify.",
          algs: "ES256 RS256"
        )

      assert header(conn, "www-authenticate") == [
               ~s(DPoP error="invalid_dpop_proof", error_description="Signature did not verify.", algs="ES256 RS256")
             ]
    end

    test "includes a scope auth-param when supplied" do
      conn =
        OAuthError.unauthorized(conn(), :bearer, "insufficient_scope", scope: "tokens.read tokens.write")

      assert header(conn, "www-authenticate") == [
               ~s(Bearer error="insufficient_scope", scope="tokens.read tokens.write")
             ]
    end

    test "sets the DPoP-Nonce header when a nonce is supplied" do
      conn = OAuthError.unauthorized(conn(), :dpop, "use_dpop_nonce", dpop_nonce: "abc123")

      assert header(conn, "dpop-nonce") == ["abc123"]
    end

    test "escapes quotes and backslashes in auth-param values" do
      conn =
        OAuthError.unauthorized(conn(), :bearer, "invalid_token", description: ~s(quote " and back \\ slash))

      assert header(conn, "www-authenticate") == [
               ~s(Bearer error="invalid_token", error_description="quote \\" and back \\\\ slash")
             ]
    end
  end

  describe "use_dpop_nonce/3 (RFC 9449 §8 / §9)" do
    test "emits a DPoP challenge with use_dpop_nonce and the nonce header" do
      conn = OAuthError.use_dpop_nonce(conn(), "n-0S6_WzA2Mj")

      assert conn.status == 401
      assert header(conn, "dpop-nonce") == ["n-0S6_WzA2Mj"]
      assert [challenge] = header(conn, "www-authenticate")
      assert String.starts_with?(challenge, ~s(DPoP error="use_dpop_nonce"))
      assert body(conn)["error"] == "use_dpop_nonce"
    end
  end

  describe "insufficient_scope/3 (RFC 6750 §3.1)" do
    test "responds 403 naming the required scopes in the scope auth-param" do
      conn = OAuthError.insufficient_scope(conn(), ["a.read", "b.write"])

      assert conn.status == 403

      assert header(conn, "www-authenticate") == [
               ~s(Bearer error="insufficient_scope", error_description="The request requires higher privileges: a.read b.write", scope="a.read b.write")
             ]

      assert body(conn) == %{
               "error" => "insufficient_scope",
               "error_description" => "The request requires higher privileges: a.read b.write"
             }
    end

    test "can name the DPoP scheme" do
      conn = OAuthError.insufficient_scope(conn(), ["a.read"], :dpop)

      assert [challenge] = header(conn, "www-authenticate")
      assert String.starts_with?(challenge, "DPoP ")
    end
  end

  describe "no_store/2 (RFC 6749 §5.1)" do
    test "sets the cache-suppression headers by default" do
      conn = OAuthError.no_store(conn(), config())

      assert header(conn, "cache-control") == ["no-store"]
      assert header(conn, "pragma") == ["no-cache"]
    end

    test "delegates to a configured :no_store callback" do
      callback = fn conn -> Plug.Conn.put_resp_header(conn, "cache-control", "private") end
      conn = OAuthError.no_store(conn(), config(no_store: callback))

      assert header(conn, "cache-control") == ["private"]
      assert header(conn, "pragma") == []
    end
  end

  describe "www_authenticate/3" do
    test "sets the header by default" do
      conn = OAuthError.www_authenticate(conn(), config(), ~s(Bearer realm="x"))

      assert header(conn, "www-authenticate") == [~s(Bearer realm="x")]
    end

    test "delegates to a configured :www_authenticate callback" do
      callback = fn conn, challenge ->
        Plug.Conn.put_resp_header(conn, "x-www-authenticate", challenge)
      end

      conn = OAuthError.www_authenticate(conn(), config(www_authenticate: callback), "DPoP")

      assert header(conn, "x-www-authenticate") == ["DPoP"]
      assert header(conn, "www-authenticate") == []
    end
  end
end
