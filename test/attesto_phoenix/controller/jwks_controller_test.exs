defmodule AttestoPhoenix.Controller.JWKSControllerTest do
  @moduledoc false
  # The keystore is resolved from the application environment by the inline
  # TestKeystore, so these run serially.
  use ExUnit.Case, async: false

  import Plug.Test
  import Plug.Conn

  alias AttestoPhoenix.Config
  alias AttestoPhoenix.Controller.JWKSController

  # The configured AttestoPhoenix.Config is read from conn.private under this
  # key by the controller (placed there by the host pipeline in production).
  @config_key :attesto_phoenix_config

  # An inline keystore that publishes the verification PEMs stashed in the
  # application environment, so a test can vary the key set without committed
  # key material.
  defmodule TestKeystore do
    @moduledoc false
    @behaviour Attesto.Keystore

    @impl true
    def signing_pem do
      [pem | _] = pems()
      pem
    end

    @impl true
    def verification_pems, do: pems()

    defp pems do
      :attesto_phoenix
      |> Application.fetch_env!(__MODULE__)
      |> Keyword.fetch!(:verification_pems)
    end
  end

  # A throwaway RSA keypair generated at test time.
  defp gen_pem do
    {:rsa, 2048}
    |> JOSE.JWK.generate_key()
    |> JOSE.JWK.to_pem()
    |> elem(1)
  end

  defp build_config(verification_pems) do
    Application.put_env(:attesto_phoenix, TestKeystore, verification_pems: verification_pems)
    on_exit(fn -> Application.delete_env(:attesto_phoenix, TestKeystore) end)

    Config.new(
      issuer: "https://issuer.example",
      keystore: TestKeystore,
      repo: __MODULE__.Repo,
      load_client: fn _ -> {:error, :not_found} end,
      verify_client_secret: fn _, _ -> false end,
      load_principal: fn _ -> {:error, :not_found} end
    )
  end

  defp call_show(config) do
    :get
    |> conn("/.well-known/jwks.json")
    |> put_private(@config_key, config)
    |> JWKSController.show(%{})
  end

  defp body(conn), do: JSON.decode!(conn.resp_body)

  describe "show/2" do
    test "renders one public JWK per verification key (RFC 7517 §5)" do
      pem = gen_pem()
      conn = call_show(build_config([pem]))

      assert conn.status == 200
      assert %{"keys" => [jwk]} = body(conn)
      assert jwk["kty"] == "RSA"
      assert jwk["use"] == "sig"
      assert jwk["alg"] == "RS256"
      assert is_binary(jwk["kid"])
      assert is_binary(jwk["n"])
      assert is_binary(jwk["e"])
    end

    test "publishes only public key material (RFC 7517 §1)" do
      conn = call_show(build_config([gen_pem()]))
      %{"keys" => [jwk]} = body(conn)

      for private_member <- ~w(d p q dp dq qi) do
        refute Map.has_key?(jwk, private_member),
               "JWK Set leaked private member #{inspect(private_member)}"
      end
    end

    test "covers a rotation window by publishing every verification key" do
      outgoing = gen_pem()
      incoming = gen_pem()
      conn = call_show(build_config([outgoing, incoming]))

      %{"keys" => keys} = body(conn)
      kids = Enum.map(keys, & &1["kid"])

      assert length(keys) == 2
      assert length(Enum.uniq(kids)) == 2
    end

    test "marks the response publicly cacheable (RFC 9111 §5.2.2)" do
      conn = call_show(build_config([gen_pem()]))

      assert [cache_control] = get_resp_header(conn, "cache-control")
      assert cache_control =~ "public"
      assert cache_control =~ ~r/max-age=\d+/
    end

    test "responds with the RFC 7517 jwk-set media type" do
      conn = call_show(build_config([gen_pem()]))

      assert [content_type] = get_resp_header(conn, "content-type")
      assert content_type =~ "application/jwk-set+json"
    end

    test "fails closed when no config is present in conn.private" do
      conn = conn(:get, "/.well-known/jwks.json")

      assert_raise ArgumentError, ~r/no %AttestoPhoenix.Config\{\}/, fn ->
        JWKSController.show(conn, %{})
      end
    end
  end
end
