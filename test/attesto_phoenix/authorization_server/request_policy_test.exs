defmodule AttestoPhoenix.AuthorizationServer.RequestPolicyTest do
  use ExUnit.Case, async: true

  alias AttestoPhoenix.AuthorizationServer.RequestPolicy
  alias AttestoPhoenix.Config

  # Clients classified through the config callbacks below.
  @public %{id: "public-1", public?: true}
  @dpop %{id: "dpop-1"}
  @mtls %{id: "mtls-1"}
  @confidential %{id: "conf-1"}

  defmodule StubKeystore do
    @moduledoc false
  end

  defmodule StubRepo do
    @moduledoc false
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

  defp config(overrides) do
    fields =
      required_fields()
      |> Keyword.merge(
        client_public?: fn client -> Map.get(client, :public?, false) == true end,
        client_requires_dpop?: fn client -> Map.get(client, :id) == "dpop-1" end,
        client_requires_mtls?: fn client -> Map.get(client, :id) == "mtls-1" end
      )
      |> Keyword.merge(overrides)

    struct!(Config, fields)
  end

  describe "require_pkce?/2" do
    test "a public client always requires PKCE, even with the global flag relaxed" do
      assert RequestPolicy.require_pkce?(config(require_pkce: false), @public)
    end

    test "a DPoP sender-constrained (FAPI) client requires PKCE despite confidential auth" do
      # FAPI 2.0 §5.3.1.2: PKCE is mandatory for the FAPI client even though it
      # authenticates with private_key_jwt and the host relaxed :require_pkce for
      # Basic-profile compatibility.
      assert RequestPolicy.require_pkce?(config(require_pkce: false), @dpop)
    end

    test "an mTLS sender-constrained client requires PKCE despite the relaxed flag" do
      assert RequestPolicy.require_pkce?(config(require_pkce: false), @mtls)
    end

    test "a plain confidential client follows the global flag (relaxed -> no PKCE)" do
      # The OpenID Connect Basic profile drives a no-PKCE confidential flow; the
      # relaxation must still reach it so that profile can run.
      refute RequestPolicy.require_pkce?(config(require_pkce: false), @confidential)
    end

    test "a plain confidential client requires PKCE when the global flag is set" do
      assert RequestPolicy.require_pkce?(config(require_pkce: true), @confidential)
    end
  end
end
