defmodule AttestoPhoenix.ConfigTest do
  use ExUnit.Case, async: true

  alias Attesto.RequestObject.Policy
  alias AttestoPhoenix.Config

  # A behaviour module that implements every ClientStore callback the resolver
  # routes through `:client_store`, plus the principal/scope/event/consent/
  # registration callbacks the other behaviour-module keys route through. Each
  # callback returns a sentinel so a test can assert the resolved `{module,
  # function}` was actually invoked (not just the flat key).
  defmodule FullStore do
    @behaviour AttestoPhoenix.ClientStore
    @behaviour AttestoPhoenix.ConsentPolicy
    @behaviour AttestoPhoenix.EventSink
    @behaviour AttestoPhoenix.PrincipalStore
    @behaviour AttestoPhoenix.RegistrationStore
    @behaviour AttestoPhoenix.ScopePolicy

    # ClaimsProvider's build_principal/3 collides with PrincipalStore's, so this
    # module satisfies ClaimsProvider by exporting the functions without the
    # `@behaviour` annotation (the resolver checks `function_exported?`, not the
    # declared behaviours).

    @impl AttestoPhoenix.ClientStore
    def load_client(_client_id), do: {:ok, :store_client}
    @impl AttestoPhoenix.ClientStore
    def verify_client_secret(_client, _secret), do: true
    @impl AttestoPhoenix.ClientStore
    def client_id(_client), do: "store-client-id"
    @impl AttestoPhoenix.ClientStore
    def client_jwks(_client), do: %{"keys" => []}
    @impl AttestoPhoenix.ClientStore
    def client_redirect_uris(_client), do: ["https://store.example/cb"]
    @impl AttestoPhoenix.ClientStore
    def client_public?(_client), do: true
    @impl AttestoPhoenix.ClientStore
    def client_requires_mtls?(_client), do: true
    @impl AttestoPhoenix.ClientStore
    def client_requires_dpop?(_client), do: true
    @impl AttestoPhoenix.ClientStore
    def client_grant_types(_client), do: ["authorization_code"]

    @impl AttestoPhoenix.PrincipalStore
    def load_principal(_subject_id), do: {:ok, :store_principal}
    @impl AttestoPhoenix.PrincipalStore
    def build_principal(_client, subject, _scope), do: %{subject: subject}

    @impl AttestoPhoenix.ScopePolicy
    def authorize_scope(_client, scope), do: {:ok, scope}

    @impl AttestoPhoenix.ConsentPolicy
    def authenticate_resource_owner(_conn, _request, _opts), do: {:none}
    @impl AttestoPhoenix.ConsentPolicy
    def consent(_conn, _request, subject), do: {:consented, subject}

    @impl AttestoPhoenix.EventSink
    def on_event(_event), do: :store_emitted

    @impl AttestoPhoenix.RegistrationStore
    def register_client(_attrs), do: {:ok, :registered}
    @impl AttestoPhoenix.RegistrationStore
    def unregister_client(_client), do: :ok
    @impl AttestoPhoenix.RegistrationStore
    def client_registration_access_token_hash(_client), do: "store-hash"

    # Satisfies AttestoPhoenix.ClaimsProvider.build_userinfo_claims/3.
    def build_userinfo_claims(_subject, _scopes, _requested), do: %{"from" => "store"}
  end

  # A module that exports none of the callbacks the resolver wants. Installed
  # under a behaviour-module key it makes the resolver fall through to `nil`
  # (for optional callbacks); used to drive the boot-validation failure path
  # for required callbacks.
  defmodule EmptyModule do
  end

  # A ClientStore exporting only the two required callbacks; its optional
  # callbacks are absent so the resolver falls through to nil for them.
  defmodule RequiredOnlyStore do
    @behaviour AttestoPhoenix.ClientStore

    @impl true
    def load_client(_client_id), do: {:error, :not_found}
    @impl true
    def verify_client_secret(_client, _secret), do: false
  end

  # A module installed as :client_store that omits the required
  # verify_client_secret/2, driving the boot-validation failure path.
  defmodule LoadOnlyStore do
    def load_client(_client_id), do: {:error, :not_found}
  end

  # The minimal required-key set. Required callbacks stay flat (this phase keeps
  # the flat keys as the required surface); overrides layer behaviour-module
  # keys or competing flat callbacks on top.
  defp config(overrides \\ []) do
    base = [
      issuer: "https://issuer.example",
      keystore: __MODULE__.Keystore,
      repo: __MODULE__.Repo,
      load_client: fn _ -> {:error, :not_found} end,
      verify_client_secret: fn _, _ -> false end,
      load_principal: fn _ -> {:error, :not_found} end
    ]

    Config.new(Keyword.merge(base, overrides))
  end

  # Like `config/1` but supplies NONE of the flat required callbacks, so the
  # required capabilities (load_client, verify_client_secret, load_principal)
  # must be satisfied by installed behaviour modules. Exercises the real
  # `Config.new/1` boot surface, not `struct/2`.
  defp behaviour_only_config(overrides) do
    base = [
      issuer: "https://issuer.example",
      keystore: __MODULE__.Keystore,
      repo: __MODULE__.Repo
    ]

    Config.new(Keyword.merge(base, overrides))
  end

  describe "resolve_callback/2 precedence" do
    test "an explicit flat key wins over an installed behaviour module" do
      flat = fn _ -> :flat end
      cfg = config(client_store: FullStore, client_id: flat)

      assert Config.resolve_callback(cfg, :client_id) == flat
      assert Config.client_id_fun(cfg) == flat
    end

    test "falls back to {module, function} when the module exports the callback" do
      cfg = config(client_store: FullStore)

      assert Config.resolve_callback(cfg, :client_id) == {FullStore, :client_id}
      assert Config.client_id_fun(cfg) == {FullStore, :client_id}
    end

    test "resolves nil when neither a flat key nor an exporting module is set" do
      cfg = config()

      assert Config.resolve_callback(cfg, :client_id) == nil
      assert Config.client_id_fun(cfg) == nil
    end

    test "resolves nil when an installed module does not export the optional callback" do
      # RequiredOnlyStore exports only the required ClientStore callbacks. An
      # optional callback it omits (`client_jwks/1`) must resolve to nil. The
      # required flat keys are unset here (built via `struct/2`, bypassing the
      # @enforce_keys surface) to isolate the module-resolution path.
      cfg =
        struct(Config, %{
          issuer: "https://issuer.example",
          keystore: __MODULE__.Keystore,
          repo: __MODULE__.Repo,
          client_store: RequiredOnlyStore
        })

      assert Config.load_client_fun(cfg) == {RequiredOnlyStore, :load_client}
      assert Config.client_jwks_fun(cfg) == nil
    end

    test "every named resolver fun strips a trailing ? from its key" do
      cfg = config(client_store: FullStore)

      assert Config.client_public_fun(cfg) == {FullStore, :client_public?}
      assert Config.client_requires_mtls_fun(cfg) == {FullStore, :client_requires_mtls?}
      assert Config.client_requires_dpop_fun(cfg) == {FullStore, :client_requires_dpop?}
    end

    test "principal/scope/consent/event/registration/claims keys resolve to their module" do
      cfg =
        config(
          principal_store: FullStore,
          scope_policy: FullStore,
          consent_policy: FullStore,
          event_sink: FullStore,
          registration: FullStore,
          claims_provider: FullStore
        )

      assert Config.build_principal_fun(cfg) == {FullStore, :build_principal}
      assert Config.authorize_scope_fun(cfg) == {FullStore, :authorize_scope}
      assert Config.consent_fun(cfg) == {FullStore, :consent}

      assert Config.authenticate_resource_owner_fun(cfg) ==
               {FullStore, :authenticate_resource_owner}

      assert Config.on_event_fun(cfg) == {FullStore, :on_event}
      assert Config.unregister_client_fun(cfg) == {FullStore, :unregister_client}

      assert Config.client_registration_access_token_hash_fun(cfg) ==
               {FullStore, :client_registration_access_token_hash}

      assert Config.build_userinfo_claims_fun(cfg) == {FullStore, :build_userinfo_claims}
    end
  end

  describe "client_store_load/2 and client_store_verify_secret/3" do
    test "invoke the resolved flat callback" do
      cfg =
        config(
          load_client: fn id -> {:ok, {:loaded, id}} end,
          verify_client_secret: fn _client, secret -> secret == "good" end
        )

      assert Config.client_store_load(cfg, "abc") == {:ok, {:loaded, "abc"}}
      assert Config.client_store_verify_secret(cfg, :client, "good") == true
      assert Config.client_store_verify_secret(cfg, :client, "bad") == false
    end

    test "invoke the resolved behaviour module when no flat callback is set" do
      # Required flat keys unset (via `struct/2`) so the installed module wins.
      cfg =
        struct(Config, %{
          issuer: "https://issuer.example",
          keystore: __MODULE__.Keystore,
          repo: __MODULE__.Repo,
          client_store: FullStore
        })

      assert Config.client_store_load(cfg, "abc") == {:ok, :store_client}
      assert Config.client_store_verify_secret(cfg, :client, "whatever") == true
    end
  end

  describe "build_userinfo_claims/4" do
    test "raises when no claim source is configured" do
      cfg = config()

      assert_raise ArgumentError, ~r/:build_userinfo_claims is required/, fn ->
        Config.build_userinfo_claims(cfg, "sub", ["openid"], %{})
      end
    end

    test "uses an explicit flat callback (3-arity userinfo contract)" do
      cfg = config(build_userinfo_claims: fn _sub, _scopes, _req -> %{"from" => "flat"} end)

      assert Config.build_userinfo_claims(cfg, "sub", ["openid"], %{}) == %{"from" => "flat"}
    end

    test "uses an installed :claims_provider module" do
      cfg = config(claims_provider: FullStore)

      assert Config.build_userinfo_claims(cfg, "sub", ["openid"], %{}) == %{"from" => "store"}
    end
  end

  describe "new/1 boot-time behaviour-module conformance" do
    test "accepts a module that exports every required behaviour callback" do
      assert %Config{} = config(client_store: FullStore)
    end

    test "rejects a behaviour module missing a required callback" do
      assert_raise ArgumentError, ~r/does not export verify_client_secret\/2/, fn ->
        config(client_store: __MODULE__.LoadOnlyStore)
      end
    end

    test "rejects a behaviour-module key that is not a module" do
      assert_raise ArgumentError, ~r/must be a module implementing/, fn ->
        config(scope_policy: "not a module")
      end
    end

    test "rejects a module that cannot be loaded" do
      assert_raise ArgumentError, ~r/cannot be loaded/, fn ->
        config(event_sink: Definitely.Not.A.Real.Module)
      end
    end

    test "does not require optional behaviour callbacks" do
      # consent_policy callbacks are both optional, so a module exporting none
      # of them is accepted; the resolver simply returns nil for each.
      assert %Config{} = cfg = config(consent_policy: EmptyModule)
      assert Config.consent_fun(cfg) == nil
    end

    test "accepts required capabilities supplied entirely by behaviour modules (no flat callbacks)" do
      # The advertised feature: install :client_store and :principal_store and
      # the required callbacks resolve from them, with NO flat load_client /
      # verify_client_secret / load_principal keys present.
      cfg = behaviour_only_config(client_store: FullStore, principal_store: FullStore)

      assert %Config{} = cfg
      assert Config.load_client_fun(cfg) == {FullStore, :load_client}
      assert Config.verify_client_secret_fun(cfg) == {FullStore, :verify_client_secret}
      assert Config.load_principal_fun(cfg) == {FullStore, :load_principal}
    end

    test "accepts a behaviour module for one capability and a flat callback for another" do
      cfg =
        behaviour_only_config(
          client_store: FullStore,
          load_principal: fn _ -> {:ok, :flat_principal} end
        )

      assert %Config{} = cfg
      assert Config.load_client_fun(cfg) == {FullStore, :load_client}
      assert is_function(Config.load_principal_fun(cfg), 1)
    end

    test "rejects when a required capability resolves to neither a flat key nor a module" do
      # client_store satisfies load_client/verify_client_secret, but nothing
      # provides load_principal: the capability is unresolved and boot fails.
      assert_raise ArgumentError, ~r/:load_principal capability is required but unresolved/, fn ->
        behaviour_only_config(client_store: FullStore)
      end
    end

    test "rejects when no required capability is wired at all" do
      assert_raise ArgumentError, ~r/:load_client capability is required but unresolved/, fn ->
        behaviour_only_config([])
      end
    end
  end

  describe "registration_enabled boot gate" do
    test "accepts an installed :registration module in place of the flat key" do
      assert %Config{} = config(registration_enabled: true, registration: FullStore)
    end

    test "still accepts the flat :register_client key" do
      assert %Config{} =
               config(registration_enabled: true, register_client: fn _ -> {:ok, :c} end)
    end

    test "rejects when neither the flat key nor a module is wired" do
      assert_raise ArgumentError, ~r/:register_client is required/, fn ->
        config(registration_enabled: true)
      end
    end
  end

  describe ":client_auth_signing_algs" do
    test "defaults to the FAPI 2 set when unset" do
      assert config().client_auth_signing_algs == Attesto.SigningAlg.fapi_algs()
    end

    test "is overridable by the host" do
      algs = ["PS256", "ES256", "RS256"]
      assert config(client_auth_signing_algs: algs).client_auth_signing_algs == algs
    end
  end

  describe ":request_object_policy" do
    test "defaults to the generic %Policy{} when unset" do
      assert config().request_object_policy == %Policy{}
    end

    test "accepts an Attesto.RequestObject.Policy" do
      # A policy that requires a signed request object needs :client_jwks; pair
      # them so the config is valid (see the boot-rejection test below).
      policy = Policy.fapi_message_signing()

      built =
        config(request_object_policy: policy, client_jwks: fn _ -> %{"keys" => []} end)

      assert built.request_object_policy == policy
    end

    test "rejects a non-Policy value at boot" do
      assert_raise ArgumentError, ~r/:request_object_policy must be an/, fn ->
        config(request_object_policy: :fapi)
      end
    end

    test "rejects a required-request-object policy without :client_jwks at boot" do
      # An unsatisfiable config: every authorization request would be rejected
      # (one with no request object fails the policy; one with a request object
      # fails verification for want of keys). Fail fast rather than deploy it.
      assert_raise ArgumentError, ~r/needs a way to resolve a client's trusted JWKS/, fn ->
        config(request_object_policy: Policy.fapi_message_signing())
      end
    end

    test "accepts a required-request-object policy when :client_jwks resolves via :client_store" do
      # The capability may come from an installed :client_store, not only a flat
      # :client_jwks callback.
      policy = Policy.fapi_message_signing()
      built = config(request_object_policy: policy, client_store: FullStore)

      assert built.request_object_policy == policy
    end
  end
end
