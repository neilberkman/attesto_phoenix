defmodule Mix.Tasks.AttestoPhoenix.InstallTest do
  @moduledoc """
  Smoke test for the `mix attesto_phoenix.install` Igniter installer.

  The installer's contract is that it is idempotent and re-runnable (see the
  task moduledoc): the first run scaffolds the config, the routes, and the host
  callback modules; a second run on the already-installed project changes
  nothing. These tests drive the task through `Igniter.Test` against a synthetic
  project seeded with a minimal Phoenix-style router, so the suite is
  deterministic and does NOT depend on the `phx_new` Hex archive (which
  `phx_test_project/1` requires). File-level effects are asserted with
  `assert_creates/2`; config/router content is read straight off the rewritten
  source so the test does not depend on the exact unified-diff rendering.
  """

  use ExUnit.Case, async: true

  import Igniter.Test

  @task "attesto_phoenix.install"

  # The synthetic project's app is `:test` with module prefix `Test`, so the
  # scaffolded callbacks land under `Test.AuthZ.*` and the router (seeded below)
  # is `TestWeb.Router` at `lib/test_web/router.ex`.
  @client_store_path "lib/test/auth_z/client_store.ex"
  @principal_store_path "lib/test/auth_z/principal_store.ex"
  @scope_policy_path "lib/test/auth_z/scope_policy.ex"
  @consent_policy_path "lib/test/auth_z/consent_policy.ex"
  @registration_store_path "lib/test/auth_z/registration_store.ex"
  @event_sink_path "lib/test/auth_z/event_sink.ex"
  @router_path "lib/test_web/router.ex"
  @config_path "config/config.exs"

  # A minimal `Phoenix.Router` the installer can find and mount into. Seeded as a
  # fixture so the test never shells out to the phx_new generator.
  @router_fixture """
  defmodule TestWeb.Router do
    use Phoenix.Router

    scope "/", TestWeb do
      get "/", PageController, :home
    end
  end
  """

  defp project do
    test_project(files: %{@router_path => @router_fixture})
  end

  describe "first run" do
    test "scaffolds the config, the callback modules, and mounts the routes" do
      igniter = Igniter.compose_task(project(), @task, [])

      # One scaffolded host module per recommended behaviour.
      igniter
      |> assert_creates(@client_store_path)
      |> assert_creates(@principal_store_path)
      |> assert_creates(@scope_policy_path)
      |> assert_creates(@consent_policy_path)
      |> assert_creates(@registration_store_path)
      |> assert_creates(@event_sink_path)

      applied = apply_igniter!(igniter)

      # The AttestoPhoenix.Config skeleton is written under the host's otp_app.
      config = source_content(applied, @config_path)
      assert config =~ "config :test, AttestoPhoenix.Config"
      assert config =~ "oauth_path_prefix: \"/oauth\""
      assert config =~ "code_store: AttestoPhoenix.Store.EctoCodeStore"
      assert config =~ "load_client: {Test.AuthZ.ClientStore, :load_client}"

      # The router gains the server scope mounting attesto_routes/1 and the use.
      router = source_content(applied, @router_path)
      assert router =~ "use AttestoPhoenix.Router"
      assert router =~ "attesto_routes()"

      # A scaffolded module tags the behaviour and stubs each callback.
      client_store = source_content(applied, @client_store_path)
      assert client_store =~ "@behaviour AttestoPhoenix.ClientStore"
      assert client_store =~ "def load_client(_arg1) do"
      assert client_store =~ "def verify_client_secret(_arg1, _arg2) do"
    end

    test "honors a relocated --oauth-path-prefix" do
      applied =
        project()
        |> Igniter.compose_task(@task, ["--oauth-path-prefix", "/mcp/oauth"])
        |> apply_igniter!()

      assert source_content(applied, @config_path) =~ "oauth_path_prefix: \"/mcp/oauth\""
      assert source_content(applied, @router_path) =~ "attesto_routes(prefix: \"/mcp\")"
    end
  end

  describe "re-run idempotency" do
    test "a second run on the installed project changes nothing" do
      first =
        project()
        |> Igniter.compose_task(@task, [])
        |> apply_igniter!()

      # Running the installer again against the already-installed project must be
      # a no-op: no duplicated config key, no second router scope, no clobbered
      # (host-edited) callback modules.
      first
      |> Igniter.compose_task(@task, [])
      |> assert_unchanged()
    end
  end

  defp source_content(igniter, path) do
    igniter.rewrite
    |> Rewrite.source!(path)
    |> Rewrite.Source.get(:content)
  end
end
