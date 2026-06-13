# Test bootstrap for the Ecto-backed store suite.
#
# Store tests are tagged `:ecto` and excluded by default; they run only when a
# SQL backend is available (e.g. `mix test --include ecto`). The database is
# provisioned only when those tests are actually included, so the default run
# needs no running SQL server. Each table has its own migration file under
# test/support/migrations, one migration module per file.

alias AttestoPhoenix.TestRepo

ExUnit.configure(exclude: [:ecto])

ecto_included? =
  ExUnit.configuration()
  |> Keyword.get(:include, [])
  |> Enum.any?(&(&1 == :ecto or match?({:ecto, _}, &1)))

if ecto_included? do
  Application.put_env(:attesto_phoenix, TestRepo,
    username: System.get_env("POSTGRES_USER", "postgres"),
    password: System.get_env("POSTGRES_PASSWORD", "postgres"),
    hostname: System.get_env("POSTGRES_HOST", "localhost"),
    database: System.get_env("POSTGRES_DB", "attesto_phoenix_test"),
    pool: Ecto.Adapters.SQL.Sandbox,
    pool_size: 10
  )

  {:ok, _} = Application.ensure_all_started(:ecto_sql)

  _ = TestRepo.__adapter__().storage_up(TestRepo.config())

  {:ok, _pid} = TestRepo.start_link()

  # Point the library's runtime `:repo` at the test repo once, globally, so the
  # store functions that resolve their repo from the application environment
  # (rather than from an explicit `AttestoPhoenix.Config`) find it. Set here
  # rather than per test so concurrent `async: true` tests never race on it.
  Application.put_env(:attesto_phoenix, :repo, TestRepo)

  Application.put_env(
    :attesto_phoenix,
    :refresh_successor_secret,
    String.duplicate("test-refresh-successor-", 4)
  )

  migrations_dir = Path.join(__DIR__, "support/migrations")

  # Each file under support/migrations defines exactly one migration module.
  migrations =
    migrations_dir
    |> File.ls!()
    |> Enum.filter(&String.ends_with?(&1, ".exs"))
    |> Enum.sort()
    |> Enum.with_index(fn file, index ->
      [{module, _bin} | _] = Code.compile_file(Path.join(migrations_dir, file))
      {index, module}
    end)

  Ecto.Migrator.run(TestRepo, migrations, :up, all: true, log: false)

  Ecto.Adapters.SQL.Sandbox.mode(TestRepo, :manual)
end

ExUnit.start()
