defmodule AttestoPhoenix.DataCase do
  @moduledoc """
  Test case template for tests that touch the SQL-backed test repository.

  Wraps each test in a sandboxed transaction and points the library's `:repo`
  configuration at `AttestoPhoenix.TestRepo` for the duration of the test,
  restoring any prior value afterwards.
  """

  use ExUnit.CaseTemplate

  alias Ecto.Adapters.SQL.Sandbox

  using do
    quote do
      # Every case that touches the database is tagged so a default run
      # (no SQL backend) excludes it via `ExUnit.configure(exclude: [:ecto])`
      # in test_helper.exs. Run them with `mix test --include ecto`.
      alias AttestoPhoenix.TestRepo

      @moduletag :ecto
    end
  end

  setup tags do
    pid =
      Sandbox.start_owner!(AttestoPhoenix.TestRepo, shared: not tags[:async])

    previous = Application.get_env(:attesto_phoenix, :repo)
    Application.put_env(:attesto_phoenix, :repo, AttestoPhoenix.TestRepo)

    on_exit(fn ->
      Sandbox.stop_owner(pid)

      case previous do
        nil -> Application.delete_env(:attesto_phoenix, :repo)
        value -> Application.put_env(:attesto_phoenix, :repo, value)
      end
    end)

    :ok
  end
end
