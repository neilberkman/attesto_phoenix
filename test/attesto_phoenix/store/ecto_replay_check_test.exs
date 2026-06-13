defmodule AttestoPhoenix.Store.EctoReplayCheckTest do
  @moduledoc """
  Tests for the Ecto-backed DPoP `jti` replay check (RFC 9449 §11.1):
  atomic record-and-check, replay rejection on the unique constraint, and
  the expired-row sweep.

  Tagged `:ecto` so it runs only when a SQL backend is available (see
  `test/test_helper.exs`).
  """

  use AttestoPhoenix.DataCase, async: true

  alias AttestoPhoenix.Schema.DPoPReplay
  alias AttestoPhoenix.Store.EctoReplayCheck
  alias Ecto.Adapters.SQL.Sandbox

  @moduletag :ecto

  describe "check_and_record/2" do
    test "records a fresh jti and returns :ok" do
      assert EctoReplayCheck.check_and_record("jti-fresh", 60) == :ok
      assert TestRepo.get(DPoPReplay, "jti-fresh")
    end

    test "rejects the second presentation of the same jti as a replay" do
      assert EctoReplayCheck.check_and_record("jti-dup", 60) == :ok
      assert EctoReplayCheck.check_and_record("jti-dup", 60) == {:error, :replay}
    end

    test "a still-present expired row rejects a repeat as a replay (fail closed)" do
      # A prior row whose TTL already elapsed is a unique-constraint
      # collision, not an overwrite. Correctness is preserved because DPoP
      # freshness rejects the stale proof before replay is consulted.
      insert_replay("jti-stale", DateTime.add(DateTime.utc_now(), -1, :second))
      assert EctoReplayCheck.check_and_record("jti-stale", 60) == {:error, :replay}
    end

    test "sizes expires_at from the ttl argument" do
      before = DateTime.utc_now()
      assert EctoReplayCheck.check_and_record("jti-ttl", 120) == :ok

      record = TestRepo.get(DPoPReplay, "jti-ttl")
      delta = DateTime.diff(record.expires_at, before, :second)
      assert delta >= 119 and delta <= 121
    end

    test "defaults the ttl to 60 seconds when called with one argument" do
      before = DateTime.utc_now()
      assert EctoReplayCheck.check_and_record("jti-default-ttl") == :ok

      record = TestRepo.get(DPoPReplay, "jti-default-ttl")
      delta = DateTime.diff(record.expires_at, before, :second)
      assert delta >= 59 and delta <= 61
    end

    test "rejects a non-positive ttl via the guard" do
      assert_raise FunctionClauseError, fn ->
        EctoReplayCheck.check_and_record("jti", 0)
      end
    end

    test "distinct jti values are each recorded independently" do
      assert EctoReplayCheck.check_and_record("jti-a", 60) == :ok
      assert EctoReplayCheck.check_and_record("jti-b", 60) == :ok
      assert EctoReplayCheck.check_and_record("jti-c", 60) == :ok
    end

    test "exactly one of two concurrent records of the same jti wins" do
      owner = self()

      results =
        ["jti-race", "jti-race"]
        |> Task.async_stream(
          fn jti ->
            # Each task runs in its own process; grant it the test's sandboxed
            # connection so both inserts hit the same transaction state.
            Sandbox.allow(TestRepo, owner, self())
            EctoReplayCheck.check_and_record(jti, 60)
          end,
          max_concurrency: 2
        )
        |> Enum.map(fn {:ok, result} -> result end)

      # The unique constraint serialises on the key: one winner, one replay.
      assert Enum.sort(results) == Enum.sort([:ok, {:error, :replay}])
    end
  end

  describe "sweep/0" do
    test "deletes only rows whose expires_at has elapsed and returns the count" do
      insert_replay("expired-1", DateTime.add(DateTime.utc_now(), -120, :second))
      insert_replay("expired-2", DateTime.add(DateTime.utc_now(), -1, :second))
      insert_replay("live-1", DateTime.add(DateTime.utc_now(), 600, :second))

      assert EctoReplayCheck.sweep() == 2

      refute TestRepo.get(DPoPReplay, "expired-1")
      refute TestRepo.get(DPoPReplay, "expired-2")
      assert TestRepo.get(DPoPReplay, "live-1")
    end

    test "a swept jti can be recorded again" do
      insert_replay("recyclable", DateTime.add(DateTime.utc_now(), -60, :second))

      assert EctoReplayCheck.sweep() == 1
      assert EctoReplayCheck.check_and_record("recyclable", 60) == :ok
    end
  end

  defp insert_replay(jti, expires_at) do
    %DPoPReplay{}
    |> DPoPReplay.changeset(%{jti: jti, expires_at: expires_at})
    |> TestRepo.insert!()
  end
end
