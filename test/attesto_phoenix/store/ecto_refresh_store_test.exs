defmodule AttestoPhoenix.Store.EctoRefreshStoreTest do
  @moduledoc """
  Behaviour conformance tests for the Ecto-backed refresh-token store.

  Exercises rotation reuse detection (RFC 6749 §10.4, OAuth 2.0 Security BCP):
  the unix-seconds and opaque-context boundary, the atomic single-use
  `consume/1` claim, replay of a consumed token surfacing as `{:reuse, _}`, and
  sticky family revocation that refuses a later insert. Tagged `:ecto`, so it
  runs only when a SQL backend is available (see `test/test_helper.exs`).
  """

  use AttestoPhoenix.DataCase, async: false

  alias AttestoPhoenix.Schema.RefreshToken
  alias AttestoPhoenix.Store.EctoRefreshStore
  alias Ecto.Adapters.SQL.Sandbox

  @moduletag :ecto

  defp entry(attrs \\ %{}) do
    Map.merge(
      %{
        token_hash: "hash-#{System.unique_integer([:positive])}",
        family_id: "fam-#{System.unique_integer([:positive])}",
        generation: 0,
        data: %{
          subject: "sub-1",
          scope: ["read"],
          client_id: "client-1",
          dpop_jkt: nil,
          claims: %{"k" => "v"}
        },
        expires_at: System.system_time(:second) + 3600,
        consumed: false
      },
      attrs
    )
  end

  defp with_data(entry, data_overrides) do
    %{entry | data: Map.merge(entry.data, data_overrides)}
  end

  describe "insert/1 and get/1" do
    test "round-trips an entry through the contract record shape" do
      e = entry()

      assert :ok = EctoRefreshStore.insert(e)
      assert {:ok, got} = EctoRefreshStore.get(e.token_hash)

      assert got.token_hash == e.token_hash
      assert got.family_id == e.family_id
      assert got.generation == e.generation
      # expires_at survives as absolute unix seconds across storage.
      assert got.expires_at == e.expires_at
      assert got.consumed == false

      # The opaque context round-trips field-for-field.
      assert got.data == e.data
    end

    test "folds a DPoP thumbprint into the cnf column and back" do
      e = entry() |> with_data(%{dpop_jkt: "thumb-xyz"})

      assert :ok = EctoRefreshStore.insert(e)
      assert {:ok, got} = EctoRefreshStore.get(e.token_hash)
      assert got.data.dpop_jkt == "thumb-xyz"
    end

    test "get/1 returns :error for an unknown token" do
      assert :error = EctoRefreshStore.get("never-inserted")
    end

    test "refuses an insert into a revoked family (sticky revocation)" do
      fam = "fam-revoked-#{System.unique_integer([:positive])}"

      # Seed a row so the family has something to mark revoked, then revoke it.
      seed = entry(%{family_id: fam})
      :ok = EctoRefreshStore.insert(seed)
      :ok = EctoRefreshStore.revoke_family(fam)

      successor = entry(%{family_id: fam})
      assert {:error, :family_revoked} = EctoRefreshStore.insert(successor)
      assert :error = EctoRefreshStore.get(successor.token_hash)
    end
  end

  describe "consume/1" do
    test "first use returns {:ok, entry} with the record as it stood (unconsumed)" do
      e = entry()
      :ok = EctoRefreshStore.insert(e)

      assert {:ok, claimed} = EctoRefreshStore.consume(e.token_hash, now: 1_900_000_000)
      assert claimed.token_hash == e.token_hash
      assert claimed.consumed == false
      assert claimed.consumed_at == nil

      # The row is now marked consumed.
      assert {:ok, got} = EctoRefreshStore.get(e.token_hash)
      assert got.consumed == true
      assert got.consumed_at == 1_900_000_000
    end

    test "replay of an already-consumed token returns {:reuse, entry} carrying the family" do
      e = entry()
      :ok = EctoRefreshStore.insert(e)

      assert {:ok, _} = EctoRefreshStore.consume(e.token_hash)
      assert {:reuse, reused} = EctoRefreshStore.consume(e.token_hash)
      assert reused.family_id == e.family_id
    end

    test "remember_successor/3 stores retry data for a consumed parent" do
      e = entry(%{generation: 4})
      :ok = EctoRefreshStore.insert(e)

      assert {:ok, _claimed} = EctoRefreshStore.consume(e.token_hash, now: 1_900_000_000)

      successor = %{
        token: "successor-token",
        generation: 5,
        context: %{
          subject: "sub-1",
          scope: ["read"],
          client_id: "client-1",
          dpop_jkt: nil,
          claims: %{"k" => "v"}
        }
      }

      assert :ok = EctoRefreshStore.remember_successor(e.token_hash, successor)
      row = TestRepo.get_by(RefreshToken, token_hash: e.token_hash)
      assert %{"v" => 1, "ciphertext" => ciphertext} = row.successor
      assert is_binary(ciphertext)
      refute inspect(row.successor) =~ "successor-token"

      assert {:reuse, reused} = EctoRefreshStore.consume(e.token_hash)
      assert reused.successor == successor
    end

    test "remember_successor/3 fails closed when no encryption secret is configured" do
      e = entry()
      :ok = EctoRefreshStore.insert(e)
      assert {:ok, _claimed} = EctoRefreshStore.consume(e.token_hash)

      original = Application.get_env(:attesto_phoenix, :refresh_successor_secret)
      Application.delete_env(:attesto_phoenix, :refresh_successor_secret)

      try do
        assert :error =
                 EctoRefreshStore.remember_successor(e.token_hash, %{
                   token: "successor-token",
                   generation: 1,
                   context: e.data
                 })
      after
        Application.put_env(:attesto_phoenix, :refresh_successor_secret, original)
      end
    end

    test "remember_successor/3 refuses an unconsumed or unknown parent" do
      e = entry()
      :ok = EctoRefreshStore.insert(e)

      assert :error = EctoRefreshStore.remember_successor(e.token_hash, %{token: "x"})
      assert :error = EctoRefreshStore.remember_successor("unknown-token", %{token: "x"})
    end

    test "unknown token returns :error and never reports reuse" do
      assert :error = EctoRefreshStore.consume("unknown-token")
    end

    test "only one of two concurrent consumes wins; the other detects reuse" do
      e = entry()
      :ok = EctoRefreshStore.insert(e)
      owner = self()

      results =
        [e.token_hash, e.token_hash]
        |> Task.async_stream(
          fn hash ->
            # Each task runs in its own process; grant it the test's sandboxed
            # connection so both claims hit the same transaction state.
            Sandbox.allow(TestRepo, owner, self())
            EctoRefreshStore.consume(hash)
          end,
          max_concurrency: 2
        )
        |> Enum.map(fn {:ok, result} -> result end)

      # The conditional UPDATE serialises on the row: one winner, one replay.
      assert Enum.count(results, &match?({:ok, _}, &1)) == 1
      assert Enum.count(results, &match?({:reuse, _}, &1)) == 1
    end
  end

  describe "Attesto.RefreshToken integration" do
    test "an immediate honest retry returns the same successor through Ecto storage" do
      assert {:ok, issued} =
               Attesto.RefreshToken.issue(
                 EctoRefreshStore,
                 %{subject: "sub-1", scope: ["read"], client_id: "client-1"},
                 now: 1_900_000_000
               )

      assert {:ok, rotated} =
               Attesto.RefreshToken.rotate(EctoRefreshStore, issued.token,
                 client_id: "client-1",
                 now: 1_900_000_001
               )

      assert {:ok, retry} =
               Attesto.RefreshToken.rotate(EctoRefreshStore, issued.token,
                 client_id: "client-1",
                 now: 1_900_000_002
               )

      assert retry.token == rotated.token
      assert retry.family_id == rotated.family_id
      assert retry.generation == rotated.generation
      assert retry.context == rotated.context

      assert {:ok, _next} =
               Attesto.RefreshToken.rotate(EctoRefreshStore, rotated.token,
                 client_id: "client-1",
                 now: 1_900_000_003
               )
    end

    test "a mismatched retry revokes the family through Ecto storage" do
      assert {:ok, issued} =
               Attesto.RefreshToken.issue(
                 EctoRefreshStore,
                 %{subject: "sub-1", scope: ["read"], client_id: "client-1"},
                 now: 1_900_000_000
               )

      assert {:ok, rotated} =
               Attesto.RefreshToken.rotate(EctoRefreshStore, issued.token,
                 client_id: "client-1",
                 now: 1_900_000_001
               )

      assert {:error, :reuse_detected} =
               Attesto.RefreshToken.rotate(EctoRefreshStore, issued.token,
                 client_id: "other-client",
                 now: 1_900_000_002
               )

      assert {:error, :invalid_grant} =
               Attesto.RefreshToken.rotate(EctoRefreshStore, rotated.token,
                 client_id: "client-1",
                 now: 1_900_000_003
               )
    end
  end

  describe "revoke_family/1" do
    test "marks every token in the family revoked while keeping the rows" do
      fam = "fam-#{System.unique_integer([:positive])}"
      a = entry(%{family_id: fam})
      b = entry(%{family_id: fam})
      :ok = EctoRefreshStore.insert(a)
      :ok = EctoRefreshStore.insert(b)

      :ok = EctoRefreshStore.revoke_family(fam)

      # Rows persist (sticky revocation), each with the flag set.
      assert %RefreshToken{family_revoked: true} =
               TestRepo.get_by(RefreshToken, token_hash: a.token_hash)

      assert %RefreshToken{family_revoked: true} =
               TestRepo.get_by(RefreshToken, token_hash: b.token_hash)
    end

    test "is idempotent for an already-revoked or unknown family" do
      fam = "fam-#{System.unique_integer([:positive])}"
      assert :ok = EctoRefreshStore.revoke_family(fam)
      assert :ok = EctoRefreshStore.revoke_family(fam)
    end

    test "leaves an unrelated family untouched" do
      keep = entry()
      :ok = EctoRefreshStore.insert(keep)

      :ok = EctoRefreshStore.revoke_family("some-other-family")

      assert %RefreshToken{family_revoked: false} =
               TestRepo.get_by(RefreshToken, token_hash: keep.token_hash)
    end
  end
end
