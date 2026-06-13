defmodule AttestoPhoenix.Store.EctoNonceStoreTest do
  @moduledoc """
  Behaviour-conformance tests for the Postgres-backed DPoP nonce store
  (RFC 9449 §8): unpredictable issuance, live/expired freshness, and the
  atomic single-use consume that holds across nodes.

  The store reads its repo from an explicit `AttestoPhoenix.Config`, so each
  test passes one built against the sandboxed test repo.
  """

  use AttestoPhoenix.DataCase, async: false

  alias AttestoPhoenix.Config
  alias AttestoPhoenix.Schema.DPoPNonce
  alias AttestoPhoenix.Store.EctoNonceStore
  alias Ecto.Adapters.SQL.Sandbox

  @ttl 300

  setup do
    config =
      Config.new(
        issuer: "https://issuer.example",
        keystore: __MODULE__.Keystore,
        repo: AttestoPhoenix.TestRepo,
        load_client: fn _ -> {:error, :not_found} end,
        verify_client_secret: fn _, _ -> false end,
        load_principal: fn _ -> {:error, :not_found} end
      )

    %{config: config}
  end

  # A minimal keystore stand-in: the store under test never touches it, but
  # `Config.new/1` requires the key to be present.
  defmodule Keystore do
    @moduledoc false
  end

  describe "issue/2" do
    test "issue/0 resolves the application-wide configured repo", %{config: config} do
      Application.put_env(:attesto_phoenix, :config, config)
      on_exit(fn -> Application.delete_env(:attesto_phoenix, :config) end)

      nonce = EctoNonceStore.issue()

      assert is_binary(nonce)
      assert TestRepo.get_by(DPoPNonce, nonce: nonce)
    end

    test "returns an opaque url-safe value", %{config: config} do
      nonce = EctoNonceStore.issue(config, @ttl)

      assert is_binary(nonce)
      assert nonce == Base.url_encode64(Base.url_decode64!(nonce, padding: false), padding: false)
    end

    test "issues distinct values", %{config: config} do
      refute EctoNonceStore.issue(config, @ttl) == EctoNonceStore.issue(config, @ttl)
    end

    test "persists the issued nonce as unused with a future expiry", %{config: config} do
      nonce = EctoNonceStore.issue(config, @ttl)
      row = TestRepo.get_by(DPoPNonce, nonce: nonce)

      assert row
      assert is_nil(row.used_at)
      assert DateTime.after?(row.expires_at, row.issued_at)
    end

    test "rejects a non-positive ttl via the guard", %{config: config} do
      assert_raise FunctionClauseError, fn -> EctoNonceStore.issue(config, 0) end
    end
  end

  describe "valid?/2" do
    test "is true for a freshly issued, unconsumed nonce", %{config: config} do
      nonce = EctoNonceStore.issue(config, @ttl)
      assert EctoNonceStore.valid?(config, nonce)
    end

    test "is false for an unknown nonce", %{config: config} do
      refute EctoNonceStore.valid?(config, "never-issued")
    end

    test "is false after the nonce has been consumed", %{config: config} do
      nonce = EctoNonceStore.issue(config, @ttl)
      :ok = EctoNonceStore.accept(config, nonce, @ttl)
      refute EctoNonceStore.valid?(config, nonce)
    end

    test "is false once the stored expiry has passed", %{config: config} do
      nonce = insert_nonce(issued_seconds_ago: 10, expires_seconds_ago: 1)
      refute EctoNonceStore.valid?(config, nonce)
    end

    test "is false for a non-binary input", %{config: config} do
      refute EctoNonceStore.valid?(config, nil)
    end
  end

  describe "accept/3" do
    test "accepts a fresh nonce exactly once", %{config: config} do
      nonce = EctoNonceStore.issue(config, @ttl)

      assert :ok == EctoNonceStore.accept(config, nonce, @ttl)
      assert {:error, :used} == EctoNonceStore.accept(config, nonce, @ttl)
    end

    test "marks the row used on the winning consume", %{config: config} do
      nonce = EctoNonceStore.issue(config, @ttl)
      :ok = EctoNonceStore.accept(config, nonce, @ttl)

      row = TestRepo.get_by(DPoPNonce, nonce: nonce)
      refute is_nil(row.used_at)
    end

    test "rejects an unknown nonce", %{config: config} do
      assert {:error, :unknown} == EctoNonceStore.accept(config, "never-issued", @ttl)
    end

    test "rejects a nonce older than the consume ttl", %{config: config} do
      nonce = insert_nonce(issued_seconds_ago: @ttl + 1)
      assert {:error, :expired} == EctoNonceStore.accept(config, nonce, @ttl)
    end

    test "accepts a nonce just inside the consume ttl", %{config: config} do
      nonce = insert_nonce(issued_seconds_ago: @ttl - 1)
      assert :ok == EctoNonceStore.accept(config, nonce, @ttl)
    end

    test "reports expired rather than used for an unconsumed expired nonce", %{config: config} do
      nonce = insert_nonce(issued_seconds_ago: @ttl + 10)
      assert {:error, :expired} == EctoNonceStore.accept(config, nonce, @ttl)
    end

    test "rejects a non-positive ttl via the guard", %{config: config} do
      nonce = EctoNonceStore.issue(config, @ttl)
      assert_raise FunctionClauseError, fn -> EctoNonceStore.accept(config, nonce, 0) end
    end

    test "only one of two concurrent consumes wins", %{config: config} do
      nonce = EctoNonceStore.issue(config, @ttl)
      owner = self()

      results =
        [nonce, nonce]
        |> Task.async_stream(
          fn n ->
            # Each task runs in its own process; grant it the test's sandboxed
            # connection so both consumes hit the same transaction state.
            Sandbox.allow(TestRepo, owner, self())
            EctoNonceStore.accept(config, n, @ttl)
          end,
          max_concurrency: 2
        )
        |> Enum.map(fn {:ok, result} -> result end)

      # The conditional UPDATE serialises on the row: one winner, one loser.
      assert Enum.sort(results) == Enum.sort([:ok, {:error, :used}])
    end
  end

  # Inserts a nonce row directly so a test can position issued_at / expires_at
  # in the past without sleeping. expires_at defaults far in the future so that
  # accept/3's own ttl, not the stored expiry, governs freshness.
  defp insert_nonce(opts) do
    issued_ago = Keyword.fetch!(opts, :issued_seconds_ago)
    now = DateTime.utc_now() |> DateTime.truncate(:second)
    issued_at = DateTime.add(now, -issued_ago, :second)

    expires_at =
      case Keyword.fetch(opts, :expires_seconds_ago) do
        {:ok, ago} -> DateTime.add(now, -ago, :second)
        :error -> DateTime.add(issued_at, @ttl * 10, :second)
      end

    nonce = :crypto.strong_rand_bytes(32) |> Base.url_encode64(padding: false)

    %{nonce: nonce, issued_at: issued_at, expires_at: expires_at}
    |> DPoPNonce.issue_changeset()
    |> TestRepo.insert!()

    nonce
  end
end
