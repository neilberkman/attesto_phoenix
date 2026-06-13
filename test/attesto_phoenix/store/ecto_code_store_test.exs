defmodule AttestoPhoenix.Store.EctoCodeStoreTest do
  @moduledoc """
  Behaviour conformance tests for the Ecto-backed authorization-code store.

  The load-bearing property is single use (RFC 6749 §4.1.2): a code is
  redeemable exactly once, even under concurrent redemption, because the
  code is the sole browser-deliverable secret in the PKCE-mandatory
  authorization-code flow (RFC 7636).

  Tagged `:ecto` so the suite is excluded by default and runs only when a SQL
  backend is available (see `test/test_helper.exs`).
  """

  use AttestoPhoenix.DataCase, async: true

  alias AttestoPhoenix.Schema.Authorization
  alias AttestoPhoenix.Store.EctoCodeStore
  alias Ecto.Adapters.SQL.Sandbox

  @moduletag :ecto

  # take/1 does not gate on expiry; a future value keeps fixtures realistic.
  @future_seconds System.system_time(:second) + 600

  # The grant context the protocol layer round-trips. The schema spreads
  # these across columns, so the required authorization-request fields must
  # be present (RFC 6749 §4.1.3, RFC 7636 §4.3).
  defp grant_data(overrides \\ %{}) do
    Map.merge(
      %{
        client_id: "client-abc",
        subject: "subject-1",
        scope: ["openid", "profile"],
        redirect_uri: "https://rp.example/cb",
        code_challenge: "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM",
        code_challenge_method: Authorization.code_challenge_method(),
        family_id: "fam-1",
        nonce: "request-nonce",
        claims: %{"acr" => "urn:mace:incommon:iap:silver"}
      },
      overrides
    )
  end

  defp entry(code_hash, data \\ grant_data(), expires_at \\ @future_seconds) do
    %{code_hash: code_hash, data: data, expires_at: expires_at}
  end

  describe "put/1" do
    test "persists a record retrievable by its code_hash" do
      assert :ok = EctoCodeStore.put(entry("hash-1"))
      assert {:ok, %{code_hash: "hash-1"}} = EctoCodeStore.take("hash-1")
    end

    test "round-trips the grant context through the column bridge" do
      assert :ok = EctoCodeStore.put(entry("hash-rt"))
      assert {:ok, %{data: data}} = EctoCodeStore.take("hash-rt")

      assert data.client_id == "client-abc"
      assert data.subject == "subject-1"
      assert data.scope == ["openid", "profile"]
      assert data.redirect_uri == "https://rp.example/cb"
      assert data.code_challenge == "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"
      assert data.family_id == "fam-1"
    end

    test "preserves expires_at as absolute unix seconds across storage" do
      assert :ok = EctoCodeStore.put(entry("hash-exp"))
      assert {:ok, %{expires_at: @future_seconds}} = EctoCodeStore.take("hash-exp")
    end

    test "rejects a duplicate code_hash rather than overwriting" do
      assert :ok = EctoCodeStore.put(entry("hash-dup", grant_data(%{subject: "first"})))

      # A repeated primary key is a caller bug; the unique constraint must
      # surface, never a silent upsert that could replace an issued code.
      # `insert!/1` maps the constraint onto the changeset and raises.
      assert_raise Ecto.InvalidChangesetError, fn ->
        EctoCodeStore.put(entry("hash-dup", grant_data(%{subject: "second"})))
      end

      # The original row is untouched.
      assert {:ok, %{data: %{subject: "first"}}} = EctoCodeStore.take("hash-dup")
    end

    test "fails closed when a required grant field is missing" do
      # The schema validates required fields; an incomplete grant must not be
      # stored as a half-formed, unredeemable code.
      bad = entry("hash-bad", Map.delete(grant_data(), :redirect_uri))
      assert_raise Ecto.InvalidChangesetError, fn -> EctoCodeStore.put(bad) end
    end
  end

  describe "take/1" do
    test "returns the record and claims it so a code is redeemable once" do
      assert :ok = EctoCodeStore.put(entry("hash-once"))

      assert {:ok, %{code_hash: "hash-once"}} = EctoCodeStore.take("hash-once")
      # The first presentation has only claimed the row. Until the protocol
      # layer reports successful redemption, a second presentation is not
      # replay evidence and fails closed as an unknown/invalid grant.
      assert :error = EctoCodeStore.take("hash-once")
    end

    test "returns consumed metadata only after successful redemption is marked" do
      assert :ok = EctoCodeStore.put(entry("hash-consumed", grant_data(%{family_id: "fam-ok"})))

      assert {:ok, %{code_hash: "hash-consumed"}} = EctoCodeStore.take("hash-consumed")
      assert :ok = EctoCodeStore.mark_consumed("hash-consumed", %{})

      assert {:error, :consumed, %{family_id: "fam-ok", subject: "subject-1"}} =
               EctoCodeStore.take("hash-consumed")
    end

    test "returns :error for an absent code_hash" do
      assert :error = EctoCodeStore.take("hash-missing")
    end

    test "consumes the row regardless of expiry" do
      stale = entry("hash-stale", grant_data(), System.system_time(:second) - 1)
      assert :ok = EctoCodeStore.put(stale)

      # take/1 does not gate on expiry; the caller re-checks. The row is still
      # spent on first presentation, denying replayed validation attempts.
      assert {:ok, %{code_hash: "hash-stale"}} = EctoCodeStore.take("hash-stale")
      assert :error = EctoCodeStore.take("hash-stale")
    end

    test "only one of two concurrent redemptions wins" do
      assert :ok = EctoCodeStore.put(entry("hash-race"))
      owner = self()

      results =
        ["hash-race", "hash-race"]
        |> Task.async_stream(
          fn h ->
            # Each task runs in its own process; grant it the test's sandboxed
            # connection so both takes hit the same transaction state.
            Sandbox.allow(TestRepo, owner, self())
            EctoCodeStore.take(h)
          end,
          max_concurrency: 2
        )
        |> Enum.map(fn {:ok, result} -> result end)

      # The atomic UPDATE ... RETURNING serialises on the row: exactly one
      # winner claims the record, the other gets :error.
      assert Enum.count(results, &match?({:ok, _}, &1)) == 1
      assert Enum.count(results, &(&1 == :error)) == 1
    end
  end

  describe "access-token revocation after authorization-code reuse" do
    test "records, revokes, and checks the access token issued from a code family" do
      expires_at = System.system_time(:second) + 600

      assert :ok = EctoCodeStore.put(entry("hash-access", grant_data(%{family_id: "fam-access"})))
      assert {:ok, %{code_hash: "hash-access"}} = EctoCodeStore.take("hash-access")

      assert :ok = EctoCodeStore.record_access_token("fam-access", "jti-1", expires_at)
      refute EctoCodeStore.access_token_revoked?("jti-1")

      assert :ok = EctoCodeStore.revoke_family_access_tokens("fam-access")
      assert EctoCodeStore.access_token_revoked?("jti-1")
    end

    test "expired revoked access tokens are ignored" do
      expires_at = System.system_time(:second) - 1

      assert :ok =
               EctoCodeStore.put(entry("hash-expired-token", grant_data(%{family_id: "fam-exp"})))

      assert {:ok, %{code_hash: "hash-expired-token"}} = EctoCodeStore.take("hash-expired-token")

      assert :ok = EctoCodeStore.record_access_token("fam-exp", "jti-expired", expires_at)
      assert :ok = EctoCodeStore.revoke_family_access_tokens("fam-exp")

      refute EctoCodeStore.access_token_revoked?("jti-expired")
    end
  end
end
