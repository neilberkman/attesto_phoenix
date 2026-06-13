defmodule Mix.Tasks.AttestoPhoenix.Gen.MigrationTest do
  use ExUnit.Case, async: false

  import ExUnit.CaptureIO

  alias Mix.Tasks.AttestoPhoenix.Gen.Migration

  @moduletag :tmp_dir

  # A throwaway Ecto repo module so the task can resolve a repo from --repo
  # without standing up a real database connection. The migration path is always
  # given explicitly via --migrations-path in these tests, so config/0 only has
  # to satisfy Mix.Ecto.ensure_repo/2.
  defmodule TestRepo do
    def __adapter__, do: Ecto.Adapters.Postgres
    def config, do: [otp_app: :attesto_phoenix]
  end

  defp migrations_dir(tmp_dir), do: Path.join(tmp_dir, "migrations")

  defp run!(args, tmp_dir) do
    # inspect/1 renders the module without the "Elixir." prefix, which is the
    # spelling Mix.Ecto.parse_repo/1 expects for --repo.
    Migration.run(["--repo", inspect(TestRepo), "--migrations-path", migrations_dir(tmp_dir)] ++ args)
  end

  defp generated_migration(tmp_dir) do
    files =
      Path.wildcard(Path.join(migrations_dir(tmp_dir), "*_create_attesto_phoenix_tables.exs"))

    assert [file] = files
    File.read!(file)
  end

  describe "run/1" do
    test "generates a migration creating all four stores", %{tmp_dir: tmp_dir} do
      run!([], tmp_dir)
      source = generated_migration(tmp_dir)

      # Table names MUST match the runtime schemas' table names exactly, or a
      # by-the-docs deploy installs tables the stores cannot use:
      #   * AttestoPhoenix.Schema.Authorization -> attesto_authorization_codes
      #   * AttestoPhoenix.Schema.RefreshToken  -> attesto_refresh_tokens
      #   * AttestoPhoenix.Schema.DPoPNonce     -> dpop_nonces
      #   * AttestoPhoenix.Schema.DPoPReplay    -> dpop_replays
      assert source =~ ~s|use Ecto.Migration|
      assert source =~ ~s|create table(:attesto_authorization_codes|
      assert source =~ ~s|create table(:attesto_refresh_tokens|
      assert source =~ ~s|create table(:dpop_nonces|
      assert source =~ ~s|create table(:dpop_replays|
    end

    test "creates the unique constraints the schemas name", %{tmp_dir: tmp_dir} do
      run!([], tmp_dir)
      source = generated_migration(tmp_dir)

      # Each unique index's Postgres default name (<table>_<col>_index) must be
      # the name the schema's unique_constraint relies on:
      #   * Authorization: attesto_authorization_codes_code_hash_index
      #   * RefreshToken:  attesto_refresh_tokens_token_hash_index
      #   * DPoPNonce:     dpop_nonces_nonce_index (Ecto default)
      assert source =~ ~s|create unique_index(:attesto_authorization_codes, [:code_hash])|
      assert source =~ ~s|create unique_index(:attesto_refresh_tokens, [:token_hash])|
      assert source =~ ~s|create unique_index(:dpop_nonces, [:nonce])|
    end

    test "keys dpop_replays on jti so the conflict is dpop_replays_pkey", %{tmp_dir: tmp_dir} do
      run!([], tmp_dir)
      source = generated_migration(tmp_dir)

      # DPoPReplay declares @primary_key {:jti, ...} and
      # unique_constraint(:jti, name: :dpop_replays_pkey). jti must therefore be
      # the table's PRIMARY KEY (its constraint name is then dpop_replays_pkey),
      # not a separate unique index, so INSERT ... ON CONFLICT DO NOTHING fires
      # on the primary key.
      assert source =~ ~s|add :jti, :string, size: 255, primary_key: true, null: false|
      refute source =~ ~s|create unique_index(:dpop_replays, [:jti])|
      assert source =~ ~s|add :inserted_at, :utc_datetime_usec, null: false|
    end

    test "authorization_codes carries the columns the store reads/writes", %{tmp_dir: tmp_dir} do
      run!([], tmp_dir)
      source = generated_migration(tmp_dir)

      # The drifted columns that broke a by-the-docs deploy: PKCE method, DPoP
      # cnf, mapped claims, OIDC nonce, and the single-use marker.
      assert source =~ ~s|add :code_hash, :string, size: 88, null: false|
      assert source =~ ~s|add :code_challenge, :string, size: 255|
      assert source =~ ~s|add :code_challenge_method, :string, size: 16|
      refute source =~ ~s|add :code_challenge, :string, size: 255, null: false|
      refute source =~ ~s|add :code_challenge_method, :string, size: 16, null: false|
      assert source =~ ~s|add :cnf, :map|
      assert source =~ ~s|add :claims, :map, null: false, default: %{}|
      assert source =~ ~s|add :consumed_at, :utc_datetime|
      # The schema is @primary_key false, keyed on code_hash: the table is
      # created primary_key: false and there is no surrogate id column in it.
      assert source =~ ~s|create table(:attesto_authorization_codes, primary_key: false) do|
    end

    test "refresh_tokens carries the rotation/reuse columns", %{tmp_dir: tmp_dir} do
      run!([], tmp_dir)
      source = generated_migration(tmp_dir)

      assert source =~ ~s|add :token_hash, :string, size: 88, null: false|
      assert source =~ ~s|add :family_id, :string, size: 255, null: false|
      assert source =~ ~s|add :generation, :integer, null: false, default: 0|
      assert source =~ ~s|add :consumed, :boolean, null: false, default: false|
      assert source =~ ~s|add :consumed_at, :utc_datetime|
      assert source =~ ~s|add :successor, :map|
      assert source =~ ~s|add :family_revoked, :boolean, null: false, default: false|
      assert source =~ ~s|add :parent_hash, :string, size: 88|
      assert source =~ ~s|create index(:attesto_refresh_tokens, [:family_id])|
    end

    test "dpop_nonces carries issued_at/used_at", %{tmp_dir: tmp_dir} do
      run!([], tmp_dir)
      source = generated_migration(tmp_dir)

      assert source =~ ~s|add :issued_at, :utc_datetime, null: false|
      assert source =~ ~s|add :used_at, :utc_datetime|
    end

    test "creates expires_at indexes on the ttl tables", %{tmp_dir: tmp_dir} do
      run!([], tmp_dir)
      source = generated_migration(tmp_dir)

      assert source =~ ~s|create index(:attesto_authorization_codes, [:expires_at])|
      assert source =~ ~s|create index(:attesto_refresh_tokens, [:expires_at])|
      assert source =~ ~s|create index(:dpop_replays, [:expires_at])|
    end

    test "is reversible", %{tmp_dir: tmp_dir} do
      run!([], tmp_dir)
      source = generated_migration(tmp_dir)

      assert source =~ ~s|def up do|
      assert source =~ ~s|def down do|
      # down drops every table the up created.
      for table <- ~w(attesto_authorization_codes attesto_refresh_tokens dpop_nonces dpop_replays) do
        assert source =~ ~s|drop table(:#{table})|
      end
    end

    test "applies an explicit --table-prefix to every table", %{tmp_dir: tmp_dir} do
      run!(["--table-prefix", "oauth_"], tmp_dir)
      source = generated_migration(tmp_dir)

      assert source =~ ~s|create table(:oauth_attesto_authorization_codes|
      assert source =~ ~s|create table(:oauth_attesto_refresh_tokens|
      assert source =~ ~s|create table(:oauth_dpop_nonces|
      assert source =~ ~s|create table(:oauth_dpop_replays|
      assert source =~ ~s|create unique_index(:oauth_attesto_authorization_codes, [:code_hash])|
    end

    test "rejects an invalid table prefix (fail closed)", %{tmp_dir: tmp_dir} do
      assert_raise Mix.Error, ~r/invalid --table-prefix/, fn ->
        run!(["--table-prefix", "bad-prefix;"], tmp_dir)
      end

      assert Path.wildcard(Path.join(migrations_dir(tmp_dir), "*.exs")) == []
    end

    test "refuses to regenerate over an existing migration", %{tmp_dir: tmp_dir} do
      run!([], tmp_dir)

      assert_raise Mix.Error, ~r/already exists/, fn ->
        run!([], tmp_dir)
      end
    end

    test "requires at least one repo", %{tmp_dir: tmp_dir} do
      # Mix.Ecto warns before our task raises its actionable "pass --repo"
      # message. Capture that expected stderr so the test suite itself stays
      # warning-free.
      capture_io(:stderr, fn ->
        assert_raise Mix.Error, ~r/no Ecto repos/, fn ->
          Migration.run(["--migrations-path", migrations_dir(tmp_dir)])
        end
      end)
    end
  end
end
