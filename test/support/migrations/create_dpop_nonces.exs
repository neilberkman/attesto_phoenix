defmodule AttestoPhoenix.TestRepo.Migrations.CreateDPoPNonces do
  @moduledoc """
  Test-suite migration for the DPoP nonce table.

  Mirrors the table that a host application would generate via the migration
  task. The unique index on `nonce` enforces that a value is issued at most
  once (RFC 9449 §8); the partial index on unused rows keeps the conditional
  consume update fast.
  """

  use Ecto.Migration

  def change do
    create table(:dpop_nonces, primary_key: false) do
      add(:id, :binary_id, primary_key: true)
      add(:nonce, :string, null: false)
      add(:issued_at, :utc_datetime, null: false)
      add(:expires_at, :utc_datetime, null: false)
      add(:used_at, :utc_datetime)
    end

    create(unique_index(:dpop_nonces, [:nonce]))

    create(index(:dpop_nonces, [:used_at], where: "used_at IS NULL", name: :dpop_nonces_unused_index))
  end
end
