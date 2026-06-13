defmodule AttestoPhoenix.Schema.RefreshToken do
  @moduledoc """
  Ecto schema for the refresh-token records that back an Ecto-backed
  `Attesto.RefreshStore`.

  Refresh tokens are rotated single-use credentials (RFC 6749 §6, §10.4;
  OAuth 2.0 Security BCP §4.13). Presenting a token consumes it and mints a
  successor in the same *family*; re-presenting an already-consumed token is
  the captured-token signal that revokes the whole family. Only the hash of
  each token is persisted, never the plaintext, so a leaked store yields no
  usable credentials.

  ## Columns

    * `:token_hash` - `Attesto.Secret.hash/1` of the token. The lookup key;
      a unique index enforces one row per token.
    * `:family_id` - groups every token descended from one authorization
      grant. Revoked together on reuse detection.
    * `:generation` - rotation generation within the family (`0` for the
      first token).
    * `:client_id` - the OAuth client the token was issued to (RFC 6749 §10.4
      requires rotation to be confined to the issuing client). `nil` for a
      token with no client binding.
    * `:subject` - the resource owner the token authorizes.
    * `:scope` - the granted scope as a list of strings (RFC 6749 §3.3); a
      successor's scope MUST be a subset of its predecessor's.
    * `:cnf` - the RFC 7800 confirmation claim binding the token to a proof of
      possession (e.g. `%{"jkt" => thumbprint}` for a DPoP key, RFC 9449;
      `%{"x5t#S256" => thumbprint}` for an mTLS certificate, RFC 8705). `nil`
      for a bearer token.
    * `:claims` - opaque issuer context round-tripped into the next access
      token. A map; never `nil`.
    * `:consumed` - whether the token has already been rotated. The atomic
      transition of this flag (see `claim_changeset/1`) is what makes reuse
      detection reliable.
    * `:consumed_at` - when the token was rotated, used for the short
      idempotency window on honest refresh retries.
    * `:successor` - encrypted already-minted successor returned during an
      idempotent retry. The plaintext successor token is never stored directly
      in the database.
    * `:family_revoked` - whether the token's family has been revoked. A
      revoked family fails closed: no row in it may be rotated, and no
      successor may be inserted into it (sticky revocation).
    * `:expires_at` - absolute expiry. A token at or past its expiry is
      refused without being consumed.
    * `:parent_hash` - the `:token_hash` of the predecessor that minted this
      token, or `nil` for the first token in a family. Diagnostic lineage; it
      is never used as a lookup key.
    * `:inserted_at` - issuance time, set on insert.

  ## Confirmation translation

  `Attesto.RefreshToken` carries the proof-of-possession binding as a
  `:dpop_jkt` thumbprint inside its opaque context map. This schema persists
  the binding as a structured `:cnf` confirmation so the same column can hold
  any RFC 7800 member. `from_store_record/2` folds a `:dpop_jkt` into a `cnf`,
  and `to_store_record/1` unfolds it back, so the protocol layer continues to
  speak `:dpop_jkt` while storage stays confirmation-shaped.
  """

  use Ecto.Schema

  import Ecto.Changeset

  alias Plug.Crypto.MessageEncryptor

  # RFC 9449 (DPoP): the confirmation member naming the JWK thumbprint of the
  # bound key.
  @cnf_jkt "jkt"
  @app :attesto_phoenix
  @successor_aad "attesto_phoenix:refresh_successor:v1"

  @type t :: %__MODULE__{}

  @primary_key {:id, :binary_id, autogenerate: true}
  schema "attesto_refresh_tokens" do
    field :token_hash, :string
    field :family_id, :string
    field :generation, :integer, default: 0
    field :client_id, :string
    field :subject, :string
    field :scope, {:array, :string}, default: []
    field :cnf, :map
    field :claims, :map, default: %{}
    field :consumed, :boolean, default: false
    field :consumed_at, :utc_datetime
    field :successor, :map
    field :family_revoked, :boolean, default: false
    field :expires_at, :utc_datetime
    field :parent_hash, :string

    timestamps(updated_at: false, type: :utc_datetime)
  end

  @required [:token_hash, :family_id, :subject, :expires_at]
  @permitted [
    :token_hash,
    :family_id,
    :generation,
    :client_id,
    :subject,
    :scope,
    :cnf,
    :claims,
    :consumed,
    :consumed_at,
    :successor,
    :family_revoked,
    :expires_at,
    :parent_hash
  ]

  @doc """
  Changeset for inserting a new (unconsumed) refresh-token record.

  Validates the columns the store contract requires and enforces single-use
  storage via the unique constraint on `:token_hash`. A new record is always
  unconsumed and never starts revoked; passing either flag as true is refused
  so an insert cannot smuggle a token into a consumed or revoked state.
  """
  @spec insert_changeset(t(), map()) :: Ecto.Changeset.t()
  def insert_changeset(struct \\ %__MODULE__{}, attrs) when is_map(struct) and is_map(attrs) do
    struct
    |> cast(attrs, @permitted)
    |> validate_required(@required)
    |> normalize_scope()
    |> normalize_claims()
    |> validate_inclusion(:consumed, [false], message: "a new refresh token must be unconsumed (RFC 6749 §6)")
    |> validate_inclusion(:family_revoked, [false], message: "a new refresh token must not start revoked")
    |> unique_constraint(:token_hash, name: :attesto_refresh_tokens_token_hash_index)
  end

  @doc """
  Changeset that atomically claims (consumes) an unconsumed token.

  The atomic primitive on which reuse detection depends (see
  `Attesto.RefreshStore`) is `UPDATE ... SET consumed = true WHERE
  token_hash = $1 AND consumed = false`. An Ecto-backed store runs this
  changeset inside such a guarded update so that two concurrent rotations
  cannot both observe the token as unconsumed: exactly one update affects a
  row, the other affects none and is reported as reuse.
  """
  @spec claim_changeset(t(), DateTime.t()) :: Ecto.Changeset.t()
  def claim_changeset(%__MODULE__{} = record, %DateTime{} = consumed_at) do
    change(record, consumed: true, consumed_at: consumed_at)
  end

  @doc """
  Build the insert attributes for a store record handed in by
  `Attesto.RefreshToken`.

  The protocol layer's record is `%{token_hash, family_id, generation, data,
  expires_at, consumed}` where `data` is the opaque context
  (`%{subject, scope, client_id, dpop_jkt, claims}`). This flattens `data`
  into the schema's columns, translating `:dpop_jkt` into an RFC 7800 `:cnf`
  confirmation, and renders `:expires_at` (unix seconds in the contract) as a
  `DateTime`. `:parent_hash` is taken from `opts[:parent_hash]` when the store
  threads predecessor lineage; the contract does not carry it.
  """
  @spec from_store_record(map(), keyword()) :: map()
  def from_store_record(record, opts \\ []) when is_map(record) and is_list(opts) do
    data = Map.get(record, :data, %{})

    %{
      token_hash: Map.fetch!(record, :token_hash),
      family_id: Map.fetch!(record, :family_id),
      generation: Map.fetch!(record, :generation),
      subject: Map.get(data, :subject),
      scope: Map.get(data, :scope, []),
      client_id: Map.get(data, :client_id),
      cnf: cnf_from_context(data),
      claims: Map.get(data, :claims, %{}),
      consumed: Map.get(record, :consumed, false),
      consumed_at: nullable_datetime(Map.get(record, :consumed_at)),
      successor: Map.get(record, :successor),
      expires_at: to_datetime(Map.fetch!(record, :expires_at)),
      parent_hash: Keyword.get(opts, :parent_hash)
    }
  end

  @doc """
  Render a persisted row back into the `Attesto.RefreshStore` record shape the
  protocol layer expects.

  Inverse of `from_store_record/2`: it rebuilds the opaque `:data` context
  (unfolding the `:cnf` confirmation back into `:dpop_jkt`) and renders
  `:expires_at` back to unix seconds. `:generation` is not stored as a column;
  it is reported as `0` so the contract's record stays well-formed without the
  schema asserting lineage it does not track.
  """
  @spec to_store_record(t()) :: map()
  def to_store_record(%__MODULE__{} = row) do
    %{
      token_hash: row.token_hash,
      family_id: row.family_id,
      generation: row.generation || 0,
      data: %{
        subject: row.subject,
        scope: row.scope || [],
        client_id: row.client_id,
        dpop_jkt: jkt_from_cnf(row.cnf),
        claims: row.claims || %{}
      },
      expires_at: to_unix(row.expires_at),
      consumed: row.consumed,
      consumed_at: nullable_unix(row.consumed_at),
      successor: successor_from_row(row.successor)
    }
  end

  # ----- confirmation translation (RFC 7800) -----

  # The DPoP binding (RFC 9449) is carried in the protocol context as a bare
  # thumbprint; persist it as the `jkt` member of an RFC 7800 confirmation so
  # the column generalizes to other confirmation methods. No binding stores no
  # confirmation rather than an empty map, keeping bearer tokens unconstrained.
  defp cnf_from_context(%{dpop_jkt: jkt}) when is_binary(jkt), do: %{@cnf_jkt => jkt}
  defp cnf_from_context(_data), do: nil

  defp jkt_from_cnf(%{@cnf_jkt => jkt}) when is_binary(jkt), do: jkt
  defp jkt_from_cnf(_cnf), do: nil

  # ----- normalization -----

  defp normalize_scope(changeset) do
    case get_change(changeset, :scope) do
      nil -> changeset
      scope -> put_change(changeset, :scope, Enum.uniq(scope))
    end
  end

  defp normalize_claims(changeset) do
    case get_field(changeset, :claims) do
      nil -> put_change(changeset, :claims, %{})
      _claims -> changeset
    end
  end

  # ----- time rendering -----

  # The store contract represents expiry as absolute unix seconds; the column
  # is a timestamp. Translate at the boundary so neither side leaks the other's
  # representation.
  defp to_datetime(%DateTime{} = dt), do: dt
  defp to_datetime(seconds) when is_integer(seconds), do: DateTime.from_unix!(seconds, :second)
  defp nullable_datetime(nil), do: nil
  defp nullable_datetime(%DateTime{} = dt), do: dt

  defp nullable_datetime(seconds) when is_integer(seconds), do: DateTime.from_unix!(seconds, :second)

  defp to_unix(%DateTime{} = dt), do: DateTime.to_unix(dt, :second)
  defp nullable_unix(nil), do: nil
  defp nullable_unix(%DateTime{} = dt), do: DateTime.to_unix(dt, :second)

  # Ecto map columns round-trip through JSON on Postgres, so atom keys come
  # back as strings. Rebuild only the successor shape the core understands; do
  # not create arbitrary atoms from stored data.
  defp successor_from_row(nil), do: nil

  defp successor_from_row(%{"v" => 1, "ciphertext" => ciphertext}) when is_binary(ciphertext) do
    case decrypt_successor(ciphertext) do
      {:ok, successor} -> successor_from_row(successor)
      :error -> nil
    end
  end

  defp successor_from_row(%{v: 1, ciphertext: ciphertext}) when is_binary(ciphertext),
    do: successor_from_row(%{"v" => 1, "ciphertext" => ciphertext})

  defp successor_from_row(%{} = successor) do
    token = value(successor, :token)
    generation = value(successor, :generation)
    context = value(successor, :context)

    if is_binary(token) and is_integer(generation) and is_map(context) do
      %{token: token, generation: generation, context: context_from_row(context)}
    end
  end

  defp context_from_row(%{} = context) do
    %{
      subject: value(context, :subject),
      scope: value(context, :scope) || [],
      client_id: value(context, :client_id),
      dpop_jkt: value(context, :dpop_jkt),
      claims: value(context, :claims) || %{}
    }
  end

  defp value(map, key) when is_map(map), do: Map.get(map, key) || Map.get(map, Atom.to_string(key))

  defp decrypt_successor(ciphertext) do
    with {:ok, enc_key, sign_key} <- successor_keys(),
         {:ok, encoded} <-
           MessageEncryptor.decrypt(ciphertext, @successor_aad, enc_key, sign_key) do
      {:ok, :erlang.binary_to_term(encoded, [:safe])}
    else
      _ -> :error
    end
  end

  defp successor_keys do
    case Application.get_env(@app, :refresh_successor_secret) do
      secret when is_binary(secret) and byte_size(secret) >= 32 ->
        {:ok, :crypto.hash(:sha256, "refresh-successor:enc:" <> secret),
         :crypto.hash(:sha256, "refresh-successor:sign:" <> secret)}

      _ ->
        :error
    end
  end
end
