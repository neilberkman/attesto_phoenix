defmodule AttestoPhoenix.Store.Sweeper do
  @moduledoc """
  Optional periodic housekeeping `GenServer` that deletes expired rows from the
  Ecto-backed authorization-code, refresh-token, DPoP-nonce, and DPoP-replay
  tables.

  Each of these tables carries an `expires_at` column whose semantics are fixed
  by the relevant RFC:

    * authorization codes - RFC 6749 §4.1.2 ("The authorization code MUST expire
      shortly after it is issued") and §10.5 (codes are short-lived,
      single-use).
    * refresh tokens - RFC 6749 §1.5 / §6 (refresh tokens MAY expire); the
      stored expiry bounds the credential's lifetime.
    * server-issued DPoP nonces - RFC 9449 §8 / §9 (the `nonce` the resource or
      authorization server requires the client to echo is time-bounded).
    * DPoP proof `jti` replay records - RFC 9449 §11.1 (a `jti` need only be
      remembered for the proof `iat` acceptance window; past that window the
      record is dead weight).

  ## Correctness vs. housekeeping

  Sweeping is **not** required for correctness. Every store re-validates
  `expires_at` against the current time on read, so an expired row that has not
  yet been swept is never honored: an expired authorization code is rejected, an
  expired nonce is rejected, and an expired replay record no longer blocks a
  fresh `jti`. The sweeper exists only to bound table growth by reclaiming rows
  that can no longer affect any decision. It is therefore safe to run on any
  interval, or not at all.

  This is generic TTL housekeeping: it issues a single
  `DELETE ... WHERE expires_at < $now` per swept table and makes no assumption
  about how, where, or by which process the host deploys it.

  ## Comparison boundary (fail-closed)

  Deletion uses a strict `<` comparison against a single `DateTime` captured
  once per sweep (`DateTime.utc_now/0`) and reused across every table, so a
  sweep applies one consistent boundary. A row whose `expires_at` equals "now"
  is retained, never deleted, so the sweeper can only ever remove rows that the
  stores themselves already treat as expired. The sweeper widens no acceptance
  window.

  ## Configuration

  All policy is read from `AttestoPhoenix.Config`; nothing is hardcoded here.

    * `:repo` - the `Ecto.Repo` the deletes run against (required by
      `AttestoPhoenix.Config`).
    * `:sweep_interval_ms` - how often a sweep runs, in milliseconds. When this
      key is unset the sweeper MUST NOT be placed in the supervision tree;
      `start_link/1` raises rather than silently choosing an interval, so a
      missing interval is a configuration error, not a default.
    * `:table_prefix` - optional Ecto schema/table prefix applied to every
      delete so a host that installed the generated tables under a non-default
      prefix sweeps the same tables it created.

  The set of swept tables is fixed by the generated schema and is not
  host-configurable: every Ecto-backed store the library generates carries an
  `expires_at` column and is swept.
  """

  use GenServer

  import Ecto.Query, only: [from: 2]

  alias AttestoPhoenix.Config

  # The Ecto-backed stores the migration generator installs. Each table has an
  # `expires_at` column; the set is exhaustive over the generated stores and is
  # intentionally not host-overridable (sweeping a partial set would let one
  # table grow unbounded). The names are module attributes (compile-time
  # literals) because Ecto's `from/2` requires a literal string source: a
  # runtime-interpolated source is rejected, which keeps the swept set static by
  # construction.
  @authorization_codes "attesto_authorization_codes"
  @refresh_tokens "attesto_refresh_tokens"
  @dpop_nonces "dpop_nonces"
  @dpop_replays "dpop_replays"

  @doc """
  Starts the sweeper.

  Requires a `%AttestoPhoenix.Config{}` under the `:config` key. The config's
  `:sweep_interval_ms` MUST be a positive integer; a missing or non-positive
  interval raises `ArgumentError` so a misconfigured host fails at boot instead
  of starting a process that never sweeps.
  """
  @spec start_link(keyword()) :: GenServer.on_start()
  def start_link(opts) when is_list(opts) do
    config = fetch_config!(opts)
    _interval = sweep_interval_ms!(config)
    GenServer.start_link(__MODULE__, config, name: Keyword.get(opts, :name, __MODULE__))
  end

  @doc false
  def child_spec(opts) do
    %{
      id: Keyword.get(opts, :name, __MODULE__),
      restart: :permanent,
      shutdown: 5_000,
      start: {__MODULE__, :start_link, [opts]},
      type: :worker
    }
  end

  @impl true
  @spec init(Config.t()) :: {:ok, map()}
  def init(%Config{} = config) do
    interval_ms = sweep_interval_ms!(config)
    schedule_sweep(interval_ms)

    {:ok,
     %{
       repo: config.repo,
       table_prefix: config.table_prefix,
       interval_ms: interval_ms
     }}
  end

  @impl true
  def handle_info(:sweep, state) do
    sweep(state)
    schedule_sweep(state.interval_ms)
    {:noreply, state}
  end

  @doc """
  Runs a single sweep synchronously and returns the number of rows deleted per
  table. Test- and diagnostic-facing; the supervised process drives sweeps via
  the configured interval, not this call.
  """
  @spec sweep_now(GenServer.server()) :: %{optional(String.t()) => non_neg_integer()}
  def sweep_now(server \\ __MODULE__) do
    GenServer.call(server, :sweep_now)
  end

  @impl true
  def handle_call(:sweep_now, _from, state) do
    {:reply, sweep(state), state}
  end

  # Deletes, per table, every row whose `expires_at` is strictly before the
  # single "now" captured for this sweep. Returns a map of table => deleted
  # count. A `DELETE` that raises (e.g. a missing table) propagates: silently
  # swallowing a failed sweep would let a table grow unbounded with no signal,
  # so this fails loud rather than fails quiet.
  defp sweep(%{repo: repo, table_prefix: prefix} = _state) do
    now = DateTime.utc_now()

    %{
      @authorization_codes => delete_expired(repo, expired_query(@authorization_codes, now), prefix),
      @refresh_tokens => delete_expired(repo, expired_query(@refresh_tokens, now), prefix),
      @dpop_nonces => delete_expired(repo, expired_query(@dpop_nonces, now), prefix),
      @dpop_replays => delete_expired(repo, expired_query(@dpop_replays, now), prefix)
    }
  end

  # `from/2` requires a literal string source, so each generated table gets its
  # own clause keyed off the compile-time module attribute. All four clauses are
  # the identical strict `WHERE expires_at < $now` predicate.
  defp expired_query(@authorization_codes, now), do: from(r in @authorization_codes, where: r.expires_at < ^now)

  defp expired_query(@refresh_tokens, now), do: from(r in @refresh_tokens, where: r.expires_at < ^now)

  defp expired_query(@dpop_nonces, now), do: from(r in @dpop_nonces, where: r.expires_at < ^now)

  defp expired_query(@dpop_replays, now), do: from(r in @dpop_replays, where: r.expires_at < ^now)

  defp delete_expired(repo, query, prefix) do
    {deleted, _} = repo.delete_all(query, prefix: prefix)
    deleted
  end

  defp schedule_sweep(interval_ms) do
    Process.send_after(self(), :sweep, interval_ms)
  end

  defp fetch_config!(opts) do
    case Keyword.fetch(opts, :config) do
      {:ok, %Config{} = config} ->
        config

      {:ok, other} ->
        raise ArgumentError,
              "AttestoPhoenix.Store.Sweeper: :config must be a %AttestoPhoenix.Config{}, " <>
                "got: #{inspect(other)}"

      :error ->
        raise ArgumentError,
              "AttestoPhoenix.Store.Sweeper: :config (a %AttestoPhoenix.Config{}) is required"
    end
  end

  defp sweep_interval_ms!(%Config{sweep_interval_ms: interval}) when is_integer(interval) and interval > 0 do
    interval
  end

  defp sweep_interval_ms!(%Config{sweep_interval_ms: interval}) do
    raise ArgumentError,
          "AttestoPhoenix.Store.Sweeper: :sweep_interval_ms must be a positive integer to run " <>
            "the sweeper; got #{inspect(interval)}. Leave the sweeper out of the supervision " <>
            "tree instead of configuring a non-positive interval."
  end
end
