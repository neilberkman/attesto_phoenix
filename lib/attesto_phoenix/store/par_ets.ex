defmodule AttestoPhoenix.Store.PAR.ETS do
  @moduledoc """
  Single-node ETS Pushed Authorization Request store.

  This is a development/default store. Clustered deployments should provide a
  `AttestoPhoenix.PARStore` backed by shared storage.
  """

  @behaviour AttestoPhoenix.PARStore

  @table :attesto_phoenix_par_requests

  @impl true
  def put(request_uri, params, ttl_seconds) when is_binary(request_uri) and is_map(params) do
    ensure_table()
    expires_at = System.system_time(:second) + ttl_seconds
    true = :ets.insert(@table, {request_uri, params, expires_at})
    :ok
  end

  @impl true
  def fetch(request_uri) when is_binary(request_uri) do
    ensure_table()
    now = System.system_time(:second)

    case :ets.lookup(@table, request_uri) do
      [{^request_uri, params, expires_at}] when expires_at > now ->
        {:ok, params}

      [{^request_uri, _params, _expires_at}] ->
        :ets.delete(@table, request_uri)
        :error

      [] ->
        :error
    end
  end

  @impl true
  def take(request_uri) when is_binary(request_uri) do
    ensure_table()
    now = System.system_time(:second)

    case :ets.take(@table, request_uri) do
      [{^request_uri, params, expires_at}] when expires_at > now -> {:ok, params}
      _ -> :error
    end
  end

  defp ensure_table do
    case :ets.whereis(@table) do
      :undefined -> :ets.new(@table, [:set, :public, :named_table, read_concurrency: true])
      _tid -> @table
    end
  end
end
