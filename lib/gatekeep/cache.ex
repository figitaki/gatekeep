defmodule Gatekeep.Cache do
  @moduledoc false
  # A per-issuer ETS cache of fetched documents: client metadata with its key
  # set, and enterprise issuers' key sets. Entries are
  # `{key, value, expires_at, fetched_at}`. Expired entries are swept every
  # minute, and the table holds at most `:client_cache_size` entries; past
  # that, results are used but not cached, so unknown IDs can't grow memory
  # without bound.

  use GenServer

  @sweep_interval :timer.seconds(60)

  def start_link(name), do: GenServer.start_link(__MODULE__, name, name: table(name))

  @doc "The ETS table of the issuer `name`."
  def table(name), do: Module.concat(name, Cache)

  @impl true
  def init(name) do
    :ets.new(table(name), [:named_table, :public, :set, read_concurrency: true])
    schedule_sweep()
    {:ok, name}
  end

  @impl true
  def handle_info(:sweep, name) do
    sweep(name)
    schedule_sweep()
    {:noreply, name}
  end

  defp schedule_sweep, do: Process.send_after(self(), :sweep, @sweep_interval)

  @doc "Drops expired entries."
  def sweep(name) do
    now = Gatekeep.Util.now()
    :ets.select_delete(table(name), [{{:_, :_, :"$1", :_}, [{:"=<", :"$1", now}], [true]}])
  end

  @doc "The unexpired entry for `key`: `{:ok, value, fetched_at}` or `:miss`."
  def lookup(name, key) do
    now = Gatekeep.Util.now()

    case :ets.lookup(table(name), key) do
      [{_, value, expires_at, fetched_at}] when expires_at > now -> {:ok, value, fetched_at}
      _ -> :miss
    end
  end

  @doc """
  Stores `value` for `ttl` seconds, unless the table is full. Entries are
  written by the cache process, so concurrent stores of different keys can't
  together exceed `max_size`. Stores follow fetches, so they are rare.
  """
  def put(name, key, value, ttl, max_size, fetched_at \\ Gatekeep.Util.now()) do
    GenServer.call(
      table(name),
      {:admit, {key, value, Gatekeep.Util.now() + ttl, fetched_at}, max_size}
    )
  end

  @impl true
  def handle_call({:admit, {key, _, _, _} = entry, max_size}, _from, name) do
    table = table(name)

    if :ets.member(table, key) or :ets.info(table, :size) < max_size do
      :ets.insert(table, entry)
    end

    {:reply, :ok, name}
  end

  @doc "Replaces the value of an existing entry, keeping its expiry."
  def update(name, key, value, fetched_at) do
    case :ets.lookup(table(name), key) do
      [{_, _, expires_at, _}] -> :ets.insert(table(name), {key, value, expires_at, fetched_at})
      [] -> :ok
    end

    :ok
  end

  def delete(name, key), do: :ets.delete(table(name), key)

  @doc """
  Runs `fun` while holding a lock on `key` on this node, so concurrent
  requests for one document share a single fetch: the others wait, then
  read the cache.
  """
  def single_flight(name, key, fun),
    do: :global.trans({{__MODULE__, name, key}, self()}, fun, [node()])
end
