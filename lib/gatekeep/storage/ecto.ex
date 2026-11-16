defmodule Gatekeep.Storage.Ecto do
  @moduledoc """
  `Gatekeep.Storage` on an Ecto repo, for PostgreSQL.

      config :my_app, MyApp.Auth,
        storage: {Gatekeep.Storage.Ecto, repo: MyApp.Repo}

  Create the tables with a migration that calls
  `Gatekeep.Storage.Ecto.Migration`:

      defmodule MyApp.Repo.Migrations.AddGatekeep do
        use Ecto.Migration

        def up, do: Gatekeep.Storage.Ecto.Migration.up(version: 1)
        def down, do: Gatekeep.Storage.Ecto.Migration.down(version: 1)
      end

  It relies on PostgreSQL's row locks: `UPDATE ... RETURNING` for
  consuming codes and `SELECT ... FOR UPDATE` for refresh tokens.

  ## Importing existing grants

  The tables are `gatekeep_grants`, `gatekeep_codes`,
  `gatekeep_access_tokens`, `gatekeep_consumed_refresh_tokens`,
  `gatekeep_clients`, and `gatekeep_seen_jtis`; see
  `Gatekeep.Storage.Ecto.Migration` for their columns. To move grants from
  another issuer without signing everyone out, copy its rows into them:

    * tokens are stored as raw SHA-256 digests (`:crypto.hash(:sha256,
      token)`), and their text is never parsed, so any opaque token works;
    * a grant's `expires_at` is when its refresh token stops working;
    * keep grant IDs when copying, then advance the `gatekeep_grants` ID
      sequence past the largest;
    * set `:registered_client_prefix` to the prefix of the copied
      registered client IDs.

  Codes and replay entries live for minutes and need not be copied.

  ## Options

    * `:repo` - the Ecto repo (required).
  """

  @behaviour Gatekeep.Storage

  import Ecto.Query, only: [from: 2]

  alias Gatekeep.Storage.Ecto.{AccessToken, Code, Grant, RegisteredClient}

  @impl true
  def transaction(opts, fun) do
    repo = repo(opts)

    if repo.in_transaction?() do
      fun.()
    else
      {:ok, result} = repo.transaction(fun)
      result
    end
  end

  @impl true
  def insert_code(opts, code) do
    repo(opts).insert!(struct!(Code, code))
    :ok
  end

  @impl true
  def consume_code(opts, code_hash, now) do
    query =
      from c in Code, where: c.code_hash == ^code_hash and is_nil(c.consumed_at), select: c

    case repo(opts).update_all(query, set: [consumed_at: now]) do
      {1, [code]} -> {:ok, to_map(code)}
      {0, _} -> :error
    end
  end

  @impl true
  def get_code(opts, code_hash) do
    case repo(opts).get_by(Code, code_hash: code_hash) do
      nil -> :error
      code -> {:ok, to_map(code)}
    end
  end

  @impl true
  def set_code_grant(opts, code_hash, grant_id) do
    repo(opts).update_all(from(c in Code, where: c.code_hash == ^code_hash),
      set: [grant_id: grant_id]
    )

    :ok
  end

  @impl true
  def insert_grant(opts, grant) do
    {:ok, grant |> then(&struct!(Grant, &1)) |> repo(opts).insert!() |> to_map()}
  end

  @impl true
  def get_grant(opts, grant_id) do
    case repo(opts).get(Grant, grant_id) do
      nil -> :error
      grant -> {:ok, to_map(grant)}
    end
  end

  @impl true
  def lock_grant_by_refresh_token(opts, hash) do
    query = from g in Grant, where: g.refresh_token_hash == ^hash, lock: "FOR UPDATE"

    case repo(opts).one(query) do
      nil -> :error
      grant -> {:ok, to_map(grant)}
    end
  end

  @impl true
  def rotate_refresh_token(opts, grant_id, old_hash, new_hash, now) do
    repo = repo(opts)

    query =
      from g in Grant,
        where: g.id == ^grant_id and g.refresh_token_hash == ^old_hash and is_nil(g.revoked_at)

    case repo.update_all(query, set: [refresh_token_hash: new_hash, updated_at: now]) do
      {1, _} ->
        repo.insert_all("gatekeep_consumed_refresh_tokens", [
          %{grant_id: grant_id, token_hash: old_hash, inserted_at: now}
        ])

        :ok

      {0, _} ->
        :error
    end
  end

  @impl true
  def find_grant_by_consumed_refresh_token(opts, hash) do
    query =
      from c in "gatekeep_consumed_refresh_tokens",
        join: g in Grant,
        on: g.id == c.grant_id,
        where: c.token_hash == ^hash,
        select: g

    case repo(opts).one(query) do
      nil -> :error
      grant -> {:ok, to_map(grant)}
    end
  end

  @impl true
  def revoke_grant(opts, grant_id, now) do
    repo(opts).update_all(from(g in Grant, where: g.id == ^grant_id and is_nil(g.revoked_at)),
      set: [revoked_at: now, updated_at: now]
    )

    :ok
  end

  @impl true
  def list_grants(opts, filters) do
    query =
      Enum.reduce(filters, from(g in Grant, order_by: [desc: g.inserted_at, desc: g.id]), fn
        {:owner, owner}, q -> from g in q, where: g.owner == ^owner
        {:subject, subject}, q -> from g in q, where: g.subject == ^subject
        {:client_id, client_id}, q -> from g in q, where: g.client_id == ^client_id
      end)

    query |> repo(opts).all() |> Enum.map(&to_map/1)
  end

  @impl true
  def touch_grant(opts, grant_id, now) do
    repo(opts).update_all(from(g in Grant, where: g.id == ^grant_id), set: [last_used_at: now])
    :ok
  end

  @impl true
  def insert_access_token(opts, token) do
    repo(opts).insert!(struct!(AccessToken, Map.delete(token, :grant)))
    :ok
  end

  @impl true
  def get_access_token(opts, hash) do
    query =
      from t in AccessToken,
        left_join: g in assoc(t, :grant),
        where: t.token_hash == ^hash,
        preload: [grant: g]

    case repo(opts).one(query) do
      nil ->
        :error

      token ->
        grant = if token.grant, do: to_map(token.grant)
        {:ok, token |> to_map() |> Map.put(:grant, grant)}
    end
  end

  @impl true
  def revoke_access_token(opts, hash, now) do
    repo(opts).update_all(
      from(t in AccessToken, where: t.token_hash == ^hash and is_nil(t.revoked_at)),
      set: [revoked_at: now]
    )

    :ok
  end

  @impl true
  def insert_client(opts, client) do
    repo(opts).insert!(struct!(RegisteredClient, client))
    :ok
  end

  @impl true
  def get_client(opts, client_id) do
    case repo(opts).get_by(RegisteredClient, client_id: client_id) do
      nil -> :error
      client -> {:ok, to_map(client)}
    end
  end

  @impl true
  def remember_jti(opts, kind, scope, jti, expires_at) do
    repo = repo(opts)

    {count, _} =
      repo.insert_all(
        "gatekeep_seen_jtis",
        [%{kind: kind, scope: scope, jti: jti, expires_at: DateTime.truncate(expires_at, :second)}],
        on_conflict: :nothing,
        conflict_target: [:kind, :scope, :jti]
      )

    if count == 1 do
      # Keep the table small without a scheduled job: about one write in
      # fifty clears entries whose window has passed.
      if :rand.uniform(50) == 1 do
        now = DateTime.utc_now()
        repo.delete_all(from j in "gatekeep_seen_jtis", where: j.expires_at < ^now)
      end

      :ok
    else
      {:error, :replayed}
    end
  end

  defp repo(opts), do: Keyword.fetch!(opts, :repo)

  defp to_map(struct) do
    struct |> Map.from_struct() |> Map.drop([:__meta__, :grant])
  end
end
