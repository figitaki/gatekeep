defmodule Gatekeep.Storage.Ecto.Migration do
  @moduledoc """
  Creates and drops the tables of `Gatekeep.Storage.Ecto`. Call it from a
  migration of your app:

      defmodule MyApp.Repo.Migrations.AddGatekeep do
        use Ecto.Migration

        def up, do: Gatekeep.Storage.Ecto.Migration.up(version: 1)
        def down, do: Gatekeep.Storage.Ecto.Migration.down(version: 1)
      end

  Later releases that change the tables add versions; a new migration then
  calls `up(version: 2)`, and so on, as Oban does.
  """

  use Ecto.Migration

  @current 1

  @doc "Migrates up to `:version` (default: the current one)."
  def up(opts \\ []) do
    for version <- 1..Keyword.get(opts, :version, @current)//1, do: change(version, :up)
    :ok
  end

  @doc "Migrates down from `:version` (default: the current one) to nothing."
  def down(opts \\ []) do
    for version <- Keyword.get(opts, :version, @current)..1//-1, do: change(version, :down)
    :ok
  end

  defp change(1, :up) do
    # One row per approved authorization. Its refresh token is the grant.
    create table(:gatekeep_grants) do
      add :client_id, :text, null: false
      add :client_name, :text
      add :subject, :text, null: false
      add :owner, :text
      add :resource, :text, null: false
      add :scopes, {:array, :text}, null: false, default: []
      add :claims, :map, null: false, default: %{}
      add :grant_type, :text, null: false
      add :refresh_token_hash, :binary
      add :dpop_jkt, :text
      add :expires_at, :utc_datetime
      add :revoked_at, :utc_datetime
      add :last_used_at, :utc_datetime

      timestamps(type: :utc_datetime)
    end

    create unique_index(:gatekeep_grants, [:refresh_token_hash])
    create index(:gatekeep_grants, [:owner])
    create index(:gatekeep_grants, [:subject])
    create index(:gatekeep_grants, [:client_id])

    create table(:gatekeep_codes) do
      add :code_hash, :binary, null: false
      add :client_id, :text, null: false
      add :client_name, :text
      add :redirect_uri, :text, null: false
      add :code_challenge, :text, null: false
      # The DPoP key the authorization request bound the code to (RFC 9449 §10).
      add :dpop_jkt, :text
      add :resource, :text, null: false
      add :scopes, {:array, :text}, null: false
      add :subject, :text, null: false
      add :owner, :text
      add :claims, :map, null: false, default: %{}
      add :grant_id, references(:gatekeep_grants, on_delete: :nilify_all)
      add :expires_at, :utc_datetime, null: false
      add :consumed_at, :utc_datetime

      timestamps(type: :utc_datetime, updated_at: false)
    end

    create unique_index(:gatekeep_codes, [:code_hash])

    create table(:gatekeep_access_tokens) do
      add :token_hash, :binary, null: false
      add :grant_id, references(:gatekeep_grants, on_delete: :delete_all)
      add :client_id, :text, null: false
      add :subject, :text, null: false
      add :resource, :text, null: false
      add :scopes, {:array, :text}, null: false
      add :dpop_jkt, :text
      add :expires_at, :utc_datetime, null: false
      add :revoked_at, :utc_datetime

      timestamps(type: :utc_datetime, updated_at: false)
    end

    create unique_index(:gatekeep_access_tokens, [:token_hash])
    create index(:gatekeep_access_tokens, [:grant_id])
    create index(:gatekeep_access_tokens, [:expires_at])

    # Refresh tokens a rotating grant replaced, kept for the grant's
    # lifetime, so presenting any of them again revokes the grant.
    create table(:gatekeep_consumed_refresh_tokens) do
      add :grant_id, references(:gatekeep_grants, on_delete: :delete_all), null: false
      add :token_hash, :binary, null: false

      timestamps(type: :utc_datetime, updated_at: false)
    end

    create unique_index(:gatekeep_consumed_refresh_tokens, [:token_hash])
    create index(:gatekeep_consumed_refresh_tokens, [:grant_id])

    # Clients registered through dynamic client registration (RFC 7591).
    create table(:gatekeep_clients) do
      add :client_id, :text, null: false
      add :client_name, :text
      add :redirect_uris, {:array, :text}, null: false

      timestamps(type: :utc_datetime, updated_at: false)
    end

    create unique_index(:gatekeep_clients, [:client_id])

    # Replay cache shared by every server: client assertion, DPoP proof, and
    # identity assertion jtis.
    create table(:gatekeep_seen_jtis, primary_key: false) do
      add :kind, :text, null: false, primary_key: true
      add :scope, :text, null: false, primary_key: true
      add :jti, :text, null: false, primary_key: true
      add :expires_at, :utc_datetime, null: false
    end

    create index(:gatekeep_seen_jtis, [:expires_at])
  end

  defp change(1, :down) do
    drop table(:gatekeep_seen_jtis)
    drop table(:gatekeep_clients)
    drop table(:gatekeep_consumed_refresh_tokens)
    drop table(:gatekeep_access_tokens)
    drop table(:gatekeep_codes)
    drop table(:gatekeep_grants)
  end
end
