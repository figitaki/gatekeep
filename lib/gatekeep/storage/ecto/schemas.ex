defmodule Gatekeep.Storage.Ecto.Grant do
  @moduledoc false
  use Ecto.Schema

  schema "gatekeep_grants" do
    field :client_id, :string
    field :client_name, :string
    field :subject, :string
    field :owner, :string
    field :resource, :string
    field :scopes, {:array, :string}, default: []
    field :claims, :map, default: %{}
    field :grant_type, :string
    field :refresh_token_hash, :binary, redact: true
    field :dpop_jkt, :string
    field :expires_at, :utc_datetime
    field :revoked_at, :utc_datetime
    field :last_used_at, :utc_datetime

    timestamps(type: :utc_datetime)
  end
end

defmodule Gatekeep.Storage.Ecto.Code do
  @moduledoc false
  use Ecto.Schema

  schema "gatekeep_codes" do
    field :code_hash, :binary, redact: true
    field :client_id, :string
    field :client_name, :string
    field :redirect_uri, :string
    field :code_challenge, :string
    field :dpop_jkt, :string
    field :resource, :string
    field :scopes, {:array, :string}
    field :subject, :string
    field :owner, :string
    field :claims, :map, default: %{}
    field :grant_id, :id
    field :expires_at, :utc_datetime
    field :consumed_at, :utc_datetime

    timestamps(type: :utc_datetime, updated_at: false)
  end
end

defmodule Gatekeep.Storage.Ecto.AccessToken do
  @moduledoc false
  use Ecto.Schema

  schema "gatekeep_access_tokens" do
    field :token_hash, :binary, redact: true
    field :client_id, :string
    field :subject, :string
    field :resource, :string
    field :scopes, {:array, :string}
    field :dpop_jkt, :string
    field :expires_at, :utc_datetime
    field :revoked_at, :utc_datetime

    belongs_to :grant, Gatekeep.Storage.Ecto.Grant

    timestamps(type: :utc_datetime, updated_at: false)
  end
end

defmodule Gatekeep.Storage.Ecto.RegisteredClient do
  @moduledoc false
  use Ecto.Schema

  schema "gatekeep_clients" do
    field :client_id, :string
    field :client_name, :string
    field :redirect_uris, {:array, :string}

    timestamps(type: :utc_datetime, updated_at: false)
  end
end
