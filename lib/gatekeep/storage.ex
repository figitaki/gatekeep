defmodule Gatekeep.Storage do
  @moduledoc """
  Where Gatekeep keeps codes, grants, tokens, registered clients, and the
  replay cache. `Gatekeep.Storage.Ecto` implements it on an Ecto repo.

  Every callback takes the adapter's options, the keyword list of
  `storage: {Adapter, opts}`, first. Codes, refresh tokens, and access tokens
  reach the storage only as SHA-256 hashes.

  ## Concurrency

  The security of codes and refresh tokens depends on two properties an
  adapter must provide:

    * `consume_code/3` marks a code consumed atomically, and the code stays
      locked until the surrounding `transaction/2` ends. A concurrent second
      redemption waits, then sees the code consumed and the grant the first
      one created, so it can revoke it.
    * `lock_grant_by_refresh_token/2` locks the grant until the surrounding
      transaction ends, so two refreshes with one token take turns and the
      second finds the token rotated away, which is reuse.

  ## Records

  A *grant* is one approved authorization: a client acting for a subject at
  one resource with some scopes. Its refresh token, if any, is the grant
  itself; revoking the grant stops the refresh token and every access token
  issued under it.
  """

  @type opts :: keyword()

  @type code :: %{
          required(:code_hash) => binary(),
          required(:client_id) => String.t(),
          required(:redirect_uri) => String.t(),
          required(:code_challenge) => String.t(),
          required(:resource) => String.t(),
          required(:scopes) => [String.t()],
          required(:subject) => String.t(),
          required(:expires_at) => DateTime.t(),
          optional(:client_name) => String.t() | nil,
          optional(:owner) => String.t() | nil,
          optional(:claims) => map(),
          optional(:dpop_jkt) => String.t() | nil,
          optional(:consumed_at) => DateTime.t() | nil,
          optional(:grant_id) => term() | nil
        }

  @type grant :: %{
          required(:id) => term(),
          required(:client_id) => String.t(),
          required(:subject) => String.t(),
          required(:resource) => String.t(),
          required(:scopes) => [String.t()],
          required(:grant_type) => String.t(),
          optional(:client_name) => String.t() | nil,
          optional(:owner) => String.t() | nil,
          optional(:claims) => map(),
          optional(:refresh_token_hash) => binary() | nil,
          optional(:dpop_jkt) => String.t() | nil,
          optional(:expires_at) => DateTime.t() | nil,
          optional(:revoked_at) => DateTime.t() | nil,
          optional(:last_used_at) => DateTime.t() | nil,
          optional(:inserted_at) => DateTime.t()
        }

  @type access_token :: %{
          required(:token_hash) => binary(),
          required(:client_id) => String.t(),
          required(:subject) => String.t(),
          required(:resource) => String.t(),
          required(:scopes) => [String.t()],
          required(:expires_at) => DateTime.t(),
          optional(:grant_id) => term() | nil,
          optional(:dpop_jkt) => String.t() | nil,
          optional(:revoked_at) => DateTime.t() | nil,
          optional(:grant) => grant() | nil
        }

  @type device_code :: %{
          required(:device_code_hash) => binary(),
          required(:user_code_hash) => binary(),
          required(:client_id) => String.t(),
          required(:resource) => String.t(),
          required(:scopes) => [String.t()],
          required(:interval) => pos_integer(),
          required(:expires_at) => DateTime.t(),
          optional(:client_name) => String.t() | nil,
          optional(:status) => String.t(),
          optional(:subject) => String.t() | nil,
          optional(:owner) => String.t() | nil,
          optional(:claims) => map(),
          optional(:last_polled_at) => DateTime.t() | nil,
          optional(:consumed_at) => DateTime.t() | nil,
          optional(:grant_id) => term() | nil
        }

  @type registered_client :: %{
          client_id: String.t(),
          client_name: String.t() | nil,
          redirect_uris: [String.t()],
          inserted_at: DateTime.t()
        }

  @doc "Runs `fun` in a transaction and returns its result. Nested calls join the outer one."
  @callback transaction(opts(), (-> result)) :: result when result: term()

  @callback insert_code(opts(), code()) :: :ok

  @doc """
  Marks the unconsumed code with `code_hash` consumed at `now` and returns
  it, locked until the transaction ends. `:error` when there is none or it
  was consumed already.
  """
  @callback consume_code(opts(), code_hash :: binary(), now :: DateTime.t()) ::
              {:ok, code()} | :error

  @doc "The code with `code_hash`, consumed or not."
  @callback get_code(opts(), code_hash :: binary()) :: {:ok, code()} | :error

  @doc "Records the grant a redeemed code created, so reusing the code can revoke it."
  @callback set_code_grant(opts(), code_hash :: binary(), grant_id :: term()) :: :ok

  @doc "Inserts a grant and returns it with its `id`."
  @callback insert_grant(opts(), map()) :: {:ok, grant()}

  @callback get_grant(opts(), grant_id :: term()) :: {:ok, grant()} | :error

  @doc """
  The grant whose current refresh token has `hash`, revoked or not, locked
  until the transaction ends.
  """
  @callback lock_grant_by_refresh_token(opts(), hash :: binary()) :: {:ok, grant()} | :error

  @doc """
  Replaces the grant's refresh token `old_hash` with `new_hash` and records
  the old one as consumed for the grant's lifetime. `:error` when the grant
  no longer has `old_hash` or is revoked.
  """
  @callback rotate_refresh_token(
              opts(),
              grant_id :: term(),
              old_hash :: binary(),
              new_hash :: binary(),
              now :: DateTime.t()
            ) :: :ok | :error

  @doc "The grant that once had the refresh token `hash` and rotated it away."
  @callback find_grant_by_consumed_refresh_token(opts(), hash :: binary()) ::
              {:ok, grant()} | :error

  @doc "Revokes the grant. Revoking a revoked or unknown grant succeeds."
  @callback revoke_grant(opts(), grant_id :: term(), now :: DateTime.t()) :: :ok

  @doc "Grants matching the filters (`:owner`, `:subject`, `:client_id`), newest first."
  @callback list_grants(opts(), filters :: keyword()) :: [grant()]

  @doc "Records that the grant was used. Called at most once a minute per grant."
  @callback touch_grant(opts(), grant_id :: term(), now :: DateTime.t()) :: :ok

  @callback insert_access_token(opts(), access_token()) :: :ok

  @doc "The access token with `hash` and, under `:grant`, its grant or nil."
  @callback get_access_token(opts(), hash :: binary()) :: {:ok, access_token()} | :error

  @callback revoke_access_token(opts(), hash :: binary(), now :: DateTime.t()) :: :ok

  @doc """
  Inserts a device authorization request (RFC 8628) with `status`
  `"pending"`. `{:error, :conflict}` when a live request has the same
  `user_code_hash`. Should prune expired requests from time to time.
  """
  @callback insert_device_code(opts(), device_code()) :: :ok | {:error, :conflict}

  @doc "The device authorization request with `user_code_hash`, in any state."
  @callback get_device_code(opts(), user_code_hash :: binary()) :: {:ok, device_code()} | :error

  @doc """
  Applies the user's decision, `changes` such as `%{status: "approved",
  subject: ...}`, to the request with `user_code_hash`, only while it is
  `"pending"` and expires after `now`. `:error` otherwise.
  """
  @callback decide_device_code(
              opts(),
              user_code_hash :: binary(),
              changes :: map(),
              now :: DateTime.t()
            ) :: {:ok, device_code()} | :error

  @doc """
  The device authorization request with `device_code_hash`, locked until
  the transaction ends, so polls of one code take turns.
  """
  @callback lock_device_code(opts(), device_code_hash :: binary()) ::
              {:ok, device_code()} | :error

  @doc "Updates the request with `device_code_hash`: `:interval`, `:last_polled_at`, `:consumed_at`, `:grant_id`."
  @callback update_device_code(opts(), device_code_hash :: binary(), changes :: map()) :: :ok

  @callback insert_client(opts(), registered_client()) :: :ok

  @callback get_client(opts(), client_id :: String.t()) :: {:ok, registered_client()} | :error

  @doc """
  Records `jti` of `kind` for `scope` (such as a client ID, a DPoP key, or an
  enterprise issuer) until `expires_at`. `{:error, :replayed}` when it was
  recorded already, by any server. Should prune expired entries from time to
  time.
  """
  @callback remember_jti(
              opts(),
              kind :: String.t(),
              scope :: String.t(),
              jti :: String.t(),
              expires_at :: DateTime.t()
            ) :: :ok | {:error, :replayed}

  @doc false
  def call(%Gatekeep.Config{storage: {module, opts}}, fun, args),
    do: apply(module, fun, [opts | args])
end
