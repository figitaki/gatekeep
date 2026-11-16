defmodule Gatekeep do
  @moduledoc """
  An OAuth 2.1 authorization server and protected-resource toolkit for MCP
  servers.

  Define one module for your issuer:

      defmodule MyApp.Auth do
        use Gatekeep, otp_app: :my_app
      end

  configure it (see `Gatekeep.Config` for every option):

      config :my_app, MyApp.Auth,
        issuer: "https://example.com",
        storage: {Gatekeep.Storage.Ecto, repo: MyApp.Repo},
        resources: [
          [id: "https://example.com/mcp", scopes: [{"notes:read", "Read your notes"}]]
        ]

  and start it in your supervision tree, after the repo:

      children = [MyApp.Repo, MyApp.Auth, MyAppWeb.Endpoint]

  The module is what the plugs take as their `:gatekeep` option:

    * `Gatekeep.Plug.Endpoints` serves the token, revocation, and registration
      endpoints, the authorization server metadata (RFC 8414), and the
      protected resource metadata (RFC 9728).
    * `Gatekeep.Plug.Authorize` serves the authorization endpoint and hands
      sign-in and consent to your `Gatekeep.Consent` module.
    * `Gatekeep.Plug.Resource` protects an API with the issued tokens.

  The functions in `Gatekeep.Authorization`, `Gatekeep.TokenEndpoint`, and
  `Gatekeep.Token` are what the plugs call, for when you'd rather write your
  own controllers.

  ## What `use Gatekeep` defines

    * `config/0` - the validated `Gatekeep.Config`, read from the application
      environment on every call so runtime changes take effect.
    * `child_spec/1` - starts the client metadata cache.
    * `list_grants/1` and `revoke_grant/1` - grant management for settings
      pages, as `Gatekeep.list_grants/2` and `Gatekeep.revoke_grant/2`.
  """

  alias Gatekeep.{Config, Storage}

  defmacro __using__(opts) do
    otp_app = Keyword.fetch!(opts, :otp_app)

    quote do
      @doc "The validated Gatekeep configuration of this issuer."
      @spec config() :: Gatekeep.Config.t()
      def config do
        unquote(otp_app)
        |> Application.get_env(__MODULE__, [])
        |> Keyword.put(:name, __MODULE__)
        |> Gatekeep.Config.new!()
      end

      @doc false
      def child_spec(_opts) do
        %{id: __MODULE__, start: {Gatekeep.Cache, :start_link, [__MODULE__]}}
      end

      @doc "Grants matching `filters`; see `Gatekeep.list_grants/2`."
      def list_grants(filters), do: Gatekeep.list_grants(config(), filters)

      @doc "Revokes a grant; see `Gatekeep.revoke_grant/2`."
      def revoke_grant(grant_id), do: Gatekeep.revoke_grant(config(), grant_id)
    end
  end

  @doc """
  Grants matching every filter, newest first: `:owner`, `:subject`, or
  `:client_id`. Revoked grants are included; check `revoked_at`.
  """
  @spec list_grants(Config.t(), keyword()) :: [Storage.grant()]
  def list_grants(%Config{} = config, filters) when is_list(filters) do
    Storage.call(config, :list_grants, [Keyword.take(filters, [:owner, :subject, :client_id])])
  end

  @doc """
  Revokes a grant by ID. Its refresh token and every access token issued
  under it stop working on their next use.
  """
  @spec revoke_grant(Config.t(), term()) :: :ok
  def revoke_grant(%Config{} = config, grant_id) do
    Storage.call(config, :revoke_grant, [grant_id, Gatekeep.Util.now_dt()])
  end

  @doc """
  The SHA-256 digest that a static client's `client_secret_sha256` option
  takes, as lowercase hex. Store this, not the secret.
  """
  @spec hash_client_secret(String.t()) :: String.t()
  def hash_client_secret(secret) when is_binary(secret) do
    :crypto.hash(:sha256, secret) |> Base.encode16(case: :lower)
  end
end
