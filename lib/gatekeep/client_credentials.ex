defmodule Gatekeep.ClientCredentials do
  @moduledoc """
  The client credentials grant (OAuth 2.1 §4.2), for machine clients, as the
  MCP extension `io.modelcontextprotocol/oauth-client-credentials` profiles
  it.

  Only pre-registered clients that list `"client_credentials"` in their
  `:grant_types` may use it, and they must hold a credential: a public
  client can't, whatever its metadata says. The token acts as the client
  itself, or as the client's `:subject` option. No refresh token is issued.
  The grant is on while a configured client lists it.
  """

  @behaviour Gatekeep.Grant

  alias Gatekeep.{Storage, TokenEndpoint, Util}

  @impl true
  def grant_type, do: "client_credentials"

  @impl true
  def enabled?(config), do: Enum.any?(config.clients, &("client_credentials" in &1.grant_types))

  @impl true
  def token(config, client, method, params, jkt) do
    with :ok <- Util.expect(method != "none", :unauthorized_client),
         {:ok, resource} <-
           TokenEndpoint.grant_resource(config, params["resource"], params["scope"]),
         :ok <- Util.expect(method in resource.client_auth_methods, :unauthorized_client),
         :ok <- TokenEndpoint.check_dpop_required(resource, jkt),
         {:ok, scopes} <- TokenEndpoint.client_scopes(resource, client, params["scope"]) do
      {:ok, grant} =
        Storage.call(config, :insert_grant, [
          %{
            client_id: client.client_id,
            client_name: client.client_name,
            subject: client.subject || client.client_id,
            resource: resource.id,
            scopes: scopes,
            claims: %{},
            grant_type: "client_credentials",
            dpop_jkt: jkt,
            expires_at: Util.in_seconds(config.access_token_ttl)
          }
        ])

      {:ok, TokenEndpoint.issue_access_token(config, grant, scopes, jkt)}
    end
  end
end
