if Code.ensure_loaded?(FastestMCP.Auth) do
  defmodule Gatekeep.FastestMCP do
    @moduledoc """
    Protects a [FastestMCP](https://hexdocs.pm/fastest_mcp) server with
    Gatekeep tokens. See the [FastestMCP guide](fastest_mcp.md).

    Over HTTP, put `Gatekeep.Plug.Resource` in front of the server: it checks
    the token, its audience, DPoP, and scopes, answers failures with the
    challenges MCP clients follow, and assigns the token. Pass the assign
    through with `auth_assigns:`, and use this module as the authenticator so
    handlers see the caller:

        # router
        pipeline :mcp do
          plug Gatekeep.Plug.Resource, gatekeep: MyApp.Auth, resource: "https://example.com/mcp"
        end

        scope "/" do
          pipe_through :mcp
          forward "/mcp", MyApp.MCPServer, auth_assigns: [:gatekeep_token]
        end

        # server
        base_server(opts)
        |> FastestMCP.add_auth(Gatekeep.FastestMCP,
          gatekeep: MyApp.Auth,
          resource: "https://example.com/mcp",
          scopes: ["notes:read"]
        )

    `:scopes` are scopes every request needs; a token without them gets
    `403`. (FastestMCP's own `required_scopes` are checked only over HTTP.)

    Without the assign, such as for in-process calls with
    `auth_input: %{"authorization" => "Bearer ..."}`, it checks a Bearer token
    itself. DPoP-bound tokens need the plug, which sees the request's method
    and URL.

    Handlers see `ctx.principal` as `%{"sub" => subject, "client_id" => id}`,
    and `ctx.auth` as the `Gatekeep.Token` under `:token`. The result's
    `audiences` and `scopes` are the token's, so FastestMCP's
    `protected_resource` checks (see `protected_resource/2`) work too.
    """

    @behaviour FastestMCP.Auth

    alias Gatekeep.{Config, Token}

    @impl true
    def authenticate(input, _context, opts) do
      gatekeep = Map.fetch!(opts, :gatekeep)
      resource = Map.fetch!(opts, :resource)

      with {:ok, token} <- token(input, gatekeep, resource) do
        missing = Map.get(opts, :scopes, []) -- token.scopes

        if missing == [] do
          {:ok, result(token)}
        else
          {:error,
           %FastestMCP.Error{
             code: :forbidden,
             message: "access token does not grant the required scopes",
             details: %{missing_scopes: missing}
           }}
        end
      end
    end

    defp token(input, gatekeep, resource) do
      case input do
        %{"assigns" => %{"gatekeep_token" => %Token{} = token}} ->
          check_resource(token, gatekeep, resource)

        _ ->
          request = %{
            authorization: input["authorization"] || bearer(input["token"]),
            dpop: [],
            method: "POST",
            path: URI.parse(resource).path || "/"
          }

          case Token.authenticate(gatekeep.config(), resource, request) do
            {:ok, token} -> {:ok, token}
            {:error, :missing_token} -> {:error, {:unauthorized, "missing credentials"}}
            {:error, _} -> {:error, {:unauthorized, "invalid credentials"}}
          end
      end
    end

    # The assign is trusted only for the resource it was checked for.
    defp check_resource(token, gatekeep, resource) do
      if Gatekeep.Util.same_url?(token.resource, Config.resource(gatekeep.config(), resource).id),
        do: {:ok, token},
        else: {:error, {:unauthorized, "invalid credentials"}}
    end

    defp bearer(token) when is_binary(token), do: "Bearer " <> token
    defp bearer(_), do: nil

    defp result(%Token{} = token) do
      %FastestMCP.Auth.Result{
        principal: %{"sub" => token.subject, "client_id" => token.client_id},
        auth: %{token: token},
        audiences: [token.resource],
        scopes: token.scopes,
        capabilities: token.scopes
      }
    end

    @doc """
    Options for FastestMCP's `protected_resource:` server option, from the
    Gatekeep resource `resource`. `required_scopes` defaults to none.
    Gatekeep serves the metadata document itself (`Gatekeep.Plug.Endpoints`);
    FastestMCP uses these to check audiences and scopes and to build its
    challenges.
    """
    @spec protected_resource(module(), String.t(), keyword()) :: keyword()
    def protected_resource(gatekeep, resource, opts \\ []) do
      config = gatekeep.config()
      %Gatekeep.Resource{} = r = Config.resource(config, resource)

      [
        resource: r.id,
        authorization_servers: [config.issuer],
        scopes_supported: r.scope_names,
        required_scopes: Keyword.get(opts, :required_scopes, [])
      ]
    end
  end
end
