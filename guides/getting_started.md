# Getting started

This guide protects an MCP server at `https://example.com/mcp` with a Gatekeep
issuer at `https://example.com`, in a Phoenix app with an Ecto repo and its
own user accounts.

Add the dependency to `mix.exs` and run `mix deps.get`:

```elixir
def deps do
  [
    {:gatekeep, "~> 0.1"},
    {:fastest_mcp, "~> 1.0"} # only to protect a FastestMCP server
  ]
end
```

## 1. Define and configure the issuer

```elixir
# lib/my_app/auth.ex
defmodule MyApp.Auth do
  use Gatekeep, otp_app: :my_app
end
```

```elixir
# config/runtime.exs
config :my_app, MyApp.Auth,
  issuer: "https://example.com",
  storage: {Gatekeep.Storage.Ecto, repo: MyApp.Repo},
  consent: MyAppWeb.Consent,
  resources: [
    [
      id: "https://example.com/mcp",
      name: "My notes",
      scopes: [{"notes:read", "Read your notes"}, {"notes:write", "Change your notes"}]
    ]
  ]
```

Start it after the repo, so its client metadata cache is running:

```elixir
children = [MyApp.Repo, MyApp.Auth, MyAppWeb.Endpoint]
```

## 2. Create the tables

```elixir
defmodule MyApp.Repo.Migrations.AddGatekeep do
  use Ecto.Migration

  def up, do: Gatekeep.Storage.Ecto.Migration.up(version: 1)
  def down, do: Gatekeep.Storage.Ecto.Migration.down(version: 1)
end
```

## 3. Mount the endpoints

`Gatekeep.Plug.Endpoints` serves the token, revocation, and registration
endpoints and the discovery documents. It reads its own request bodies, so
put it in your endpoint before `Plug.Parsers`:

```elixir
# lib/my_app_web/endpoint.ex
plug Gatekeep.Plug.Endpoints, gatekeep: MyApp.Auth
plug Plug.Parsers, ...
```

The authorization endpoint goes in a browser pipeline, where your session and
CSRF protection live:

```elixir
# lib/my_app_web/router.ex
scope "/oauth" do
  pipe_through :browser
  get "/authorize", Gatekeep.Plug.Authorize, gatekeep: MyApp.Auth
  post "/authorize", MyAppWeb.ConsentController, :decide
end
```

## 4. Ask for consent

Gatekeep checks the request (client, redirect URI, PKCE, resource, scopes),
then hands it to your `Gatekeep.Consent` module. You decide who the user is
and what the page looks like:

```elixir
defmodule MyAppWeb.Consent do
  @behaviour Gatekeep.Consent
  use MyAppWeb, :controller

  @impl true
  def handle_authorization(conn, request) do
    case conn.assigns.current_scope do
      nil -> redirect(conn, to: ~p"/users/log-in?#{[return_to: current_path(conn)]}")
      scope -> render(conn, :consent, request: request, user: scope.user)
    end
  end
end
```

The consent page shows `Gatekeep.Client.label(request.client)` (the verified
domain of a metadata document client) and `request.scope_descriptions`, and
posts back `request.params` with the user's choice:

```elixir
defmodule MyAppWeb.ConsentController do
  use MyAppWeb, :controller
  alias Gatekeep.Authorization

  def decide(conn, params) do
    config = MyApp.Auth.config()

    case Authorization.check(config, params) do
      {:ok, request} when params["decision"] == "approve" ->
        {:ok, url} =
          Authorization.approve(config, request,
            subject: "user:#{conn.assigns.current_scope.user.id}",
            scopes: params["scopes"]
          )

        Gatekeep.Plug.Authorize.redirect(conn, url)

      {:ok, request} ->
        Gatekeep.Plug.Authorize.redirect(conn, Authorization.deny(config, request))

      {:redirect, url} ->
        Gatekeep.Plug.Authorize.redirect(conn, url)

      {:error, _reason} ->
        send_resp(conn, 400, "This sign-in link is not valid.")
    end
  end
end
```

## 5. Protect the MCP server

With FastestMCP, check the token in front of the server and hand the result
to FastestMCP:

```elixir
# router
pipeline :mcp do
  plug Gatekeep.Plug.Resource, gatekeep: MyApp.Auth, resource: "https://example.com/mcp"
end

scope "/" do
  pipe_through :mcp
  forward "/mcp", MyApp.MCPServer, auth_assigns: [:gatekeep_token]
end
```

```elixir
# lib/my_app/mcp_server.ex
def server(opts) do
  base_server(opts)
  |> FastestMCP.add_auth(Gatekeep.FastestMCP,
    gatekeep: MyApp.Auth,
    resource: "https://example.com/mcp",
    scopes: ["notes:read"]
  )
  |> FastestMCP.add_tool("whoami", fn _args, ctx -> ctx.principal end)
end
```

A request without a token now gets the challenge MCP clients follow:

```text
HTTP/1.1 401 Unauthorized
WWW-Authenticate: Bearer resource_metadata="https://example.com/.well-known/oauth-protected-resource/mcp", DPoP resource_metadata="...", algs="ES256 PS384 RS256"
```

which leads to the resource's metadata, then the issuer's, then sign-in. Try
it with `claude mcp add --transport http notes https://example.com/mcp`. The
[FastestMCP guide](fastest_mcp.md) covers the details, and
`Gatekeep.Plug.Resource` works the same in front of any Plug API.

## Grant management

Each approval is a grant. List and revoke them on a settings page:

```elixir
MyApp.Auth.list_grants(subject: "user:42")
MyApp.Auth.revoke_grant(grant.id)
```

Pass `owner:` to `Gatekeep.Authorization.approve/3` when the subject and the
person managing the grant differ, such as agents acting for a user.

## Machine clients

Pre-register clients for the client credentials grant:

```elixir
clients: [
  [
    client_id: "nightly-report",
    client_secret_sha256: "…", # Gatekeep.hash_client_secret(secret)
    grant_types: ["client_credentials"],
    scopes: ["notes:read"]
  ]
]
```

or give them `jwks:` for `private_key_jwt`, which the MCP client credentials
extension recommends.

## Enterprise-managed authorization

Add `enterprise: [module: MyApp.EnterpriseTrust]`, implementing
`Gatekeep.Enterprise`: which IdP issuers each tenant trusts, and how an IdP
identity maps to a local user. See the
[enterprise guide](enterprise_managed_authorization.md), which also
lists what the specification leaves open.
