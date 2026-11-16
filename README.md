# Gatekeep

An OAuth 2.1 authorization server and protected-resource toolkit for
[MCP](https://modelcontextprotocol.io) servers in Elixir.

[FastestMCP](https://hex.pm/packages/fastest_mcp) checks tokens and publishes
protected resource metadata, but leaves the authorization server to you.
Gatekeep is that authorization server, built for what MCP clients such as
Claude, ChatGPT, Claude Code, and the MCP Inspector actually do:

- **OAuth 2.1 authorization code with PKCE** (S256 only), a pluggable consent
  UI, `iss` in every authorization response (RFC 9207), and errors that never
  turn the endpoint into an open redirector.
- **Refresh token rotation with reuse detection**: presenting any replaced
  refresh token revokes the grant and every token issued under it. Codes are
  consumed atomically; reusing one revokes what it issued.
- **Revocation** (RFC 7009) and **authorization server metadata** (RFC 8414).
- **Client ID metadata documents** (HTTPS `client_id`s), `private_key_jwt`
  client authentication, and **dynamic client registration** (RFC 7591) as a
  fallback, plus pre-registered clients with secrets or keys.
- **Protected resources**: RFC 9728 metadata, RFC 8707 resource indicators
  with per-resource audiences (a token for one resource is refused by every
  other), and `WWW-Authenticate` challenges with `scope` and
  `insufficient_scope`.
- **DPoP** (RFC 9449): proof verification (`htm`, `htu`, `iat` window, `jti`
  replay, `ath`), DPoP-bound access and refresh tokens, `dpop_jkt` code
  binding, and mandatory DPoP for clients that declare
  `dpop_bound_access_tokens` or resources that require it.
- **Client credentials** for machine clients.
- **Enterprise-managed authorization**: the MCP extension's ID-JAG
  (identity assertion JWT authorization grant), so users signed in to their
  company's IdP get access without a consent screen.
- **Extension points**: storage as a behaviour (Ecto/PostgreSQL adapter and
  migrations included), your own sign-in and consent, a signer behaviour for
  keys held outside the BEAM, and a FastestMCP authenticator.

Tokens, codes, and refresh tokens are random values stored only as SHA-256
hashes. Access tokens can also be RFC 9068 JWTs signed by your signer.

> Gatekeep is v0.1 and not yet published to Hex.

## Quick start: protect an MCP server

Add the dependency (from GitHub until it is on Hex):

```elixir
{:gatekeep, github: "figitaki/gatekeep"}
```

### 1. Define and configure the issuer

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

### 2. Create the tables

```elixir
defmodule MyApp.Repo.Migrations.AddGatekeep do
  use Ecto.Migration

  def up, do: Gatekeep.Storage.Ecto.Migration.up(version: 1)
  def down, do: Gatekeep.Storage.Ecto.Migration.down(version: 1)
end
```

### 3. Mount the endpoints

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

### 4. Ask for consent

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

### 5. Protect the MCP server

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
[FastestMCP guide](guides/fastest_mcp.md) covers the details, and
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
[enterprise guide](guides/enterprise_managed_authorization.md), which also
lists what the specification leaves open.

## How Gatekeep differs from Boruta

[Boruta](https://hex.pm/packages/boruta) is a mature, general OAuth 2.0 and
OpenID Connect provider core (OpenID certified, with implicit, hybrid,
password, introspection, and in its 3.0 betas DPoP and verifiable
credentials). Choose it when you need an OpenID Connect provider.

Gatekeep is narrower: an OAuth 2.1 authorization server for MCP and similar
APIs, with MCP's choices built in rather than configured:

| | Gatekeep | Boruta 2.3 |
| --- | --- | --- |
| Profile | OAuth 2.1 only: code + PKCE S256, no implicit or password | OAuth 2.0 + OpenID Connect, all grants; PKCE per client, `plain` allowed |
| Clients | Client ID metadata documents (fetched, SSRF-guarded, cached), DCR, static | Clients stored in the database, DCR |
| Resources | RFC 8707 resource indicators, per-resource audience, RFC 9728 metadata, MCP `WWW-Authenticate` challenges | No resource indicators or protected resource metadata |
| `iss` in authorization responses (RFC 9207) | Yes | No |
| Refresh tokens | Rotation; reuse of any replaced token revokes the grant | Rotation |
| DPoP | Proofs, bound access and refresh tokens, `dpop_jkt`, client-declared enforcement | 3.0 beta |
| Enterprise-managed auth (ID-JAG) | Yes | No |
| Consent and accounts | Your app's, through a behaviour | Generated Phoenix controllers and templates |
| Dependencies | Plug, Ecto, NimbleOptions; JOSE and HTTP from OTP | `jose`, `joken`, Finch, Nebulex, Phoenix, and more |

## Development

```sh
docker run -d -p 5432:5432 -e POSTGRES_PASSWORD=postgres postgres:17  # or a local PostgreSQL
mix deps.get
mix test      # creates and migrates gatekeep_test
mix ci        # format, warnings, credo, tests
mix dialyzer
```

The [security guide](guides/security.md) lists what Gatekeep defends against
and what the tests cover.

## License

Apache 2.0; see [LICENSE](https://github.com/figitaki/gatekeep/blob/main/LICENSE).
