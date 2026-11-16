# Protecting a FastestMCP server

[FastestMCP](https://hexdocs.pm/fastest_mcp) is a resource server: it checks
credentials with an authenticator you give it, and leaves issuing tokens to
an authorization server. Gatekeep is that server, and `Gatekeep.FastestMCP`
is the authenticator.

## Over HTTP

Run `Gatekeep.Plug.Resource` in front of the server. It does what FastestMCP
can't from the authenticator input alone:

- checks DPoP proofs, which need the request's method and URL;
- refuses tokens of other resources, expired, revoked, or blocked tokens;
- answers with challenges naming the protected resource metadata, the
  needed `scope`, and `insufficient_scope`, for both Bearer and DPoP.

On success it assigns the `Gatekeep.Token`, which `auth_assigns:` passes to
FastestMCP:

```elixir
pipeline :mcp do
  plug Gatekeep.Plug.Resource,
    gatekeep: MyApp.Auth,
    resource: "https://example.com/mcp",
    scopes: ["notes:read"]
end

scope "/" do
  pipe_through :mcp
  forward "/mcp", MyApp.MCPServer, auth_assigns: [:gatekeep_token]
end
```

Unlike the plugs FastestMCP's guide shows, this one halts on failure. Its
challenge already carries `resource_metadata`, which is how MCP clients find
the authorization server.

## The authenticator

```elixir
def server(opts) do
  base_server(opts)
  |> FastestMCP.add_auth(Gatekeep.FastestMCP,
    gatekeep: MyApp.Auth,
    resource: "https://example.com/mcp",
    scopes: ["notes:read"]
  )
end
```

Handlers see:

- `ctx.principal`: `%{"sub" => subject, "client_id" => client_id}`, where the
  subject is what your consent controller passed to
  `Gatekeep.Authorization.approve/3`;
- `ctx.auth.token`: the `Gatekeep.Token`, with `scopes`, `owner`, `claims`,
  and `grant_id`;
- `ctx.capabilities`: the token's scopes, for
  `FastestMCP.Authorization.require_capabilities/1` on single tools.

Without the assign, as in tests and in-process calls, the authenticator
checks a Bearer token from `auth_input: %{"authorization" => "Bearer ..."}`
itself. DPoP-bound tokens need the plug.

## FastestMCP's protected resource option

Gatekeep serves the resource's metadata itself, from `Gatekeep.Plug.Endpoints`.
If you also set FastestMCP's `protected_resource:` option, for example to
use its challenges for in-process clients, build it from Gatekeep's config so
the two agree:

```elixir
FastestMCP.server("notes",
  protected_resource: Gatekeep.FastestMCP.protected_resource(MyApp.Auth, "https://example.com/mcp")
)
```

Don't route FastestMCP's own well-known route and Gatekeep's to the same
path; one is enough.

## Testing

```elixir
%{"access_token" => token} = sign_in_somehow()

FastestMCP.call_tool!(MyApp.MCPServer, "whoami", %{},
  auth_input: %{"authorization" => "Bearer " <> token}
)
```

Gatekeep's own tests (`test/gatekeep/fastest_mcp_test.exs`) start a
FastestMCP server this way.
