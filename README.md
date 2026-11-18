# Gatekeep

[![CI](https://github.com/figitaki/gatekeep/actions/workflows/ci.yml/badge.svg)](https://github.com/figitaki/gatekeep/actions/workflows/ci.yml)
[![Hex.pm](https://img.shields.io/hexpm/v/gatekeep.svg)](https://hex.pm/packages/gatekeep)
[![Hex Docs](https://img.shields.io/badge/hex-docs-lightgreen.svg)](https://hexdocs.pm/gatekeep)
[![License](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](https://github.com/figitaki/gatekeep/blob/main/LICENSE)

**An OAuth 2.1 authorization server for MCP servers in Elixir.**

[FastestMCP](https://hex.pm/packages/fastest_mcp) checks tokens and leaves
the authorization server to you; Gatekeep is that server. It covers what MCP
clients such as Claude, ChatGPT, Claude Code, and the MCP Inspector use:
PKCE, client ID metadata documents, dynamic client registration, resource
indicators, DPoP, and client credentials.

[Getting started](https://hexdocs.pm/gatekeep/getting_started.html) ·
[FastestMCP](https://hexdocs.pm/gatekeep/fastest_mcp.html) ·
[Security](https://hexdocs.pm/gatekeep/security.html)

> #### Status: pre-release, APIs may change {: .warning}
>
> Gatekeep is at `0.1.0-alpha.1`; its APIs may change before 0.1.0. It is
> not on Hex yet. Until it is, depend on
> `{:gatekeep, github: "figitaki/gatekeep"}`.

## Installation

Add `gatekeep` to your dependencies in `mix.exs`:

```elixir
def deps do
  [
    {:gatekeep, "~> 0.1.0-alpha.1"}
  ]
end
```

A requirement without a pre-release, such as `"~> 0.1"`, skips alphas; this
one opts in, and also matches later 0.1 alphas and 0.1.x releases.

Gatekeep requires Elixir 1.19 or later and Erlang/OTP 27 or later, and CI
tests Elixir 1.19 with OTP 27 and Elixir 1.20 with OTP 28. The bundled
storage adapter needs PostgreSQL through Ecto; the FastestMCP integration
needs `{:fastest_mcp, "~> 1.0"}`.

## Quick start

Define an issuer and describe the MCP server it protects:

```elixir
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
    [id: "https://example.com/mcp", scopes: [{"notes:read", "Read your notes"}]]
  ]
```

Start `MyApp.Auth` after your repo, create the tables with
`Gatekeep.Storage.Ecto.Migration`, and mount the plugs:

```elixir
# endpoint.ex, before Plug.Parsers: token, revocation, registration, metadata
plug Gatekeep.Plug.Endpoints, gatekeep: MyApp.Auth

# router.ex
scope "/oauth" do
  pipe_through :browser
  get "/authorize", Gatekeep.Plug.Authorize, gatekeep: MyApp.Auth
end

pipeline :mcp do
  plug Gatekeep.Plug.Resource, gatekeep: MyApp.Auth, resource: "https://example.com/mcp"
end

scope "/" do
  pipe_through :mcp
  forward "/mcp", MyApp.MCPServer, auth_assigns: [:gatekeep_token]
end
```

`MyAppWeb.Consent` implements `Gatekeep.Consent`: it signs the user in and
shows the consent page, whose decision calls
`Gatekeep.Authorization.approve/3`. In the FastestMCP server, add
`FastestMCP.add_auth(Gatekeep.FastestMCP, gatekeep: MyApp.Auth, resource: "https://example.com/mcp")`
so tools see the caller.

A request without a token now gets a `401` whose `WWW-Authenticate` header
points MCP clients to the resource's metadata, the issuer, and sign-in. The
[getting started guide](https://hexdocs.pm/gatekeep/getting_started.html)
walks through each step, including the consent controller.

## Features

- OAuth 2.1 authorization code with PKCE S256, a pluggable consent UI, and
  `iss` in authorization responses (RFC 9207).
- Refresh token rotation with reuse detection, revocation (RFC 7009), and
  authorization server metadata (RFC 8414).
- Client ID metadata documents, `private_key_jwt`, dynamic client
  registration (RFC 7591), and pre-registered clients.
- Protected resource metadata (RFC 9728), resource indicators with
  per-resource audiences (RFC 8707), and `WWW-Authenticate` challenges with
  `scope` and `insufficient_scope`.
- DPoP (RFC 9449): proof checks, bound access and refresh tokens, `dpop_jkt`,
  and enforcement for clients that declare `dpop_bound_access_tokens`.
- The client credentials grant for machine clients.
- The device authorization grant (RFC 8628) for command-line tools and
  other clients that can't take a redirect.
- Behaviours for storage (Ecto adapter included), consent, signing, and
  extension grants, and an authenticator for FastestMCP.

Codes, refresh tokens, and access tokens are stored only as SHA-256 hashes;
access tokens can also be RFC 9068 JWTs from your signer.

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
| Consent and accounts | Your app's, through a behaviour | Generated Phoenix controllers and templates |
| Dependencies | Plug, Ecto, NimbleOptions; JOSE and HTTP from OTP | `jose`, `joken`, Finch, Nebulex, Phoenix, and more |

## Development

```sh
mix deps.get
mix test      # needs PostgreSQL; creates and migrates gatekeep_test
mix ci        # format, warnings, credo, tests
mix dialyzer
```

## License

Gatekeep is released under the Apache License 2.0. See
[LICENSE](https://github.com/figitaki/gatekeep/blob/main/LICENSE).
