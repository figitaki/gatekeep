# Enterprise-managed authorization

The MCP extension `io.modelcontextprotocol/enterprise-managed-authorization`
(stable, protocol revision 2026-07-28) lets a company's identity provider
(IdP) decide which employees may use which MCP servers from which MCP
clients. A user signed in to the client through SSO gets access to your
server with no consent screen.

Sources:

- [MCP extension specification](https://github.com/modelcontextprotocol/ext-auth/blob/main/specification/stable/enterprise-managed-authorization/2026-07-28/enterprise-managed-authorization.mdx)
- [Identity Assertion JWT Authorization Grant](https://datatracker.ietf.org/doc/draft-ietf-oauth-identity-assertion-authz-grant/) (ID-JAG), an IETF draft
- [Claude's guide for servers](https://claude.com/docs/connectors/building/enterprise-managed-auth), which adds Claude-issued assertions

## The flow, and Gatekeep's part

1. The user signs in to the MCP client with OpenID Connect or SAML. *(Client and IdP.)*
2. The client exchanges the identity token at the IdP for an ID-JAG, an RFC
   8693 token exchange with `audience` set to your issuer and optionally
   `resource` set to your MCP server. The IdP applies its policy. *(Client and IdP.)*
3. The client presents the ID-JAG at your token endpoint with
   `grant_type=urn:ietf:params:oauth:grant-type:jwt-bearer`. **Gatekeep
   validates it and issues an access token** audience-restricted to the
   resource. *(Gatekeep.)*
4. The client calls your MCP server with the token. *(Gatekeep.Plug.Resource.)*

Gatekeep is not the IdP: it never performs the token exchange of step 2.

## Turning it on

```elixir
config :my_app, MyApp.Auth,
  enterprise: [module: MyApp.EnterpriseTrust]
```

```elixir
defmodule MyApp.EnterpriseTrust do
  @behaviour Gatekeep.Enterprise

  # Which IdP each tenant trusts, set by the tenant's admin.
  @impl true
  def trusted_issuer(iss, _unverified_claims, _client) do
    case MyApp.Tenants.get_by_trusted_issuer(iss) do
      %{id: tenant_id} -> {:ok, %{tenant_id: tenant_id}}
      nil -> :error
    end
  end

  # A verified identity to a local user of that tenant.
  @impl true
  def resolve_subject(%{"iss" => iss, "sub" => sub}, %{tenant_id: tenant_id}) do
    case MyApp.Accounts.get_by_sso(tenant_id, iss, sub) do
      nil -> {:error, :access_denied}
      user -> {:ok, subject: "user:#{user.id}", owner: "user:#{user.id}"}
    end
  end
end
```

The metadata then lists `urn:ietf:params:oauth:grant-type:jwt-bearer` in
`grant_types_supported` and `urn:ietf:params:oauth:grant-profile:id-jag` in
`authorization_grant_profiles_supported`, which is how clients discover
support.

`trusted_issuer/3` may return `jwks: [jwk, ...]` to pin an issuer's keys;
otherwise Gatekeep reads `<iss>/.well-known/openid-configuration`, requires its
`issuer` to equal `iss`, and fetches `jwks_uri` with the same SSRF limits and
cache as client metadata.

## Validation

`Gatekeep.Enterprise` lists the checks and their order. In short: trusted
issuer (exact string, before fetching keys); ES256 or RS256 signature by the
issuer's keys, never keys named in the token; `typ` `oauth-id-jag+jwt`; `aud`
exactly this issuer (a string or a one-element list); `client_id` equal to
the authenticated client; `sub` present; `exp`, `iat`, `nbf` with clock skew
and a maximum lifetime; `jti` accepted once per issuer; the `resource` claim
naming a resource Gatekeep serves; scopes no wider than the claim; and, with
a `cnf` claim, a DPoP proof from that key.

Every failure is `invalid_grant`; an unknown user is `access_denied`, as the
draft profiles. No refresh token is issued: the client gets a new ID-JAG from
the IdP, which keeps the IdP's policy in force.

## Clients

The client must be known to Gatekeep: pre-registered under `:clients` with
`"urn:ietf:params:oauth:grant-type:jwt-bearer"` in `grant_types`, or a client
ID metadata document. Dynamic client registration doesn't work here, since
the IdP stamps a fixed `client_id` into every assertion.

A metadata document without `grant_types` may use the grant. One that lists
`grant_types` must include it. The IdP vouches for the client, and the
assertion's `client_id` must match the client that authenticates.

## Open questions in the specifications

These are decisions the specifications leave to the server. Gatekeep's
current choice is in bold; please weigh in before 1.0.

1. **The `resource` claim is optional.** The MCP profile requires the access
   token be audience-restricted to "the MCP Server identified by the
   resource claim", but the claim may be absent. **Gatekeep falls back to the
   `resource` parameter or `:default_resource`**, or refuses with
   `require_resource_claim: true`.
2. **Assertion lifetime and clock skew** have no normative limits. **600
   seconds maximum lifetime, 30 seconds of skew** (Claude's guide allows up to
   60).
3. **Which client may present an assertion.** The draft lets proof of
   possession of a `cnf` key replace client authentication. **Gatekeep always
   requires the authenticated client (or the named public client) to match
   the `client_id` claim**, which is stricter.
4. **`jwt-dpop` grant type.** Draft -06 names
   `urn:ietf:params:oauth:grant-type:jwt-dpop` for DPoP-bound ID-JAGs; the MCP
   extension and Claude use `jwt-bearer`. **Gatekeep accepts `jwt-bearer` with
   a DPoP proof** and doesn't yet accept `jwt-dpop`.
5. **Multi-tenant issuers** (`tenant`, `aud_tenant`, `aud_sub`, `sub_id`).
   Tenant resolution is application policy, so **Gatekeep passes the claims
   to your callbacks** and doesn't interpret them. `trusted_issuer/3`
   receives the unverified claims to choose a tenant; `resolve_subject/2`
   receives the verified ones.
6. **Email matching.** Claude-issued assertions are meant to be matched by
   verified `email`, IdP-issued ones by `iss`+`sub`. That is
   `resolve_subject/2`'s job; the warning in its docs applies.
7. **SAML `sub_id` NameID comparison** is not implemented.
8. **`authorization_details`** (RFC 9396) in an ID-JAG are kept in the claims
   your callback sees but not enforced.
9. **mTLS-bound assertions** (`cnf.x5t#S256`) are refused, as the draft
   requires of servers that don't support them.
