# Security notes

What Gatekeep defends against, how, and which tests show it. Every
failure at the token and resource endpoints returns a generic OAuth error;
the specific reason stays internal.

## Authorization endpoint

| Threat | Defense | Tests |
| --- | --- | --- |
| Open redirect | Redirect URIs match exactly (loopback ports excepted, RFC 8252 §7.3); metadata documents may list only URIs on their own host; errors about the client or redirect URI never redirect; registered clients' errors never redirect | `authorization_test.exs` "open redirects" |
| Code interception | PKCE S256 required; `plain` refused; verifier compared in constant time | `token_endpoint_test.exs` "a wrong PKCE verifier" |
| Mix-up attacks | `iss` in every authorization response, errors included (RFC 9207) | "rejected requests that redirect" |
| Clickjacking | `X-Frame-Options: DENY` on the authorize response | "reaches consent" |
| Scope escalation at consent | `approve/3` refuses scopes the request didn't ask for | "approval can narrow scopes" |

## Token endpoint

| Threat | Defense | Tests |
| --- | --- | --- |
| Code replay | Consumed atomically; a failed attempt consumes it too; reuse by its client revokes the grant | "replaying a code", "two concurrent redemptions" |
| Code theft by another client | Code bound to client, redirect URI, resource, and optional DPoP key | "another client sharing the redirect URI", "a code bound with dpop_jkt" |
| Expired codes | 120-second lifetime | "an expired code" |
| Refresh token theft | Rotation; reuse of any replaced token revokes the grant; another client presenting it changes nothing | "refresh tokens" |
| Audience confusion | Token requests may only repeat the grant's resource | "naming another resource", "can't be moved" |
| Machine client impersonation | Client credentials only for pre-registered clients that list the grant and hold a secret or key; public clients refused | "client credentials" |
| Forged client assertions | Keys only from the client's key set; `aud` the issuer; 5-minute lifetime; `jti` once | "client authentication" |
| Stale keys | Cache expires; unknown `kid` refetches at most every 30 s | "a key removed from jwks_uri" |
| SSRF via metadata URLs | HTTPS only, no redirects, private addresses refused, connection pinned to the checked address, 100 KB limit | `Gatekeep.Fetcher` |
| Fetch floods | Single-flight per client; failures cached 30 s; bounded cache | "share one metadata fetch", "a full cache" |

## Resources

| Threat | Defense | Tests |
| --- | --- | --- |
| Token for another resource | Each token carries one resource; others refuse it | "a token issued for one resource is refused by another" |
| Expired or revoked tokens | Checked on every request against storage | "an expired token", "revocation" |
| Stolen DPoP-bound token | Needs `Authorization: DPoP` and a proof by the bound key over this method, URL, and token (`ath`); bound tokens sent as Bearer are refused | `resource_test.exs` "DPoP" |
| DPoP proof replay | `jti` accepted once per key across servers; `iat` window 60 s + 30 s skew | `jose_dpop_test.exs` |

## Enterprise-managed authorization

See the [enterprise guide](enterprise_managed_authorization.md);
`enterprise_test.exs` covers each rule (type, audience, client, issuer,
signature, header keys, time, replay, resource, scope, and `cnf`).

## Operational notes

- Never log the bodies of token, revocation, or registration requests.
- `blocked_clients` stops a client's tokens immediately.
- `Gatekeep.Clients.forget/2` drops a client's cached keys after a leak.
- The replay cache (`gatekeep_seen_jtis`) prunes itself; no job is needed.
- Public clients (`"none"`) turn on dynamic registration. Leave `"none"` out
  of a resource's `client_auth_methods` to admit only clients with keys.
