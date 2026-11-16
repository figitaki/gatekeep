# Changelog

All notable changes to this project are documented in this file. The format
follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the
project adheres to [Semantic Versioning](https://semver.org/).

## [Unreleased]

The first release, 0.1.0.

### Added

- OAuth 2.1 authorization code grant with PKCE S256, a `Gatekeep.Consent`
  behaviour for sign-in and consent, and `iss` in authorization responses
  (RFC 9207).
- Token endpoint with refresh token rotation and reuse detection, revocation
  (RFC 7009), and authorization server metadata (RFC 8414).
- Client ID metadata documents, `private_key_jwt`, client secrets for
  pre-registered clients, and dynamic client registration (RFC 7591).
- Protected resource metadata (RFC 9728), resource indicators with
  per-resource audiences (RFC 8707), and `Gatekeep.Plug.Resource`.
- DPoP (RFC 9449): proof verification, bound access and refresh tokens,
  `dpop_jkt` code binding, and `dpop_bound_access_tokens` enforcement.
- `Gatekeep.Storage` with an Ecto/PostgreSQL adapter and migrations,
  `Gatekeep.Signer` with `Gatekeep.Signer.Local` for JWT access tokens, and the
  `Gatekeep.FastestMCP` authenticator.
- `Gatekeep.Grant`, the behaviour of extension grants.
- `:registered_client_prefix`, so registered client IDs from an earlier
  issuer keep working.

[Unreleased]: https://github.com/figitaki/gatekeep/commits/main
