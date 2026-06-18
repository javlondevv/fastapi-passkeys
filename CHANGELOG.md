# Changelog

All notable changes to this project are documented here. This project adheres to
[Semantic Versioning](https://semver.org/) and the changelog is generated from
[Conventional Commits](https://www.conventionalcommits.org/).

## [0.1.0] - Unreleased

Initial alpha release.

### Added
- WebAuthn registration and authentication ceremonies for FastAPI.
- `Passkeys` facade with a ready-to-mount router (Layer A) and standalone
  `RegistrationService` / `AuthenticationService` (Layer B).
- Async, ORM-agnostic `CredentialRepository` and `ChallengeStore` Protocols.
- Built-in in-memory and stateless (HMAC-signed) stores; `[sqlalchemy]` async
  credential repository and `[redis]` challenge store.
- Signature-counter clone detection with `strict-reject` / `flag-disable` policies.
- Server-enforced challenge TTL, single-use challenges, strict origin/RP validation.
- Structured audit events via a pluggable `AuditSink`.
- Shipped contract test-suite and a software authenticator in `fastapi_passkeys.testing`.
