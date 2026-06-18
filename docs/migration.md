# Migrating from django-passkeys

`fastapi-passkeys` is a redesign, not a port, so this is a concept map rather than a
drop-in replacement. The data model is intentionally richer.

## Concept mapping

| django-passkeys | fastapi-passkeys |
| --- | --- |
| `PasskeyModelBackend` (auth backend) | No backend — `on_authenticated` hook returns the verified user; you issue the session. |
| `UserPasskey` model | `Credential` domain entity + your chosen `CredentialRepository`. |
| `token` (consolidated credential) | Explicit `public_key`, `transports`, `aaguid`, `backup_eligible`, `backup_state`. |
| *(no signature counter)* | `sign_count` stored **and enforced** for clone detection. |
| `request.session['fido2_state']` | Pluggable `ChallengeStore` (stateless, in-memory, or Redis) — no server session required. |
| `FIDO_SERVER_ID` / `FIDO_SERVER_NAME` | `PasskeyConfig(rp_id=..., rp_name=...)`. |
| `KEY_ATTACHMENT` | `PasskeyConfig(authenticator_attachment=...)`. |
| DRF views | `Passkeys.router` (FastAPI) or the services directly. |

## Key behavioural differences

- **Signature counter.** django-passkeys stores no counter and cannot detect cloned
  authenticators. Here it is enforced by default (`sign_count_policy="strict-reject"`). If you
  import legacy credentials with no counter, start them at `0`.
- **Challenges are not in the session.** The client carries an opaque `state` handle between
  `begin` and `finish`, so the flow works for stateless SPAs and mobile clients.
- **Auth is decoupled.** The library verifies the passkey and stops there; minting a session
  or JWT is your code in `on_authenticated`.

## Importing existing credentials

Map each `UserPasskey` row into a `Credential`: decode the stored credential id to bytes, set
`public_key` from your stored COSE key, and set `sign_count=0`. Persist via your repository's
`add`.
