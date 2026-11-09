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
| `enabled` flag / toggle | No soft-disable yet: delete the credential, or use `sign_count_policy="flag-disable"`. |
| user-agent platform detection | `aaguid` (authenticator model) and `authenticatorAttachment` in the result `detail`. |
| `FIDO_SERVER_ID` callable (multi-tenant) | Build a `PasskeyConfig` per tenant from an allow-list; never from the raw `Host` header. |
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
`add`. Keep the **same `rp_id`** — credentials are bound to it and cannot be moved.

Two things differ from what django-passkeys stored, and both matter for imported keys:

- **User handle.** django-passkeys put `base64url(username)` in the WebAuthn user handle;
  this library uses `PasskeyUser.id` and verifies that the assertion's `userHandle` matches the
  credential owner. Authenticators keep the handle they were given at registration, so
  imported passkeys will present the old one. Set `verify_user_handle=False` while you still
  have imported credentials. Ownership is still enforced by credential-id lookup and the
  signature; you only lose the extra `userHandle` cross-check.
- **Backup eligibility.** django-passkeys did not record the BE flag. If you import with
  `backup_eligible=False`, synced passkeys (which report BE=1) would be rejected. Either set
  `enforce_backup_eligibility=False` for the transition, or set `backup_eligible=True` for
  keys you know are synced.

Ask users to register a fresh passkey after migrating; you can turn both settings back on once
the imported credentials have been replaced.

## Issues fixed by design

The [0.2.0 audit](audit.md) maps every django-passkeys issue to its status here.
