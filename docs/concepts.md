# Concepts

A short primer on the WebAuthn vocabulary you'll meet in this library.

## Relying Party (RP)

Your application. Identified by an **RP ID** (a registrable domain like `example.com`) and a
human-readable **RP name**. Credentials are scoped to the RP ID, and the browser refuses to
use a credential on a different origin — this is what makes passkeys phishing-resistant.

## Ceremonies

Two of them, each a `begin` → `finish` pair:

- **Registration (attestation):** the authenticator creates a new key pair and returns the
  public key. You store it.
- **Authentication (assertion):** the authenticator signs a fresh challenge with the private
  key. You verify the signature against the stored public key.

## Challenge

A random value the server issues at `begin` and must see signed back at `finish`. It prevents
replay. In this library it is single-use (in the in-memory and Redis stores) and expires after
`challenge_ttl`. The client carries it between calls as an opaque `state` handle.

## Signature counter (`sign_count`)

Many authenticators maintain a counter that increments on every assertion. If a presented
counter does not exceed the stored one, the credential may have been cloned. This library
**stores and enforces** the counter — see the [security model](security.md).

## User verification (UV)

Whether the authenticator proved the user's presence *and* identity (PIN/biometric) versus
mere presence (a tap). Controlled by `user_verification` in the config.

## Discoverable credentials (resident keys)

Credentials the authenticator can find without being told which user — this enables
**usernameless** login (call `authenticate/begin` with no `userId`). Controlled by
`resident_key`.

## Backup flags (BE / BS)

Every response carries two bits. **Backup eligible (BE)** says the credential *can* be synced
(a multi-device passkey); it is fixed for the credential's lifetime, so this library rejects an
assertion that flips it. **Backup state (BS)** says it *is* currently backed up; it may change,
and the library records the latest value on each sign-in. Use them for policy — e.g. nudge
users whose only passkey is single-device (`backupEligible: false`) to add a second one.

## User handle

`PasskeyUser.id`, UTF-8 encoded, is the WebAuthn **user handle**. The authenticator stores it
with the credential and returns it on every discoverable sign-in. The library checks that it
identifies the credential's owner. Keep it opaque (a UUID) and stable: it must not contain
personal data, and it cannot be changed on credentials that already exist.

## Hints, autofill, signals and related origins (WebAuthn Level 3)

- **Hints** (`PasskeyConfig.hints`) nudge the browser toward a security key, the local device,
  or a phone.
- **Conditional mediation (autofill)** shows passkeys in the username field's autofill menu.
  It is a usernameless `authenticate/begin` plus `mediation: "conditional"` on the client.
- **Signal API** keeps passkey providers in sync with your server: tell them a credential was
  deleted, which credentials are still valid, or that the user's name changed.
- **Related origins** let one `rp_id` serve several domains (e.g. `example.com` and
  `example.co.uk`) via `/.well-known/webauthn`.
