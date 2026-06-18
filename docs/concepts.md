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
