# fastapi-passkeys

**Passkeys / WebAuthn authentication for FastAPI — secure by default, storage-agnostic,
async-native.**

`fastapi-passkeys` owns the hard, security-sensitive part of passkeys — the WebAuthn
ceremony, challenge integrity, signature-counter clone detection, and credential lifecycle —
and stays out of the way of *your* idea of a session.

## What it does

- Verifies WebAuthn registration (attestation) and authentication (assertion) responses.
- Generates and validates single-use, TTL-bound challenges.
- Stores credentials through an async repository you choose (or implement).
- Detects cloned authenticators via the signature counter.
- Hands you the verified user and lets you mint whatever session/token you like.

## What it does *not* do

- It is not a session or JWT framework. You decide what "logged in" means.
- It is not a FIDO2/CTAP client or a hardware-key management suite.

## Where to next

- [Quickstart](quickstart.md) — running in under 30 lines.
- [Concepts](concepts.md) — a short, correct WebAuthn primer.
- [Storage backends](storage.md) — SQLAlchemy, Redis, and your own.
- [Security model](security.md) — exactly what is and isn't protected.
