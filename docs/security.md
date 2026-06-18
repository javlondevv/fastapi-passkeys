# Security model

This library is responsible for the WebAuthn ceremony and credential integrity. It is **not**
responsible for your session, rate limiting, or transport security — those are noted below as
your responsibility.

## What the library protects

| Concern | How |
| --- | --- |
| Challenge integrity | CSPRNG (`secrets.token_bytes`), bound to user + ceremony type. |
| Replay | Single-use challenges: `ChallengeStore.consume` fetches and invalidates atomically. |
| Challenge expiry | TTL enforced server-side (`challenge_ttl`), independent of the client timeout. |
| RP ID validation | The authenticator data RP-ID hash is checked against `rp_id`. |
| Origin validation | Strict match against `expected_origins` (multiple origins supported). |
| Cloned authenticators | `sign_count` is stored and required to advance; a regression is rejected and audited. |
| User verification | Enforced when `user_verification="required"`. |
| Cross-user use | A user-bound ceremony rejects credentials owned by anyone else. |
| Information leakage | Verification failures use generic errors; audit events carry no secrets or keys. |

## Clone detection policy

When the signature counter fails to advance, the configured `sign_count_policy` applies:

- `strict-reject` (default) — reject the attempt; the credential remains for investigation.
- `flag-disable` — reject **and** revoke the credential so it cannot be retried.

Both emit a `CLONE_SUSPECTED` audit event.

## Challenge store tradeoffs

| Store | Single-use | Infra | Notes |
| --- | --- | --- | --- |
| `InMemoryChallengeStore` | ✅ | none | Single process only. |
| `RedisChallengeStore` | ✅ (atomic `GETDEL`) | Redis | Recommended for multi-instance. |
| `StatelessChallengeStore` | ❌ (replayable within TTL) | none | Signed token; relies on the layers below to close the replay window. Keep `challenge_ttl` short. |

The stateless store cannot mark a token "used" without state. A captured token is replayable
until it expires — but a replayed *assertion* still fails the `sign_count` check, and a
replayed *attestation* still fails the duplicate-credential check. If you need strict
single-use at the challenge layer, use Redis or the in-memory store.

## Your responsibility

- **Sessions/tokens:** you mint them in `on_authenticated`. Set `Secure`, `HttpOnly`,
  `SameSite` cookies; compose with a session/device library.
- **Rate limiting:** put a limiter (reverse proxy or Starlette middleware) in front of the
  `begin` endpoints to bound abuse and enumeration attempts.
- **HTTPS:** WebAuthn requires a secure context. Terminate TLS and set `expected_origins`
  to `https://` origins in production.

## Reporting vulnerabilities

See [SECURITY.md](https://github.com/javlondevv/fastapi-passkeys/blob/main/SECURITY.md).
