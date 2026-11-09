# Security model

This library is responsible for the WebAuthn ceremony and credential integrity. It is **not**
responsible for your session, rate limiting, or transport security — those are listed under
[your responsibility](#your-responsibility).

## What the library protects

| Concern | How |
| --- | --- |
| Challenge integrity | CSPRNG (`secrets.token_bytes`), bound to user + ceremony type. |
| Replay | Single-use challenges: `ChallengeStore.consume` fetches and invalidates atomically. |
| Challenge expiry | TTL enforced server-side (`challenge_ttl`), independent of the client timeout. |
| RP ID validation | The authenticator data RP-ID hash is checked against `rp_id`. |
| Origin validation | Exact match against `expected_origins` (+ `related_origins`), normalized at startup to the browser's serialization; origins not on `rp_id` are rejected at startup. |
| Registration hijack | `register/finish` is bound to the user who called `register/begin`: a handle issued to someone else is rejected. |
| Credential ownership | The assertion's `userHandle` must identify the credential's owner (WebAuthn §7.2 step 6); a user-bound ceremony rejects anyone else's credential. |
| Credential overwrite | Repositories must refuse — not overwrite — a duplicate credential id (enforced by the contract suite). |
| Cloned authenticators | `sign_count` is stored and required to advance; a regression is audited and handled by `sign_count_policy`. |
| Backup eligibility | The BE flag is fixed per credential; an assertion that flips it is rejected (`enforce_backup_eligibility`). BS is tracked on every login. |
| User verification | Enforced when `user_verification="required"`; the actual UV flag is reported in `AuthenticationResult.detail`. |
| Credential management | Rename/delete are owner-scoped and return **404** both for unknown ids and for other users' ids (no existence oracle). |
| Input bounds | `state`, `userId`, and device names are length-bounded; device names reject control characters. |
| Resource exhaustion | The in-memory challenge store evicts expired entries and caps live ones (`max_entries`). |
| Information leakage | Verification failures use generic errors; audit events carry no secrets or keys. |
| Broken audit sinks | A sink that raises is logged and ignored; it never turns a completed ceremony into an error. |

## Clone detection policy

When the signature counter fails to advance, the configured `sign_count_policy` applies:

- `strict-reject` (default) — reject the attempt; the credential remains for investigation.
- `flag-disable` — reject **and delete** the credential so it cannot be retried
  (also emits `CREDENTIAL_REVOKED`).
- `audit-only` — accept, but emit `CLONE_SUSPECTED`. For apps where a false positive (a locked-out
  user) costs more than the residual risk.

All emit a `CLONE_SUSPECTED` audit event.

!!! note "Counters and synced passkeys"
    iCloud Keychain, Google Password Manager and most other synced passkey providers always
    report a counter of **0**. For those credentials the counter can neither detect clones nor
    stop replays — single-use challenges are what protect you.

## Challenge store tradeoffs

| Store | Single-use | Infra | Notes |
| --- | --- | --- | --- |
| `InMemoryChallengeStore` | ✅ | none | **Single process only** — with several workers, `begin` and `finish` can land on different processes. |
| `RedisChallengeStore` | ✅ (atomic `GETDEL`) | Redis | Recommended for multi-instance deployments. |
| `StatelessChallengeStore` | ⚠️ per process | none | Signed token. Remembers consumed tokens *in-process* until they expire (failing closed when `max_consumed` live records are held), so a replay against the **same** process fails — but a captured `{state, credential}` pair can be replayed against **another** instance until the token expires. |

!!! warning "Stateless store across several instances"
    Before 0.2 the stateless store relied on the signature counter to stop replays. That does
    not work for synced passkeys (counter always 0): a captured request body could be replayed
    to log in again within `challenge_ttl`. 0.2 adds the per-process guard above. If you run
    more than one instance, use `RedisChallengeStore`, or keep `challenge_ttl` short and make
    sure request bodies never reach logs or traces.

`Passkeys` picks the stateless store automatically when `signing_secret` is set and no
`challenge_store` is passed.

## Your responsibility

- **`get_user` must return the *authenticated* user.** It decides whose account a new passkey
  is attached to and whose passkeys are listed, renamed, or deleted. Resolve it from your
  session or a verified sign-up token — **never** from an identifier the client sends (an
  email or user id in the body or query string), or anyone can add their passkey to anyone's
  account. Raise `HTTPException(401)` when there is no authenticated user.
- **Use an opaque `PasskeyUser.id`.** It becomes the WebAuthn user handle, which the
  authenticator stores and may sync. Use a UUID or random id, not an email address
  (it must be 1–64 bytes).
- **Re-authenticate before sensitive changes.** Consider requiring a recent sign-in ("sudo
  mode") before adding or deleting passkeys, so a stolen session cannot swap in an attacker's
  key. Add it as a dependency: `app.include_router(passkeys.router, dependencies=[...])`.
- **Sessions/tokens:** you mint them in `on_authenticated`. Set `Secure`, `HttpOnly`,
  `SameSite` cookies. If you use cookie sessions, the management endpoints are
  state-changing — keep CSRF protection in place (the JSON content type alone forces a CORS
  preflight, but do not rely on CORS misconfiguration never happening).
- **Rate limiting:** the `begin` endpoints are unauthenticated. Put a limiter (reverse proxy,
  or e.g. `slowapi`) in front of `*/begin` and `*/finish`, per IP and per account.
- **Username enumeration:** `authenticate/begin` with a `userId` returns that user's
  credential ids (`allowCredentials`), and an empty list reveals that a user has no passkeys.
  Prefer usernameless sign-in (no `userId`, discoverable credentials), or put that endpoint
  behind your own lookup that does not reveal whether an account exists.
  Likewise, whether a given *credential id* is registered can be told apart from the error
  code (`credential_not_found` vs `assertion_verification_failed`). Credential ids are not
  secrets, so this is by design: it lets the browser's Signal API prune deleted passkeys.
- **Multi-tenant `rp_id`:** never derive `rp_id` or origins from the `Host` header unchecked —
  map the host through an allow-list of tenants.
- **Render names safely:** device names are user input. Escape them (`textContent`, template
  auto-escaping) wherever you display them.
- **HTTPS:** WebAuthn requires a secure context. `http://localhost` is the only exception.
- **Attestation:** `attestation="direct"` asks for an attestation statement, and its signature
  is verified, but no trust roots or metadata (FIDO MDS) are checked. Do not treat it as proof
  of the authenticator model.
- **Changing `rp_id` orphans every credential.** Credentials are bound to the RP ID forever.

## Reporting vulnerabilities

See [SECURITY.md](https://github.com/javlondevv/fastapi-passkeys/blob/main/SECURITY.md).
