# CHANGELOG

<!-- version list -->


### Release notes

A security-hardening release. Every item below has a regression test, and the full
mapping of defects and django-passkeys issues is in
[docs/audit.md](https://javlondevv.github.io/fastapi-passkeys/audit/).

#### Security

- **Registration is bound to the signed-in user.** `register/finish` now calls `get_user`
  and rejects a `state` handle issued to a different user (`registration_user_mismatch`).
  Before this, anyone holding a valid handle could attach their own authenticator to the
  account it was issued for. `RegistrationService.finish()` gains a `user=` argument.
- **`userHandle` is verified** (WebAuthn §7.2 step 6). In usernameless flows it must be
  present and identify the credential's owner; in user-bound flows it must match whenever
  it is present. `verify_user_handle=False` opts out for imported credentials.
- **Stateless challenge store replay.** A captured request body could be replayed to sign
  in again within `challenge_ttl`, because synced passkeys report a signature counter of 0.
  Consumed tokens are now remembered per process. **Use `RedisChallengeStore` when you run
  more than one instance.**
- **Docs: `get_user` must return the authenticated user.** The quickstart previously
  suggested resolving it from "an email from the request body", which would let anyone
  register a passkey on any account.
- `InMemoryChallengeStore` evicts expired challenges and caps live ones (`max_entries`).
  Unauthenticated `begin` calls could previously exhaust memory.
- Credential rename/delete return **404** for unknown ids and for other users' ids, and no
  longer emit a `CREDENTIAL_REVOKED` event for a delete that did not happen.
- Repositories must refuse — not overwrite — a duplicate credential id. The in-memory and
  SQLAlchemy adapters now raise `CredentialAlreadyExists`, and the contract suite checks it.
- An assertion whose backup-eligible (BE) flag differs from registration is rejected
  (`enforce_backup_eligibility`).
- Request bodies are bounded: device names (≤ 64 characters, trimmed, no control or format
  characters), `state`, and `userId`.
- Base64url decoding is strict: non-canonical credential ids are rejected.
- A failing audit sink is logged and ignored, so it can no longer turn a completed
  ceremony into an error.

#### Bug fixes

- Origins are normalized to the browser's form: a trailing slash, uppercase host, or
  default port previously made every ceremony fail. Origins outside `rp_id`, an `rp_id` with
  a scheme or port, and a non-positive `challenge_ttl` now fail at startup.
- `user_verified` in `AuthenticationResult.detail` now reflects the authenticator's UV
  flag. On py_webauthn 2.0–2.4 it previously reported the configured policy.
- `Credential.is_discoverable` now comes from the `credProps` extension (requested
  automatically), with the `resident_key` policy as the fallback.
- `PasskeyUser.id` is validated to 1–64 bytes. An empty `display_name` falls back to
  `name`, because some password managers reject empty names.
- SQLAlchemy: rows with unknown transports load instead of failing, and `credential_id` is
  `VARBINARY(1023)` on MySQL/MariaDB (an unbounded `BLOB` primary key could not be created).
- `flag-disable` now also emits `CREDENTIAL_REVOKED`.

#### Features

- `hints` (WebAuthn L3) for both ceremonies.
- Signal API support: `GET /credentials/signals`, and `error.signal.unknownCredential` on
  `credential_not_found`.
- Related Origin Requests: `related_origins` plus `passkeys.well_known_router`.
- Android app origins (`android:apk-key-hash:…`).
- `max_credentials_per_user`.
- `sign_count_policy="audit-only"`.
- Backup state is persisted on every sign-in. `update_usage` gains an optional
  `backup_state` argument, and 0.1 repositories without it keep working.
- `AuthenticationResult.detail` adds `backup_eligible`, `backup_state` and
  `authenticator_attachment`. `CredentialView` adds `aaguid` and `discoverable`.
- `Transport.SMART_CARD`, a `CREDENTIAL_RENAMED` audit event, and
  `SoftwareAuthenticator(resident_key=..., attachment=...)`.
- The example app has autofill (conditional UI), Signal API calls, and safe rendering.

#### Upgrade notes

- **Behaviour change:** `register/finish` now calls your `get_user` hook. It must resolve
  the same user it did for `register/begin`.
- **Behaviour change:** configs whose origins do not belong to `rp_id` now fail at startup.
  Browsers reject such pairings anyway.
- Custom `CredentialRepository.add` implementations should raise `CredentialAlreadyExists`
  on duplicates; `check_credential_repository` now asserts this.
- If you imported credentials from django-passkeys, read the migration guide
  (`verify_user_handle`, `enforce_backup_eligibility`).
- Dependencies: `webauthn>=2.0,<4`. Tested with 2.0.0 through 3.0.1, Python 3.10–3.14.

#### CI / release

- CI adds Python 3.14, a minimum-dependency job, and a build plus `twine check` job.
  Publishing to PyPI now requires the full CI matrix to pass.


## v0.1.2 (2026-06-18)

### Bug Fixes

- Derive __version__ from package metadata to prevent version drift
  ([`14ed2c4`](https://github.com/javlondevv/fastapi-passkeys/commit/14ed2c4a4734b1d713dfa54441bd13da65789946))

### Documentation

- Add auto-generated API reference page
  ([`a5e197a`](https://github.com/javlondevv/fastapi-passkeys/commit/a5e197ad3481521bb931dfd9249aacff3bccaf55))

- Add banner, revamp README, and add gh-pages docs deploy
  ([`f7e3515`](https://github.com/javlondevv/fastapi-passkeys/commit/f7e3515cbdcecff67fdc891cb24532d7c538f005))

Match the README/badge/topics style of the author's other libraries and add a mkdocs Material docs
  site published to GitHub Pages via mkdocs gh-deploy.

- Drop downloads badge and clean changelog
  ([`26dc002`](https://github.com/javlondevv/fastapi-passkeys/commit/26dc0021e72ed8697dc4da21c3562d9f800c2cbe))


## v0.1.1 (2026-06-18)

### Bug Fixes

- **release**: Add manual workflow_dispatch trigger to release pipeline
  ([`e3906cc`](https://github.com/javlondevv/fastapi-passkeys/commit/e3906cc99d847e594691036ba88d56e5f29f3f1c))

Allows manually re-triggering a release and ensures the first successful PyPI publish via Trusted
  Publishing (OIDC).


## v0.1.0 (2026-06-18)

### Features

- Initial fastapi-passkeys library (v0.1.0)
  ([`aa0a59c`](https://github.com/javlondevv/fastapi-passkeys/commit/aa0a59c429dad4515dd16d7aaaa1947a28c3d91e))

WebAuthn/passkeys authentication for FastAPI: async-native, storage-agnostic, secure by default.
  Includes registration/authentication ceremonies, signature counter clone detection, single-use TTL
  challenges, strict origin/RP validation, pluggable repositories (in-memory, stateless, SQLAlchemy,
  Redis), a contract test-suite, a software authenticator for tests, docs, and a runnable example.
