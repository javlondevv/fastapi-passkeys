# 0.2.0 audit report

The audit for the 0.2.0 release had three parts:

1. Every issue and bug-related pull request in
   [mkalioby/django-passkeys](https://github.com/mkalioby/django-passkeys/issues) was mapped to
   the matching concern in fastapi-passkeys.
2. Every line of this code base was reviewed, and its behaviour was checked against the WebAuthn
   Level 3 specification and py_webauthn 2.0–3.0.
3. Comparable libraries were surveyed: py_webauthn, python-fido2, go-webauthn, SimpleWebAuthn,
   webauthn4j, java-webauthn-server, fido2-net-lib, webauthn-rs and Laragear/WebAuthn.

A finding was only marked **Fixed** after a regression test reproduced the failure against
0.1.2 and then passed. Those tests are in `tests/test_regressions.py`,
`tests/test_api_regressions.py`, `tests/test_features.py` and `tests/test_edge_cases.py`.

**Status legend:**

- **Fixed:** the defect was in 0.1.2 and is fixed in 0.2.0.
- **N/A:** the architecture rules it out.
- **Already handled:** 0.1.2 was already correct.
- **Docs:** the concern is the integrator's to handle, and is now documented.
- **Deferred:** accepted for now and put on the roadmap.

## A. Defects found in fastapi-passkeys 0.1.2

| ID | Severity | Finding | Root cause | Resolution |
| --- | --- | --- | --- | --- |
| F1 | High | `userHandle` was never checked. A usernameless assertion was accepted with any user handle, or none. | The service looked credentials up by id only. WebAuthn §7.2 step 6 also requires the user handle to identify the credential's owner. | **Fixed.** The handle is required in usernameless flows and must match whenever it is present. `verify_user_handle` is an opt-out for imported credentials. |
| F2 | High | Registration hijack: `register/finish` did not check who was calling. Anyone holding another user's `state` handle could attach their own authenticator to that account. | The handle was the only binding. The stateless store makes this worse, because a handle stays valid for the whole TTL even after use (F3). | **Fixed.** `RegistrationService.finish(user=...)` rejects a handle issued to a different user. The router always passes the authenticated user. |
| F3 | High | With the stateless store, a captured `{state, credential}` pair could be replayed to sign in again within `challenge_ttl` (5 min). | The docs claimed the signature counter would stop a replay. Synced passkeys always report a counter of 0, so the counter check passes. | **Fixed.** The store now keeps a per-process record of consumed tokens. It never evicts a record that has not expired: when full, it rejects new tokens (fail closed). The docs now state plainly that this does not cover several instances; use Redis there. |
| F4 | Medium | `InMemoryChallengeStore` grew without bound. Each unauthenticated `begin` call added a challenge that was never removed, which is a memory DoS. | Entries were only removed when a challenge was consumed. | **Fixed.** Expired entries are evicted on `put`, and live entries are capped by `max_entries`. |
| F5 | Medium | A configured origin such as `https://example.com/` (trailing slash), `https://Example.com` or `…:443` never matched, so every ceremony failed. | Origins were compared as raw strings, but browsers serialize them in a normalized form. | **Fixed.** Origins are normalized at startup. Origins outside `rp_id`, an `rp_id` that contains a scheme or port, and a TTL ≤ 0 are now rejected at startup. Android `apk-key-hash` origins are now accepted. |
| F6 | Medium | Rename and delete returned 204 for unknown ids and for other users' ids. Delete still wrote a `CREDENTIAL_REVOKED` audit event, so the audit trail recorded revocations that never happened. | The router delegated straight to the user-scoped repository write and never checked the result. | **Fixed.** The router looks the credential up first. Unknown and foreign ids both return 404 (`credential_not_found`), and the audit event is emitted only on a real change. |
| F6b | Low | Request bodies were unbounded: device name, `state` and `userId`. A long device name raised a database error (500) on PostgreSQL's `String(255)` column. Control characters were stored as-is. | No length bounds on the schemas. | **Fixed.** Device names are limited to 64 characters, trimmed, and may not contain control or format characters. `state` and `userId` are length-bounded. |
| F7a | Medium | `InMemoryCredentialRepository.add` silently overwrote an existing credential id. In SQLAlchemy, a concurrent duplicate raised `IntegrityError` (500). | `add` was not atomic, and the contract suite did not test duplicates. | **Fixed.** Both adapters raise `CredentialAlreadyExists` (409). The contract suite now requires this. |
| F7b | Medium | A `PasskeyUser.id` over 64 bytes, or an empty one, produced invalid options. An empty `displayName` breaks 1Password. | No validation. | **Fixed.** `begin` raises `ConfigurationError` for an id outside 1–64 bytes or an empty name. An empty `display_name` falls back to `name`. |
| F7c | Low | Base64url decoding accepted non-canonical input: `+`, `/`, and any non-alphabet character, which was silently dropped. | The stdlib `urlsafe_b64decode` is lenient. | **Fixed.** Decoding is now strict. |
| F7d | Medium | An audit sink that raised turned a completed ceremony into a 500. For example, the credential was stored but the client saw an error. | Audit events were emitted inline, with no isolation. | **Fixed.** `emit_safely` logs sink failures and continues. |
| F7e | Low | `is_discoverable` was inferred from config, so it was wrong under `resident_key=preferred`. | The `credProps` extension was neither requested nor read. | **Fixed.** `credProps` is requested and stored, with config as the fallback. |
| F7f | Low | BE/BS were captured only at registration. BS went stale, and a change to BE went undetected. | The authentication path ignored the backup flags. | **Fixed.** A BE change is rejected (`enforce_backup_eligibility`). BS is persisted on each login and reported in `detail`. |
| F7g | Medium | With py_webauthn 2.0–2.4, `detail["user_verified"]` reported the *policy* rather than the authenticator's actual UV flag. | It fell back to `config.require_user_verification` whenever the result had no `user_verified` field. | **Fixed.** The UV bit is read from the verified `authenticatorData`. |
| F7h | Low | SQLAlchemy failed to load a row containing a transport it did not know, which broke sign-in for that row. The `BLOB` primary key also made `create_all` fail on MySQL. | Strict enum parsing; an unbounded `LargeBinary` primary key. | **Fixed.** Unknown transports are skipped, `smart-card` was added, and the key is `VARBINARY(1023)` on MySQL. |
| F7i | Low | `FLAG_DISABLE` deleted the credential without emitting `CREDENTIAL_REVOKED`. | Missing event. | **Fixed.** |
| F8a | Medium | The dependency `webauthn>=2.0` had no upper bound, and CI only tested the latest version. The declared floors (webauthn 2.0, FastAPI 0.110, pydantic 2.5) had never been tested. Testing them found F7g and a pydantic 2.5 bug where the name validators were skipped. | Missing CI job. | **Fixed.** The bound is now `webauthn>=2.0,<4`. CI adds a minimum-dependencies job and Python 3.14, and has been verified on webauthn 3.0.1. |
| F8b | Medium | The release workflow published to PyPI on every push to `main` without running tests. | The release job had no dependency on CI. | **Fixed.** Release now `needs:` the full CI matrix, and `major_on_zero = false` stops an accidental 1.0. |
| F9 | High (docs) | The quickstart and README said to build `get_user` from "an email from the request body". An app that followed this would let anyone register a passkey on anyone's account. | Unsafe example. | **Fixed.** The examples now resolve the authenticated user, and the security model explains why. |

## B. django-passkeys issues

| # | Issue | Root cause there | Status here | Resolution / evidence |
| --- | --- | --- | --- | --- |
| 2 | `reg_begin` ValueError | User handle had the wrong type or encoding. | **Fixed** (F7b) | The handle is always `user.id` UTF-8 bytes, validated to 1–64 bytes. |
| 4 | Missing `.js.map` breaks collectstatic | Vendored assets. | N/A | No static assets are shipped. |
| 5 | jQuery/Bootstrap assumed | Template JS coupled to frameworks. | N/A | No templates. The example uses plain JS. |
| 6 | Setup instructions; port inside the RP ID | Unvalidated RP ID and unclear docs. | **Fixed** (F5) | `rp_id` is validated at startup (no scheme or port, origins must match). New configuration page. |
| 7 | "Invalid origin"; RP ID `localhost:8000` | Origin and RP ID mismatch. | **Fixed** (F5) | Normalization plus a startup check. The config docs cover `localhost` vs `127.0.0.1`. |
| 16 | "A request is already pending" | Conditional UI not aborted. | Docs | The example uses `AbortController`, and the quickstart documents it. |
| 17 | "start is not defined" | Template blocks and Bootstrap. | N/A | No templates. |
| 19 | Mobile (Flutter) client | No JSON API. | Already handled + **Fixed** | A JSON router already existed. Android `apk-key-hash` origins are now accepted (F5). |
| 20 | Releases without tags | Process. | Already handled | Semantic-release tags every release. Releases are now gated on CI (F8b). |
| 21 | README wording; RP ID called the "full domain" | Docs. | Docs | The configuration page defines the RP ID precisely. |
| 22 | Passkeys not persisting | Ephemeral database, or a changed RP ID. | Docs | The security model now says changing `rp_id` orphans every credential, and that in-memory storage is for development only. |
| 25 | `USERNAME_FIELD` hard-coded | Lookup by a login field. | N/A | Lookups use the opaque `PasskeyUser.id`. |
| 26 | "Invalid origin" | Origin mismatch. | **Fixed** (F5) | As #7. |
| 30 | NotAllowedError; empty `displayName` | Environment, plus an empty name. | **Fixed** (F7b) | An empty `display_name` falls back to `name`. UV and attachment are configurable. |
| 31 | Missing `@login_required` on registration | Registration endpoints were not bound to an authenticated user. | **Fixed** (F2, F9) | `register/finish` is bound to the `get_user` result. The docs require `get_user` to be the authenticated user. |
| 33 | Refactor proposal | — | N/A | — |
| 35 | Not PEP8 | Style. | Already handled | ruff and `mypy --strict` run in CI. |
| 36 | Vendored packages | — | N/A | None vendored. |
| 37 | HTML/JS in templates | — | N/A | No templates. |
| 38 | Errors signalled in the body, not the HTTP status | Ad-hoc responses. | Already handled + **Fixed** (F6) | Typed errors map to 400, 401, 404 and 409. Management endpoints now return 404. |
| 39 | `delKey` 500 on an invalid id | Unvalidated id. | **Fixed** (F6, F7c) | An invalid or unknown id returns 404. |
| 40 | Admin integration | — | N/A | — |
| 41 | Tests outside the package | — | Already handled | The test suite and a contract suite ship as `fastapi_passkeys.testing`. |
| 42 | ngrok for the example | Local TLS. | Docs | `http://localhost` works with no TLS (configuration page). |
| 43 | Standard login views | — | N/A | No login views; the `on_authenticated` hook is used instead. |
| 44 | Unspecific registration error | All errors collapsed into a 500. | Already handled | Typed codes, for example `attestation_verification_failed`, `credential_already_exists` and `registration_user_mismatch`. |
| 45 | Platform detection from the user agent | Heuristic. | **Fixed** | `CredentialView.aaguid` (authenticator model) and `detail.authenticator_attachment`. |
| 46 | `auth_complete` is not a view | Design. | N/A | — |
| 47 | FIDO2 module mixes concerns | Design. | N/A | Engine, service and router are separate layers. |
| 53 | Wire format for a custom fetch | Undocumented. | Docs | The quickstart documents the full JSON shape. |
| 54 | python-fido2 major-version break | Unbounded dependency on a library with breaking majors. | **Fixed** (F8a) | `webauthn<4` upper bound. CI tests the floor and latest versions; 3.0.1 is verified. |
| 55 | Modal greyed out | Bootstrap. | N/A | — |
| 56 | Passwordless login; userHandle never checked | Lookup by credential id only. | **Fixed** (F1) | `userHandle` is verified. |
| 57 | Migration from django-fido | No import path. | Docs | The migration guide covers mapping, the user handle and BE. |
| 58 | Blank 1Password dialog: `Uint8Array`, empty names | Client serializer and empty names. | **Fixed** (F7b) + Docs | Name fallback. The example handles any BufferSource and prefers `toJSON()`. |
| 60 | Variable RP ID (multi-tenant) | `Host` header trusted. | Docs | Per-tenant config from an allow-list (security model). |
| 61 | Missing migrations | Model change. | Docs | Schema notes in the storage docs. No table changes are needed on PostgreSQL or SQLite. |
| 71 | `get_user_model()` at import | Django specific. | N/A | No user model is imported. |
| 72 | Backend raises instead of returning None | Auth plugin crashed the auth chain. | N/A | No auth backend. Errors are typed 4xx responses. |
| 73 | KeyError on a missing session state | Unchecked pop. | Already handled | A missing, expired or replayed state gives a clean `challenge_not_found` (400). |

### Bug-related pull requests

| PR | Concern | Status here |
| --- | --- | --- |
| #3 | Disabled keys could still authenticate | N/A. There is no enabled flag; deletion takes effect immediately. A soft-disable is **Deferred** (needs a schema change). |
| #8, #78 | Hard-coded username field | N/A (opaque `PasskeyUser.id`). |
| #9, #29 | IDOR and an existence oracle on key deletion | **Fixed** (F6): identical 404 for unknown and foreign ids. |
| #11, #67 | XSS through the key name | The library returns JSON only. **Fixed**: names are bounded and stripped of control characters. Docs and example use `textContent`. |
| #12, #62 | State changes over GET (CSRF) | Already handled (PATCH and DELETE with JSON). CSRF guidance in the security model. |
| #18, #51 | Conditional-UI abort; `Uint8Array` | Example and docs (see #16, #58). |
| #49, #74 | Backend raising, custom user model | N/A. |
| #67 | Uncaught verify exceptions became 500; duplicate registration | Already handled: every engine error maps to a typed 4xx. Duplicates give 409, now atomic (F7a). |
| #76 | `get_full_name` missing; empty displayName | **Fixed** (F7b). |
| #79 | Integer username; PII in the user handle | N/A for the type. Docs: the handle must be an opaque 1–64 byte id, never an email. |

### Problems in django-passkeys' current core that no issue reports

| Concern | Status here |
| --- | --- |
| Sign count never stored or checked | Already handled. Enforced, with three policies. |
| userHandle not checked | **Fixed** (F1). |
| User handle is `base64(username)`, which is PII | Docs (opaque id). Format validated (F7b). |
| userVerification not set explicitly | Already handled (configurable, sent explicitly). Actual UV now reported accurately (F7g). |
| Username-first begin enumerates credentials | Docs. Usernameless flows are recommended. Fake-credential mitigation is **Deferred**. |
| Attestation not verified; AAGUID and transports not stored | AAGUID and transports are stored and exposed. Attestation trust and MDS are **Deferred**. |

## C. Features adopted from the library survey

| Feature | Seen in | Decision |
| --- | --- | --- |
| userHandle ownership check | go-webauthn, fido2-net-lib | **Adopted** (F1). |
| BE immutability check and BS tracking | go-webauthn, fido2-net-lib | **Adopted** (F7f). |
| `credProps` → discoverable flag | SimpleWebAuthn | **Adopted** (F7e). |
| `audit-only` clone policy | go-webauthn (`CloneWarning`) | **Adopted.** |
| WebAuthn L3 `hints` | py_webauthn, SimpleWebAuthn | **Adopted** (`config.hints`). |
| Signal API payloads | SimpleWebAuthn browser | **Adopted** (`GET /credentials/signals`, `error.signal.unknownCredential`). |
| Related Origin Requests | spec §5.11, go-webauthn | **Adopted** (`related_origins`, `well_known_router`). |
| Max credentials per user | — | **Adopted** (`max_credentials_per_user`). |
| AAGUID exposed in listings | fido2-net-lib, Laragear | **Adopted** (`CredentialView.aaguid`). A bundled name/icon map is **Deferred**: the community passkey-aaguids list is being retired in favour of FIDO MDS. |
| Android app origins | go-webauthn, SimpleWebAuthn | **Adopted.** |
| Soft-disable instead of delete | Laragear | **Deferred.** It needs a new column, so it waits for a release that ships migrations. |
| Random per-user handle decoupled from `user.id` | SimpleWebAuthn, py_webauthn | **Deferred.** It changes the repository and schema; for now the docs require an opaque id. |
| Re-auth ("sudo") dependency | — | **Docs.** This depends on the app's session model; it can be attached as a router dependency. |
| Fake `allowCredentials` for unknown users | webauthn-rs | **Deferred.** Docs recommend usernameless flows. |
| Attestation trust + FIDO MDS3 | python-fido2, Yubico, go-webauthn | **Deferred.** Planned as an optional `[mds]` extra. |
| Default `user_verification="required"` | SimpleWebAuthn, webauthn-rs | **Not adopted** in 0.2, because it would break PIN-less security keys. It is documented as the recommended setting for passwordless sign-in. |
| Compare-and-set sign-count update | — | **Deferred.** Two concurrent assertions that present the same counter can both pass. This is low risk, and fixing it needs a repository contract change. |
