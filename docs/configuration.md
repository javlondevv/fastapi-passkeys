# Configuration

`PasskeyConfig` is a `pydantic-settings` model: pass values in code, or set
`PASSKEYS_<FIELD>` environment variables (lists as JSON, e.g.
`PASSKEYS_EXPECTED_ORIGINS='["https://example.com"]'`).

The config is validated at startup, so mistakes that would otherwise fail every ceremony at
runtime fail at startup instead.

## Relying party

| Field | Default | Notes |
| --- | --- | --- |
| `rp_id` | — | Bare registrable domain: `example.com`. No scheme, port or path. Lowercased. |
| `rp_name` | — | Shown by some authenticators. |
| `expected_origins` | — | Exact origins allowed at verification. Normalized to the browser's form (`https://Example.com:443/` → `https://example.com`). Every web origin must be `rp_id` or a subdomain of it. Android app origins (`android:apk-key-hash:…`) are accepted verbatim. |
| `related_origins` | `[]` | [Related Origin Requests](https://passkeys.dev/docs/advanced/related-origins/): origins on **other** domains allowed to use `rp_id`. Served from `/.well-known/webauthn` by `passkeys.well_known_router` and accepted at verification. Browsers limit this to 5 distinct registrable domains. |

!!! tip "Local development"
    `rp_id="localhost"` with `expected_origins=["http://localhost:8000"]`. Use `localhost`, not
    `127.0.0.1`: an IP address is never a valid RP ID.

## Ceremony policy

| Field | Default | Notes |
| --- | --- | --- |
| `user_verification` | `preferred` | `required` makes the server reject assertions/attestations without the UV flag. Recommended for passwordless sign-in. |
| `resident_key` | `preferred` | Discoverable credentials enable usernameless login and autofill. |
| `authenticator_attachment` | `None` | `platform` / `cross-platform` to restrict; `None` allows both (and phones via hybrid). |
| `attestation` | `none` | See the [security model](security.md) before asking for `direct`. |
| `hints` | `[]` | WebAuthn L3 hints (`security-key`, `client-device`, `hybrid`), most preferred first. Sent with both ceremonies. |
| `timeout_ms` | `60000` | Client-side hint. |
| `challenge_ttl` | 5 min | Server-enforced. Must be positive; a warning is emitted if shorter than `timeout_ms`. |
| `max_credentials_per_user` | `None` | Refuse registration beyond this many passkeys (`credential_limit_reached`, 409). |

## Verification strictness

| Field | Default | Notes |
| --- | --- | --- |
| `sign_count_policy` | `strict-reject` | `strict-reject`, `flag-disable`, or `audit-only` — see [clone detection](security.md#clone-detection-policy). |
| `verify_user_handle` | `True` | Require the assertion's `userHandle` to identify the credential owner. Turn off only for credentials imported from a library with a different user-handle scheme ([migration](migration.md)). |
| `enforce_backup_eligibility` | `True` | Reject an assertion whose BE flag differs from registration. Turn off if you imported credentials without knowing their BE flag. |

## Storage

| Field | Default | Notes |
| --- | --- | --- |
| `signing_secret` | `None` | When set and no `challenge_store` is passed, `Passkeys` uses `StatelessChallengeStore`. Read its [tradeoff](security.md#challenge-store-tradeoffs) first. |
