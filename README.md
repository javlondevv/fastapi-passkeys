# fastapi-passkeys

[![PyPI](https://img.shields.io/pypi/v/fastapi-passkeys.svg)](https://pypi.org/project/fastapi-passkeys/)
[![Python](https://img.shields.io/pypi/pyversions/fastapi-passkeys.svg)](https://pypi.org/project/fastapi-passkeys/)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
[![CI](https://github.com/javlondevv/fastapi-passkeys/actions/workflows/ci.yml/badge.svg)](https://github.com/javlondevv/fastapi-passkeys/actions)

**Passkeys / WebAuthn authentication for FastAPI — secure by default, storage-agnostic, async-native.**

`fastapi-passkeys` owns the hard, security-sensitive part of passkeys — the WebAuthn
ceremony, challenge integrity, signature-counter clone detection, and credential
lifecycle — and stays out of the way of *your* idea of a session. You bring a storage
backend and two small hooks; it brings correctness.

> **Status: alpha (0.1.x).** The public API may change before 1.0. It is being driven to
> a stable, production-ready 1.0 — see the [roadmap](#roadmap).

## Table of contents

- [Why](#why)
- [Install](#install)
- [Quickstart](#quickstart)
- [How it works](#how-it-works)
- [Endpoints](#endpoints)
- [Storage backends](#storage-backends)
- [Security model](#security-model)
- [Roadmap](#roadmap)
- [Contributing](#contributing)
- [License](#license)

## Why

Passwords are a liability. Passkeys (WebAuthn) replace them with phishing-resistant,
public-key credentials backed by the user's device. But WebAuthn is easy to get subtly
wrong: dropped signature counters, replayable challenges, missing origin checks. The
existing Django solution couples tightly to the Django ORM, sessions, and DRF, and
notably **stores no signature counter at all** — so it cannot detect cloned authenticators.

`fastapi-passkeys` is a ground-up design for FastAPI that:

- **Is secure by default** — enforced challenge TTL + single-use, origin/RP validation,
  user-verification policy, and monotonic `sign_count` clone detection.
- **Doesn't lock you into an ORM** — storage is an async `Protocol`; ship-with adapters
  for SQLAlchemy and Redis, plus a contract test-suite for your own.
- **Doesn't impose an auth opinion** — it verifies the passkey and hands you the user;
  you mint whatever session or token you like.
- **Is fully typed** (`mypy --strict`) and async end-to-end.

## Install

```bash
pip install fastapi-passkeys                  # core (in-memory + stateless stores)
pip install "fastapi-passkeys[sqlalchemy]"    # SQLAlchemy 2.0 async credential repo
pip install "fastapi-passkeys[redis]"         # Redis challenge store
```

## Quickstart

```python
from fastapi import FastAPI, Request
from fastapi_passkeys import Passkeys, PasskeyConfig, PasskeyUser, AuthenticationResult
from fastapi_passkeys.contrib import InMemoryCredentialRepository


async def get_user(request: Request) -> PasskeyUser:
    # however your app identifies the in-progress user (session, signup token, ...)
    return PasskeyUser(id="user-123", name="ada@example.com", display_name="Ada Lovelace")


async def on_authenticated(request: Request, result: AuthenticationResult) -> dict:
    # mint your own session / JWT here
    return {"access_token": issue_token(result.user_id)}


passkeys = Passkeys(
    config=PasskeyConfig(
        rp_id="example.com",
        rp_name="Example",
        expected_origins=["https://example.com"],
    ),
    credential_repository=InMemoryCredentialRepository(),
    get_user=get_user,
    on_authenticated=on_authenticated,
)

app = FastAPI()
app.include_router(passkeys.router, prefix="/auth/passkeys")
passkeys.install_exception_handlers(app)
```

Need full control? Skip the router and drive `passkeys.registration` /
`passkeys.authentication` (the services) from your own endpoints.

## How it works

Both ceremonies are two HTTP round-trips. `begin` returns the options your frontend
passes to `navigator.credentials.create()` / `.get()`, plus an opaque `state` handle.
Your frontend echoes that `state` back to `finish` along with the authenticator's
response. The challenge is single-use and TTL-bound; the handle is the only thing the
client needs to keep between the two calls — no server session required.

## Endpoints

| Method | Path | Purpose |
| --- | --- | --- |
| `POST` | `/register/begin` | Start registration; returns creation options + `state`. |
| `POST` | `/register/finish` | Verify attestation and store the credential. |
| `POST` | `/authenticate/begin` | Start authentication (usernameless or with `userId`). |
| `POST` | `/authenticate/finish` | Verify assertion; runs `on_authenticated`. |
| `GET` | `/credentials` | List the current user's passkeys. |
| `PATCH` | `/credentials/{id}` | Rename a passkey. |
| `DELETE` | `/credentials/{id}` | Revoke a passkey. |

## Storage backends

| Backend | Import | Extra | Notes |
| --- | --- | --- | --- |
| In-memory | `fastapi_passkeys.contrib.InMemoryCredentialRepository` | — | Dev/tests, single process. |
| In-memory challenges | `fastapi_passkeys.contrib.InMemoryChallengeStore` | — | Single-use, single process. |
| Stateless challenges | `fastapi_passkeys.contrib.StatelessChallengeStore` | — | Signed token, no infra ([tradeoff](src/fastapi_passkeys/contrib/stateless.py)). |
| SQLAlchemy | `fastapi_passkeys.contrib.sqlalchemy.SqlAlchemyCredentialRepository` | `[sqlalchemy]` | Async, production default. |
| Redis challenges | `fastapi_passkeys.contrib.redis.RedisChallengeStore` | `[redis]` | Atomic single-use across instances. |

Implement the `CredentialRepository` / `ChallengeStore` Protocols for any other store and
validate it with the shipped contract suite (`fastapi_passkeys.testing`).

## Security model

- **Challenges** are CSPRNG-generated, bound to user + ceremony, TTL-enforced server-side,
  and single-use (in the in-memory and Redis stores).
- **Clone detection**: the signature counter is stored and required to advance; a
  regression is rejected (and optionally auto-disables the credential) and audited.
- **Origins & RP ID** are strictly validated; multiple origins are supported.
- **No secrets are logged**; audit events carry identifiers and outcomes only.

See the [security documentation](docs/security.md) for the full model.

## Roadmap

- [x] Core domain, engine, services
- [x] Registration & authentication flows
- [x] SQLAlchemy + Redis adapters, contract suite
- [ ] Documentation site
- [ ] `1.0.0` once the public API is proven stable

## Contributing

Issues and PRs welcome. Run `ruff check`, `mypy src`, and `pytest` before submitting.
See [CONTRIBUTING.md](CONTRIBUTING.md).

## License

MIT © Javlon Baxtiyorov
