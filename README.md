<p align="center">
  <a href="https://github.com/javlondevv/fastapi-passkeys">
    <img src="assets/banner.svg" alt="fastapi-passkeys" width="100%">
  </a>
</p>

<h1 align="center">fastapi-passkeys</h1>

<p align="center">
  Passkeys / WebAuthn authentication for <b>FastAPI</b> —
  phishing-resistant passwordless login with cloned-authenticator detection,
  single-use challenges, and strict origin checks, without locking into a
  specific auth library or ORM.
</p>

<p align="center">
  <a href="https://pypi.org/project/fastapi-passkeys/"><img src="https://img.shields.io/pypi/v/fastapi-passkeys?color=blue&label=pypi" alt="PyPI version"></a>
  <a href="https://pypi.org/project/fastapi-passkeys/"><img src="https://img.shields.io/pypi/pyversions/fastapi-passkeys" alt="Python versions"></a>
  <a href="./LICENSE"><img src="https://img.shields.io/badge/license-MIT-green" alt="License: MIT"></a>
  <a href="https://github.com/javlondevv/fastapi-passkeys/actions/workflows/ci.yml"><img src="https://github.com/javlondevv/fastapi-passkeys/actions/workflows/ci.yml/badge.svg" alt="CI"></a>
  <a href="https://github.com/astral-sh/ruff"><img src="https://img.shields.io/badge/code%20style-ruff-261230" alt="Code style: ruff"></a>
  <a href="https://github.com/python/mypy"><img src="https://img.shields.io/badge/typed-mypy%20strict-2a6db2" alt="Typed: mypy strict"></a>
  <br>
  <a href="https://github.com/javlondevv/fastapi-passkeys/stargazers"><img src="https://img.shields.io/github/stars/javlondevv/fastapi-passkeys?style=social" alt="GitHub stars"></a>
  <a href="https://github.com/javlondevv/fastapi-passkeys/issues"><img src="https://img.shields.io/github/issues/javlondevv/fastapi-passkeys" alt="Open issues"></a>
  <a href="https://github.com/javlondevv/fastapi-passkeys/commits/main"><img src="https://img.shields.io/github/last-commit/javlondevv/fastapi-passkeys/main" alt="Last commit"></a>
</p>

<p align="center">
  <b>If this project helps you, please <a href="https://github.com/javlondevv/fastapi-passkeys">⭐ star the repo</a> — it really helps others find it.</b>
  &nbsp;·&nbsp;
  <a href="https://twitter.com/intent/tweet?text=fastapi-passkeys%20%E2%80%94%20passkeys%20%26%20WebAuthn%20authentication%20for%20FastAPI&url=https://github.com/javlondevv/fastapi-passkeys&hashtags=FastAPI,Python,WebAuthn,passkeys"><img src="https://img.shields.io/badge/Tweet-share-1DA1F2?logo=twitter&logoColor=white" alt="Tweet"></a>
</p>

---

## Table of contents

- [Status](#status)
- [Why](#why)
- [Install](#install)
- [Quickstart](#quickstart)
- [Endpoints](#endpoints)
- [Storage backends](#storage-backends)
- [Security](#security)
- [Documentation](#documentation)
- [Roadmap](#roadmap)
- [Contributing](#contributing)
- [Support the project](#support-the-project)
- [License](#license)

## Status

`0.1.1` — **Alpha.** Full registration + authentication ceremonies, clone
detection, and SQLAlchemy/Redis adapters. The public API may change before
`1.0`. See [`CHANGELOG.md`](./CHANGELOG.md) and the [roadmap](#roadmap).

## Why

Passwords are a liability and WebAuthn is easy to get subtly wrong — dropped
signature counters, replayable challenges, missing origin checks.
`fastapi-passkeys` owns the hard, security-sensitive part and stays out of the
way of *your* idea of a session:

- **Secure by default** — single-use, TTL-bound challenges; strict origin/RP
  validation; user-verification policy; and monotonic `sign_count` cloned-
  authenticator detection (the prior Django solution stores no counter at all).
- **Auth-agnostic** — it verifies the passkey and hands you the user; you mint
  whatever session or JWT you like via an `on_authenticated` hook.
- **Storage-abstracted** — credentials live behind an async `CredentialRepository`
  protocol (in-memory, stateless, SQLAlchemy 2.0, and Redis adapters included),
  with a shipped contract test-suite for your own.
- **Async-native and fully typed** (`mypy --strict`, `py.typed`).

## Install

```bash
pip install fastapi-passkeys
# optional extras:
pip install "fastapi-passkeys[sqlalchemy]"   # SQLAlchemy 2.0 async credential repo
pip install "fastapi-passkeys[redis]"        # Redis challenge store (atomic single-use)
```

## Quickstart

```python
from fastapi import FastAPI, Request

from fastapi_passkeys import (
    AuthenticationResult,
    Passkeys,
    PasskeyConfig,
    PasskeyUser,
)
from fastapi_passkeys.contrib import InMemoryCredentialRepository


async def get_user(request: Request) -> PasskeyUser:
    # However your app identifies the in-progress user: a signup token, an
    # existing session, an email from the request body, etc.
    return PasskeyUser(id="user-123", name="ada@example.com", display_name="Ada Lovelace")


async def on_authenticated(request: Request, result: AuthenticationResult) -> dict:
    # The passkey is verified — now mint *your* session or token.
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
app.include_router(passkeys.router, prefix="/auth/passkeys", tags=["passkeys"])
passkeys.install_exception_handlers(app)
```

Each ceremony is a `begin` → `finish` pair: `begin` returns the options your
frontend passes to `navigator.credentials.create()` / `.get()` plus an opaque
`state` handle; echo that `state` back to `finish` with the authenticator's
response. No server session is required between the calls. A full, runnable
browser demo lives in [`examples/app.py`](./examples/app.py).

Need full control? Skip the router and drive `passkeys.registration` /
`passkeys.authentication` (the services) from your own endpoints.

### Endpoints

| Method | Path | Purpose |
|---|---|---|
| `POST` | `/register/begin` | Start registration; returns creation options + `state` |
| `POST` | `/register/finish` | Verify attestation and store the credential |
| `POST` | `/authenticate/begin` | Start authentication (usernameless or with `userId`) |
| `POST` | `/authenticate/finish` | Verify assertion; runs your `on_authenticated` hook |
| `GET` | `/credentials` | List the current user's passkeys |
| `PATCH` | `/credentials/{id}` | Rename a passkey |
| `DELETE` | `/credentials/{id}` | Revoke a passkey |

## Storage backends

| Backend | Import | Extra |
|---|---|---|
| In-memory credentials | `fastapi_passkeys.contrib.InMemoryCredentialRepository` | — |
| In-memory challenges | `fastapi_passkeys.contrib.InMemoryChallengeStore` | — |
| Stateless challenges | `fastapi_passkeys.contrib.StatelessChallengeStore` | — |
| SQLAlchemy credentials | `fastapi_passkeys.contrib.sqlalchemy.SqlAlchemyCredentialRepository` | `[sqlalchemy]` |
| Redis challenges | `fastapi_passkeys.contrib.redis.RedisChallengeStore` | `[redis]` |

Implement the `CredentialRepository` / `ChallengeStore` protocols for any other
store (SQLModel, Tortoise, Beanie, …) and validate it with the shipped contract
suite in `fastapi_passkeys.testing`.

## Security

- **Challenges** are CSPRNG-generated, bound to user + ceremony, TTL-enforced
  server-side, and single-use (in-memory and Redis stores).
- **Clone detection** stores and enforces the signature counter; a regression is
  rejected (and optionally auto-disables the credential) and audited.
- **Origins & RP ID** are strictly validated; multiple origins are supported.
- **No secrets are logged** — audit events carry identifiers and outcomes only.

See the [security model](https://javlondevv.github.io/fastapi-passkeys/security/)
for the full picture, including the stateless-store tradeoff. Report
vulnerabilities privately via [`SECURITY.md`](./SECURITY.md).

## Documentation

Full docs: **https://javlondevv.github.io/fastapi-passkeys/**

- [Quickstart](https://javlondevv.github.io/fastapi-passkeys/quickstart/)
- [Concepts](https://javlondevv.github.io/fastapi-passkeys/concepts/) — a short WebAuthn primer
- [Storage backends](https://javlondevv.github.io/fastapi-passkeys/storage/)
- [Security model](https://javlondevv.github.io/fastapi-passkeys/security/)
- [Migrating from django-passkeys](https://javlondevv.github.io/fastapi-passkeys/migration/)

## Roadmap

- **0.1** — core ceremonies, clone detection, router + services, in-memory /
  stateless / SQLAlchemy / Redis adapters, contract suite, docs site.
- **0.2** — username-first resolution hooks, conditional-UI helpers, attestation
  verification options, rate-limiting guidance.
- **0.3** — SQLModel / Tortoise / Beanie adapters, credential metadata events,
  admin/management helpers.
- **1.0** — API freeze + semver guarantee.

## Contributing

Contributions are very welcome! See [`CONTRIBUTING.md`](./CONTRIBUTING.md) for the
dev setup and checks. Good entry points are the issues labelled
[**good first issue**](https://github.com/javlondevv/fastapi-passkeys/issues?q=is%3Aissue+is%3Aopen+label%3A%22good+first+issue%22)
and [**help wanted**](https://github.com/javlondevv/fastapi-passkeys/issues?q=is%3Aissue+is%3Aopen+label%3A%22help+wanted%22).
Please also read our [Code of Conduct](./CODE_OF_CONDUCT.md).

## Support the project

The simplest way to help is a **⭐ star** — it boosts visibility for everyone.

Embed a live star button on your own site or docs with
[GitHub Buttons](https://buttons.github.io/):

```html
<!-- Place once, before </body> -->
<a class="github-button"
   href="https://github.com/javlondevv/fastapi-passkeys"
   data-icon="octicon-star"
   data-size="large"
   data-show-count="true"
   aria-label="Star javlondevv/fastapi-passkeys on GitHub">Star</a>
<script async defer src="https://buttons.github.io/buttons.js"></script>
```

## License

MIT — see [`LICENSE`](./LICENSE).
