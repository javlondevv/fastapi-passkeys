# CHANGELOG


## v0.1.1 (2026-06-18)

### Bug Fixes

- **release**: Add manual workflow_dispatch trigger to release pipeline
  ([`cd1eb35`](https://github.com/javlondevv/fastapi-passkeys/commit/cd1eb35d0bb55b0c223986c3f03ef1a07bb26f83))

Allows manually re-triggering a release and ensures the first successful PyPI publish via Trusted
  Publishing (OIDC).


## v0.1.0 (2026-06-18)

### Features

- Initial fastapi-passkeys library (v0.1.0)
  ([`78c011a`](https://github.com/javlondevv/fastapi-passkeys/commit/78c011a63c3b4cd8f53e49e35d3c650ad0bd5055))

WebAuthn/passkeys authentication for FastAPI: async-native, storage-agnostic, secure by default.
  Includes registration/authentication ceremonies, signature counter clone detection, single-use TTL
  challenges, strict origin/RP validation, pluggable repositories (in-memory, stateless, SQLAlchemy,
  Redis), a contract test-suite, a software authenticator for tests, docs, and a runnable example.
