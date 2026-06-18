# CHANGELOG


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
