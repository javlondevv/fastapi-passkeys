# Contributing to fastapi-passkeys

Thanks for your interest in improving fastapi-passkeys! This is a security-sensitive
library, so we hold a high bar for tests and clarity.

## Development setup

```bash
python -m venv .venv && source .venv/bin/activate
pip install -e ".[dev,sqlalchemy,redis]"
pre-commit install
```

## Before you open a PR

Run the full gate locally — CI runs the same on Python 3.10–3.13:

```bash
ruff check src tests
ruff format --check src tests
mypy src
pytest
```

## Guidelines

- **Keep the layering.** `domain` depends on nothing; only `engine` imports the WebAuthn
  library; only `api` imports FastAPI; only `contrib.<x>` imports `<x>`. New optional
  dependencies go behind an extra and a `contrib` module.
- **New storage adapters** must pass the contract suite in `fastapi_passkeys.testing`.
- **Security changes** need a test under `tests/test_security.py` demonstrating the property.
- **Commit messages** follow [Conventional Commits](https://www.conventionalcommits.org/)
  (`feat:`, `fix:`, `docs:`, …) — releases and the changelog are generated from them.

## Reporting vulnerabilities

Please do **not** open public issues for security vulnerabilities. See
[SECURITY.md](SECURITY.md) for private disclosure.
