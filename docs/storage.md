# Storage backends

The library never imports an ORM. Storage is two async Protocols:
`CredentialRepository` (persistent passkeys) and `ChallengeStore` (in-flight challenges).

## Shipped adapters

```python
# Core (no extras)
from fastapi_passkeys.contrib import (
    InMemoryCredentialRepository,
    InMemoryChallengeStore,
    StatelessChallengeStore,
)
```

### SQLAlchemy (`[sqlalchemy]`)

```python
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine
from fastapi_passkeys.contrib.sqlalchemy import PasskeyBase, SqlAlchemyCredentialRepository

engine = create_async_engine("postgresql+asyncpg://localhost/app")
async with engine.begin() as conn:
    await conn.run_sync(PasskeyBase.metadata.create_all)

repo = SqlAlchemyCredentialRepository(async_sessionmaker(engine, expire_on_commit=False))
```

`user_id` is a plain indexed string (the WebAuthn user handle). Add a foreign key to your
users table in your own migration if you want referential integrity.

### Redis challenge store (`[redis]`)

```python
from redis.asyncio import Redis
from fastapi_passkeys.contrib.redis import RedisChallengeStore

store = RedisChallengeStore(Redis.from_url("redis://localhost:6379/0"))
```

## Repository contract (0.2)

- `add` must raise `CredentialAlreadyExists` — never overwrite — when the credential id is
  already stored. Credential ids are chosen by the authenticator, so an overwrite would let a
  user replace someone else's passkey. The contract suite checks this. Back it with a unique /
  primary key and translate the integrity error, as the SQLAlchemy adapter does.
- `update_usage` accepts an optional `backup_state: bool | None` keyword (the credential's
  current BS flag; `None` = unchanged). Repositories written for 0.1 without it keep working —
  the backup state is then reported but not persisted.

### SQLAlchemy schema notes

The `passkey_credentials` table is unchanged in 0.2 on PostgreSQL and SQLite. On
MySQL/MariaDB `credential_id` is now `VARBINARY(1023)`. Earlier versions declared an
unbounded `BLOB` primary key, so `create_all` failed on MySQL and no existing MySQL table
needs migrating.

## Writing your own

Implement the Protocol against any store, then prove it with the shipped contract suite:

```python
import pytest
from fastapi_passkeys.testing import check_credential_repository, check_challenge_store


@pytest.mark.asyncio
async def test_my_repo():
    await check_credential_repository(MyCredentialRepository)


@pytest.mark.asyncio
async def test_my_store():
    await check_challenge_store(lambda clock: MyChallengeStore(clock=clock))
```

This is exactly how the SQLAlchemy, Redis, and in-memory adapters are tested — so an
SQLModel, Tortoise, or Beanie adapter you write is held to the same bar.
