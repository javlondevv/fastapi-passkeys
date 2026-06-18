"""Run the shipped contract suite against every storage adapter."""

from __future__ import annotations

import pytest
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine
from sqlalchemy.pool import StaticPool

from fastapi_passkeys.contrib.memory import InMemoryChallengeStore, InMemoryCredentialRepository
from fastapi_passkeys.contrib.redis import RedisChallengeStore
from fastapi_passkeys.contrib.sqlalchemy import PasskeyBase, SqlAlchemyCredentialRepository
from fastapi_passkeys.contrib.stateless import StatelessChallengeStore
from fastapi_passkeys.testing import check_challenge_store, check_credential_repository


async def test_in_memory_credential_repository() -> None:
    await check_credential_repository(InMemoryCredentialRepository)


async def test_in_memory_challenge_store() -> None:
    await check_challenge_store(lambda clock: InMemoryChallengeStore(clock=clock))


async def test_stateless_challenge_store() -> None:
    await check_challenge_store(
        lambda clock: StatelessChallengeStore("test-secret", clock=clock),
        single_use=False,
    )


async def test_sqlalchemy_credential_repository() -> None:
    engine = create_async_engine(
        "sqlite+aiosqlite://",
        poolclass=StaticPool,
        connect_args={"check_same_thread": False},
    )
    async with engine.begin() as conn:
        await conn.run_sync(PasskeyBase.metadata.create_all)
    session_factory = async_sessionmaker(engine, expire_on_commit=False)
    try:
        await check_credential_repository(lambda: SqlAlchemyCredentialRepository(session_factory))
    finally:
        await engine.dispose()


async def test_redis_challenge_store() -> None:
    fakeredis = pytest.importorskip("fakeredis")
    client = fakeredis.FakeAsyncRedis()
    try:
        await check_challenge_store(lambda clock: RedisChallengeStore(client, clock=clock))
    finally:
        await client.aclose()
