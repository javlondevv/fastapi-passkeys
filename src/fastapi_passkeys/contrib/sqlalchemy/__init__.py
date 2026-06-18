"""SQLAlchemy 2.0 (async) credential repository.

Requires the ``[sqlalchemy]`` extra. Ship a ready-made model on its own
declarative base so it never collides with your app's metadata; ``user_id`` is a
plain indexed string (the WebAuthn user handle). Add a foreign key in your own
migration if you want referential integrity.

    from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine
    from fastapi_passkeys.contrib.sqlalchemy import (
        PasskeyBase, SqlAlchemyCredentialRepository,
    )

    engine = create_async_engine("postgresql+asyncpg://...")
    async with engine.begin() as conn:
        await conn.run_sync(PasskeyBase.metadata.create_all)
    repo = SqlAlchemyCredentialRepository(async_sessionmaker(engine))
"""

from __future__ import annotations

from datetime import datetime

from sqlalchemy import (
    BigInteger,
    Boolean,
    DateTime,
    LargeBinary,
    String,
    delete,
    select,
    update,
)
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column
from sqlalchemy.types import JSON

from fastapi_passkeys.domain.enums import Transport
from fastapi_passkeys.domain.models import Credential


class PasskeyBase(DeclarativeBase):
    """Declarative base owning the passkey table's metadata."""


class PasskeyCredential(PasskeyBase):
    __tablename__ = "passkey_credentials"

    credential_id: Mapped[bytes] = mapped_column(LargeBinary, primary_key=True)
    user_id: Mapped[str] = mapped_column(String(255), index=True)
    public_key: Mapped[bytes] = mapped_column(LargeBinary)
    sign_count: Mapped[int] = mapped_column(BigInteger, default=0)
    transports: Mapped[list[str]] = mapped_column(JSON, default=list)
    aaguid: Mapped[bytes | None] = mapped_column(LargeBinary, nullable=True)
    backup_eligible: Mapped[bool] = mapped_column(Boolean, default=False)
    backup_state: Mapped[bool] = mapped_column(Boolean, default=False)
    device_name: Mapped[str] = mapped_column(String(255), default="")
    is_discoverable: Mapped[bool] = mapped_column(Boolean, default=False)
    attestation_fmt: Mapped[str | None] = mapped_column(String(64), nullable=True)
    created_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    last_used_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)


def _to_domain(row: PasskeyCredential) -> Credential:
    return Credential(
        credential_id=row.credential_id,
        user_id=row.user_id,
        public_key=row.public_key,
        sign_count=row.sign_count,
        transports=tuple(Transport(t) for t in row.transports),
        aaguid=row.aaguid,
        backup_eligible=row.backup_eligible,
        backup_state=row.backup_state,
        device_name=row.device_name,
        is_discoverable=row.is_discoverable,
        attestation_fmt=row.attestation_fmt,
        created_at=row.created_at,
        last_used_at=row.last_used_at,
    )


class SqlAlchemyCredentialRepository:
    """Async :class:`CredentialRepository` backed by SQLAlchemy 2.0."""

    def __init__(self, session_factory: async_sessionmaker[AsyncSession]) -> None:
        self._session_factory = session_factory

    async def add(self, credential: Credential) -> None:
        async with self._session_factory() as session:
            session.add(
                PasskeyCredential(
                    credential_id=credential.credential_id,
                    user_id=credential.user_id,
                    public_key=credential.public_key,
                    sign_count=credential.sign_count,
                    transports=[t.value for t in credential.transports],
                    aaguid=credential.aaguid,
                    backup_eligible=credential.backup_eligible,
                    backup_state=credential.backup_state,
                    device_name=credential.device_name,
                    is_discoverable=credential.is_discoverable,
                    attestation_fmt=credential.attestation_fmt,
                    created_at=credential.created_at,
                    last_used_at=credential.last_used_at,
                )
            )
            await session.commit()

    async def get_by_credential_id(self, credential_id: bytes) -> Credential | None:
        async with self._session_factory() as session:
            row = await session.get(PasskeyCredential, credential_id)
            return _to_domain(row) if row is not None else None

    async def list_by_user(self, user_id: str) -> list[Credential]:
        async with self._session_factory() as session:
            result = await session.execute(
                select(PasskeyCredential).where(PasskeyCredential.user_id == user_id)
            )
            return [_to_domain(row) for row in result.scalars().all()]

    async def update_usage(
        self, credential_id: bytes, *, sign_count: int, last_used_at: datetime
    ) -> None:
        async with self._session_factory() as session:
            await session.execute(
                update(PasskeyCredential)
                .where(PasskeyCredential.credential_id == credential_id)
                .values(sign_count=sign_count, last_used_at=last_used_at)
            )
            await session.commit()

    async def rename(self, credential_id: bytes, user_id: str, name: str) -> None:
        async with self._session_factory() as session:
            await session.execute(
                update(PasskeyCredential)
                .where(
                    PasskeyCredential.credential_id == credential_id,
                    PasskeyCredential.user_id == user_id,
                )
                .values(device_name=name)
            )
            await session.commit()

    async def delete(self, credential_id: bytes, user_id: str) -> None:
        async with self._session_factory() as session:
            await session.execute(
                delete(PasskeyCredential).where(
                    PasskeyCredential.credential_id == credential_id,
                    PasskeyCredential.user_id == user_id,
                )
            )
            await session.commit()


__all__ = [
    "PasskeyBase",
    "PasskeyCredential",
    "SqlAlchemyCredentialRepository",
]
