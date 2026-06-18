"""Credential storage contract.

Implement this Protocol against any store (SQLAlchemy, SQLModel, Tortoise,
Beanie, Redis, a REST service…). The shipped :mod:`fastapi_passkeys.testing`
contract suite verifies an implementation behaves correctly — run it against
your adapter in CI.
"""

from __future__ import annotations

from datetime import datetime
from typing import Protocol, runtime_checkable

from fastapi_passkeys.domain.models import Credential


@runtime_checkable
class CredentialRepository(Protocol):
    """Persistence for registered passkeys. All methods are coroutines."""

    async def add(self, credential: Credential) -> None:
        """Persist a newly registered credential."""
        ...

    async def get_by_credential_id(self, credential_id: bytes) -> Credential | None:
        """Return the credential with this id, or ``None`` if unknown."""
        ...

    async def list_by_user(self, user_id: str) -> list[Credential]:
        """Return all credentials registered to a user (may be empty)."""
        ...

    async def update_usage(
        self,
        credential_id: bytes,
        *,
        sign_count: int,
        last_used_at: datetime,
    ) -> None:
        """Record a successful authentication: advance counter and last-used."""
        ...

    async def rename(self, credential_id: bytes, user_id: str, name: str) -> None:
        """Set a user-facing device name. Scoped to ``user_id`` for safety."""
        ...

    async def delete(self, credential_id: bytes, user_id: str) -> None:
        """Revoke a credential. Scoped to ``user_id`` so users cannot delete others'."""
        ...
