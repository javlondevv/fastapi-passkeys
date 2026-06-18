"""In-memory storage backends.

Bundled in core (no extras) so the library works out of the box and powers the
test suite. Both are single-process only — fine for development, tests, and
single-instance deployments, but use :mod:`fastapi_passkeys.contrib.sqlalchemy`
and :mod:`fastapi_passkeys.contrib.redis` for anything horizontally scaled.
"""

from __future__ import annotations

import dataclasses
import secrets
from datetime import datetime

from fastapi_passkeys.domain.models import (
    AuthenticationChallenge,
    Credential,
    RegistrationChallenge,
)
from fastapi_passkeys.services.clock import Clock, SystemClock


class InMemoryCredentialRepository:
    """Dict-backed :class:`CredentialRepository`, keyed by credential id."""

    def __init__(self) -> None:
        self._by_id: dict[bytes, Credential] = {}

    async def add(self, credential: Credential) -> None:
        self._by_id[credential.credential_id] = credential

    async def get_by_credential_id(self, credential_id: bytes) -> Credential | None:
        return self._by_id.get(credential_id)

    async def list_by_user(self, user_id: str) -> list[Credential]:
        return [c for c in self._by_id.values() if c.user_id == user_id]

    async def update_usage(
        self, credential_id: bytes, *, sign_count: int, last_used_at: datetime
    ) -> None:
        existing = self._by_id.get(credential_id)
        if existing is not None:
            self._by_id[credential_id] = dataclasses.replace(
                existing, sign_count=sign_count, last_used_at=last_used_at
            )

    async def rename(self, credential_id: bytes, user_id: str, name: str) -> None:
        existing = self._by_id.get(credential_id)
        if existing is not None and existing.user_id == user_id:
            self._by_id[credential_id] = dataclasses.replace(existing, device_name=name)

    async def delete(self, credential_id: bytes, user_id: str) -> None:
        existing = self._by_id.get(credential_id)
        if existing is not None and existing.user_id == user_id:
            del self._by_id[credential_id]


class InMemoryChallengeStore:
    """Dict-backed, genuinely single-use :class:`ChallengeStore`.

    ``consume`` pops the entry, so a replayed handle returns ``None``. Expiry is
    enforced against the injected clock.
    """

    def __init__(self, *, clock: Clock | None = None) -> None:
        self._clock = clock or SystemClock()
        self._store: dict[str, RegistrationChallenge | AuthenticationChallenge] = {}

    async def put(self, challenge: RegistrationChallenge | AuthenticationChallenge) -> str:
        handle = secrets.token_urlsafe(32)
        self._store[handle] = challenge
        return handle

    async def consume(self, handle: str) -> RegistrationChallenge | AuthenticationChallenge | None:
        challenge = self._store.pop(handle, None)
        if challenge is None:
            return None
        if self._clock.now() > challenge.expires_at:
            return None
        return challenge
