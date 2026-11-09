"""In-memory storage backends.

Bundled in core (no extras) so the library works out of the box and powers the
test suite. Both are single-process only — fine for development, tests, and
single-instance deployments, but use :mod:`fastapi_passkeys.contrib.sqlalchemy`
and :mod:`fastapi_passkeys.contrib.redis` for anything horizontally scaled.
"""

from __future__ import annotations

import dataclasses
import secrets
from collections import OrderedDict
from datetime import datetime

from fastapi_passkeys.domain.models import (
    AuthenticationChallenge,
    Credential,
    RegistrationChallenge,
)
from fastapi_passkeys.exceptions import CredentialAlreadyExists
from fastapi_passkeys.services.clock import Clock, SystemClock


class InMemoryCredentialRepository:
    """Dict-backed :class:`CredentialRepository`, keyed by credential id."""

    def __init__(self) -> None:
        self._by_id: dict[bytes, Credential] = {}

    async def add(self, credential: Credential) -> None:
        if credential.credential_id in self._by_id:
            raise CredentialAlreadyExists()
        self._by_id[credential.credential_id] = credential

    async def get_by_credential_id(self, credential_id: bytes) -> Credential | None:
        return self._by_id.get(credential_id)

    async def list_by_user(self, user_id: str) -> list[Credential]:
        return [c for c in self._by_id.values() if c.user_id == user_id]

    async def update_usage(
        self,
        credential_id: bytes,
        *,
        sign_count: int,
        last_used_at: datetime,
        backup_state: bool | None = None,
    ) -> None:
        existing = self._by_id.get(credential_id)
        if existing is not None:
            self._by_id[credential_id] = dataclasses.replace(
                existing,
                sign_count=sign_count,
                last_used_at=last_used_at,
                backup_state=existing.backup_state if backup_state is None else backup_state,
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

    ``begin`` endpoints are usually unauthenticated, so abandoned ceremonies must
    not accumulate forever: expired entries are evicted on every ``put`` and the
    number of live challenges is capped at ``max_entries`` (oldest evicted first).
    """

    def __init__(self, *, clock: Clock | None = None, max_entries: int = 100_000) -> None:
        if max_entries < 1:
            raise ValueError("max_entries must be at least 1")
        self._clock = clock or SystemClock()
        self._max_entries = max_entries
        self._store: OrderedDict[str, RegistrationChallenge | AuthenticationChallenge] = (
            OrderedDict()
        )

    def __len__(self) -> int:
        return len(self._store)

    async def put(self, challenge: RegistrationChallenge | AuthenticationChallenge) -> str:
        self._evict()
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

    def _evict(self) -> None:
        now = self._clock.now()
        # Insertion order ~ expiry order (one TTL per config), so expired entries
        # cluster at the front; stop at the first live one.
        while self._store:
            oldest = next(iter(self._store.values()))
            if now <= oldest.expires_at:
                break
            self._store.popitem(last=False)
        while len(self._store) >= self._max_entries:
            self._store.popitem(last=False)
