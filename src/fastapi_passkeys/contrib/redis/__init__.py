"""Redis-backed challenge store.

Requires the ``[redis]`` extra and ``redis>=6.2`` (for ``GETDEL``). Gives strict,
atomic single-use across processes: ``consume`` fetches and deletes in one
command, so a replayed handle returns ``None``. Expiry is handled by the Redis
key TTL.

    from redis.asyncio import Redis
    from fastapi_passkeys.contrib.redis import RedisChallengeStore

    store = RedisChallengeStore(Redis.from_url("redis://localhost:6379/0"))
"""

from __future__ import annotations

import json
import secrets
from typing import Any, cast

from redis.asyncio import Redis

from fastapi_passkeys.contrib._codec import challenge_to_payload, payload_to_challenge
from fastapi_passkeys.domain.models import AuthenticationChallenge, RegistrationChallenge
from fastapi_passkeys.services.clock import Clock, SystemClock


class RedisChallengeStore:
    """Atomic single-use :class:`ChallengeStore` backed by Redis."""

    def __init__(
        self,
        client: Redis,
        *,
        clock: Clock | None = None,
        key_prefix: str = "fastapi-passkeys:challenge:",
    ) -> None:
        self._client = client
        self._clock = clock or SystemClock()
        self._prefix = key_prefix

    async def put(self, challenge: RegistrationChallenge | AuthenticationChallenge) -> str:
        handle = secrets.token_urlsafe(32)
        payload = challenge_to_payload(challenge)
        ttl = max(1, int((challenge.expires_at - self._clock.now()).total_seconds()))
        await self._client.set(self._prefix + handle, json.dumps(payload), ex=ttl)
        return handle

    async def consume(self, handle: str) -> RegistrationChallenge | AuthenticationChallenge | None:
        raw = await cast("Any", self._client).getdel(self._prefix + handle)
        if raw is None:
            return None
        if isinstance(raw, bytes):
            raw = raw.decode("utf-8")
        try:
            payload: dict[str, Any] = json.loads(raw)
        except (json.JSONDecodeError, TypeError):
            return None
        challenge = payload_to_challenge(payload)
        if challenge is None or self._clock.now() > challenge.expires_at:
            return None
        return challenge


__all__ = ["RedisChallengeStore"]
