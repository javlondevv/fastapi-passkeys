"""Stateless, HMAC-signed challenge store.

The handle *is* the challenge: a signed token carrying the challenge and its
expiry. No shared server-side storage, so it scales horizontally with zero
infrastructure.

Tradeoff — read this: a signed token cannot be marked "used" without state.
This store therefore keeps a small **per-process** record of consumed tokens
until they expire, which makes it single-use within one process. It does *not*
make it single-use across several processes or hosts: a captured
``{state, credential}`` pair can be replayed against a *different* instance
until the token expires. The signature-counter check does not close that gap
for synced passkeys (iCloud Keychain, Google Password Manager, …), which always
report a counter of 0. For horizontally scaled deployments use
:class:`fastapi_passkeys.contrib.redis.RedisChallengeStore`.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import logging
from collections import OrderedDict
from datetime import datetime
from typing import Any

from fastapi_passkeys._b64 import b64url_to_bytes, bytes_to_b64url
from fastapi_passkeys.contrib._codec import challenge_to_payload, payload_to_challenge
from fastapi_passkeys.domain.models import AuthenticationChallenge, RegistrationChallenge
from fastapi_passkeys.exceptions import ConfigurationError
from fastapi_passkeys.services.clock import Clock, SystemClock

_log = logging.getLogger("fastapi_passkeys.stateless")


def _sign(body: bytes, secret: bytes) -> bytes:
    return hmac.new(secret, body, hashlib.sha256).digest()


class StatelessChallengeStore:
    """Signed-token :class:`ChallengeStore`. See module docstring for the tradeoff."""

    def __init__(
        self,
        secret: str | bytes,
        *,
        clock: Clock | None = None,
        max_consumed: int = 100_000,
    ) -> None:
        if not secret:
            raise ConfigurationError("StatelessChallengeStore requires a non-empty secret")
        self._secret = secret.encode("utf-8") if isinstance(secret, str) else secret
        self._clock = clock or SystemClock()
        self._max_consumed = max_consumed
        # signature -> token expiry; replay guard for this process only. Bounded
        # by ``max_consumed`` live records; when full, consume() refuses tokens.
        self._consumed: OrderedDict[bytes, datetime] = OrderedDict()

    async def put(self, challenge: RegistrationChallenge | AuthenticationChallenge) -> str:
        payload = challenge_to_payload(challenge)
        body = json.dumps(payload, separators=(",", ":"), sort_keys=True).encode("utf-8")
        return f"{bytes_to_b64url(body)}.{bytes_to_b64url(_sign(body, self._secret))}"

    async def consume(self, handle: str) -> RegistrationChallenge | AuthenticationChallenge | None:
        verified = self._verify(handle)
        if verified is None:
            return None
        payload, signature = verified
        challenge = payload_to_challenge(payload)
        now = self._clock.now()
        if challenge is None or now > challenge.expires_at:
            return None
        self._forget_expired(now)
        if signature in self._consumed:
            return None
        if len(self._consumed) >= self._max_consumed:
            # Fail closed. Evicting a live record would let a flood of fresh
            # tokens push out a captured one and re-open replay; refusing new
            # ceremonies until records expire is the safe failure mode. Sustained
            # hits mean a flood: rate-limit the endpoints or move to Redis.
            _log.warning(
                "stateless challenge replay guard is full (%d live records); refusing "
                "new ceremonies until records expire",
                self._max_consumed,
            )
            return None
        self._consumed[signature] = challenge.expires_at
        return challenge

    def _forget_expired(self, now: datetime) -> None:
        while self._consumed:
            expires_at = next(iter(self._consumed.values()))
            if now <= expires_at:
                break
            self._consumed.popitem(last=False)

    def _verify(self, handle: str) -> tuple[dict[str, Any], bytes] | None:
        try:
            body_part, sig_part = handle.split(".", 1)
            body = b64url_to_bytes(body_part)
            signature = b64url_to_bytes(sig_part)
        except (ValueError, AttributeError):
            return None
        if not hmac.compare_digest(signature, _sign(body, self._secret)):
            return None
        try:
            decoded = json.loads(body)
        except (json.JSONDecodeError, UnicodeDecodeError):
            return None
        if not isinstance(decoded, dict):
            return None
        return decoded, signature
