"""Stateless, HMAC-signed challenge store.

The handle *is* the challenge: a signed token carrying the challenge and its
expiry. No server-side storage, so it scales horizontally with zero shared
infrastructure.

Tradeoff — read this: a purely stateless token cannot be marked "used" without
state, so a captured handle is technically replayable until it expires. That
window is closed by the *next* layer in both ceremonies: a replayed assertion
fails the monotonic ``sign_count`` check (clone detection), and a replayed
attestation fails the duplicate-credential check. Keep ``challenge_ttl`` short.
If you require strict single-use at the challenge layer, use
:class:`fastapi_passkeys.contrib.redis.RedisChallengeStore` or the in-memory
store instead.
"""

from __future__ import annotations

import hashlib
import hmac
import json
from typing import Any

from fastapi_passkeys._b64 import b64url_to_bytes, bytes_to_b64url
from fastapi_passkeys.contrib._codec import challenge_to_payload, payload_to_challenge
from fastapi_passkeys.domain.models import AuthenticationChallenge, RegistrationChallenge
from fastapi_passkeys.exceptions import ConfigurationError
from fastapi_passkeys.services.clock import Clock, SystemClock


def _sign(body: bytes, secret: bytes) -> bytes:
    return hmac.new(secret, body, hashlib.sha256).digest()


class StatelessChallengeStore:
    """Signed-token :class:`ChallengeStore`. See module docstring for the tradeoff."""

    def __init__(self, secret: str | bytes, *, clock: Clock | None = None) -> None:
        if not secret:
            raise ConfigurationError("StatelessChallengeStore requires a non-empty secret")
        self._secret = secret.encode("utf-8") if isinstance(secret, str) else secret
        self._clock = clock or SystemClock()

    async def put(self, challenge: RegistrationChallenge | AuthenticationChallenge) -> str:
        payload = challenge_to_payload(challenge)
        body = json.dumps(payload, separators=(",", ":"), sort_keys=True).encode("utf-8")
        return f"{bytes_to_b64url(body)}.{bytes_to_b64url(_sign(body, self._secret))}"

    async def consume(self, handle: str) -> RegistrationChallenge | AuthenticationChallenge | None:
        payload = self._verify(handle)
        if payload is None:
            return None
        challenge = payload_to_challenge(payload)
        if challenge is None or self._clock.now() > challenge.expires_at:
            return None
        return challenge

    def _verify(self, handle: str) -> dict[str, Any] | None:
        try:
            body_part, sig_part = handle.split(".", 1)
            body = b64url_to_bytes(body_part)
            signature = b64url_to_bytes(sig_part)
        except (ValueError, AttributeError):
            return None
        if not hmac.compare_digest(signature, _sign(body, self._secret)):
            return None
        try:
            decoded: dict[str, Any] = json.loads(body)
        except json.JSONDecodeError:
            return None
        return decoded
