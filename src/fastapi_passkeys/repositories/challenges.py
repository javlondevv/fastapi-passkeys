"""Challenge storage contract.

A challenge is issued at the start of a ceremony and must be redeemed exactly
once. ``consume`` is the security-critical operation: it must atomically return
*and* invalidate the challenge, so a replayed handle yields ``None`` the second
time. Implementations are also responsible for enforcing expiry.
"""

from __future__ import annotations

from typing import Protocol, runtime_checkable

from fastapi_passkeys.domain.models import AuthenticationChallenge, RegistrationChallenge


@runtime_checkable
class ChallengeStore(Protocol):
    """Single-use storage for in-flight ceremony challenges."""

    async def put(self, challenge: RegistrationChallenge | AuthenticationChallenge) -> str:
        """Store a challenge and return an opaque handle the client echoes back."""
        ...

    async def consume(self, handle: str) -> RegistrationChallenge | AuthenticationChallenge | None:
        """Atomically fetch and invalidate the challenge.

        Returns ``None`` if the handle is unknown, already consumed, expired, or
        tampered with. Never returns an expired challenge.
        """
        ...
