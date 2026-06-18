"""Injectable time source.

Services never call :func:`datetime.now` directly; they take a :class:`Clock`.
This makes challenge-expiry and ``last_used_at`` logic deterministic in tests
(see ``FrozenClock`` in :mod:`fastapi_passkeys.testing`).
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Protocol, runtime_checkable


@runtime_checkable
class Clock(Protocol):
    """Returns the current time as a timezone-aware UTC ``datetime``."""

    def now(self) -> datetime: ...


class SystemClock:
    """Default clock backed by the system wall clock (UTC)."""

    def now(self) -> datetime:
        return datetime.now(timezone.utc)
