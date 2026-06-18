"""Deterministic clock for tests."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone


class FrozenClock:
    """A controllable :class:`Clock` whose time only moves when you advance it."""

    def __init__(self, start: datetime | None = None) -> None:
        self._now = start or datetime(2026, 1, 1, tzinfo=timezone.utc)

    def now(self) -> datetime:
        return self._now

    def advance(self, delta: timedelta) -> None:
        self._now += delta
