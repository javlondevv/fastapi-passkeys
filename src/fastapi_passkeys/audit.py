"""Structured audit events.

Security-relevant outcomes are emitted as :class:`AuditEvent` to a pluggable
:class:`AuditSink`. Events never contain secrets, public keys, or raw challenges
— only identifiers and outcome metadata safe to log and retain.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Any, Protocol, runtime_checkable


class AuditEventType(str, Enum):
    REGISTRATION_BEGAN = "registration_began"
    REGISTRATION_SUCCEEDED = "registration_succeeded"
    REGISTRATION_FAILED = "registration_failed"
    AUTHENTICATION_BEGAN = "authentication_began"
    AUTHENTICATION_SUCCEEDED = "authentication_succeeded"
    AUTHENTICATION_FAILED = "authentication_failed"
    CHALLENGE_EXPIRED = "challenge_expired"
    CLONE_SUSPECTED = "clone_suspected"
    CREDENTIAL_REVOKED = "credential_revoked"


@dataclass(frozen=True, slots=True)
class AuditEvent:
    type: AuditEventType
    timestamp: datetime
    user_id: str | None = None
    credential_id: str | None = None  # base64url, never raw bytes
    detail: dict[str, Any] = field(default_factory=dict)


@runtime_checkable
class AuditSink(Protocol):
    """Receives audit events. Implementations must not raise on the hot path."""

    async def emit(self, event: AuditEvent) -> None: ...


class NullAuditSink:
    """Default sink that discards events."""

    async def emit(self, event: AuditEvent) -> None:
        return None


class LoggingAuditSink:
    """Emits events to the standard library logger ``fastapi_passkeys.audit``."""

    def __init__(self, logger_name: str = "fastapi_passkeys.audit") -> None:
        import logging

        self._log = logging.getLogger(logger_name)

    async def emit(self, event: AuditEvent) -> None:
        self._log.info(
            "%s user=%s credential=%s detail=%s",
            event.type.value,
            event.user_id,
            event.credential_id,
            event.detail,
        )
