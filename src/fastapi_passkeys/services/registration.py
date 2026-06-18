"""Registration ceremony orchestration."""

from __future__ import annotations

import secrets
from typing import Any

from fastapi_passkeys._b64 import bytes_to_b64url
from fastapi_passkeys.audit import AuditEvent, AuditEventType, AuditSink, NullAuditSink
from fastapi_passkeys.config import PasskeyConfig
from fastapi_passkeys.domain.enums import ResidentKeyRequirement
from fastapi_passkeys.domain.models import Credential, PasskeyUser, RegistrationChallenge
from fastapi_passkeys.engine.base import WebAuthnEngine
from fastapi_passkeys.exceptions import (
    ChallengeNotFound,
    CredentialAlreadyExists,
    PasskeyError,
)
from fastapi_passkeys.repositories.challenges import ChallengeStore
from fastapi_passkeys.repositories.credentials import CredentialRepository
from fastapi_passkeys.services.clock import Clock, SystemClock

_CHALLENGE_BYTES = 32


class RegistrationService:
    """Begins and finishes passkey registration (attestation) ceremonies."""

    def __init__(
        self,
        *,
        config: PasskeyConfig,
        credentials: CredentialRepository,
        challenges: ChallengeStore,
        engine: WebAuthnEngine,
        clock: Clock | None = None,
        audit: AuditSink | None = None,
    ) -> None:
        self._config = config
        self._credentials = credentials
        self._challenges = challenges
        self._engine = engine
        self._clock = clock or SystemClock()
        self._audit = audit or NullAuditSink()

    async def begin(self, user: PasskeyUser) -> tuple[dict[str, Any], str]:
        """Issue creation options and a challenge handle the client echoes back."""
        existing = await self._credentials.list_by_user(user.id)
        challenge = secrets.token_bytes(_CHALLENGE_BYTES)
        now = self._clock.now()
        options = self._engine.registration_options(
            config=self._config, user=user, challenge=challenge, exclude=existing
        )
        handle = await self._challenges.put(
            RegistrationChallenge(
                challenge=challenge,
                user=user,
                created_at=now,
                expires_at=now + self._config.challenge_ttl,
            )
        )
        await self._audit.emit(
            AuditEvent(type=AuditEventType.REGISTRATION_BEGAN, timestamp=now, user_id=user.id)
        )
        return options, handle

    async def finish(
        self,
        *,
        response: dict[str, Any] | str,
        handle: str,
        device_name: str = "",
    ) -> Credential:
        """Verify the attestation response and persist the new credential."""
        stored = await self._challenges.consume(handle)
        if not isinstance(stored, RegistrationChallenge):
            await self._fail(AuditEventType.CHALLENGE_EXPIRED, user_id=None)
            raise ChallengeNotFound()

        try:
            verified = self._engine.verify_registration(
                config=self._config, response=response, expected_challenge=stored.challenge
            )
            if await self._credentials.get_by_credential_id(verified.credential_id) is not None:
                raise CredentialAlreadyExists()
        except PasskeyError:
            await self._fail(AuditEventType.REGISTRATION_FAILED, user_id=stored.user.id)
            raise

        now = self._clock.now()
        credential = Credential(
            credential_id=verified.credential_id,
            user_id=stored.user.id,
            public_key=verified.public_key,
            sign_count=verified.sign_count,
            transports=verified.transports,
            aaguid=verified.aaguid,
            backup_eligible=verified.backup_eligible,
            backup_state=verified.backup_state,
            device_name=device_name,
            is_discoverable=self._config.resident_key is ResidentKeyRequirement.REQUIRED,
            attestation_fmt=verified.attestation_fmt,
            created_at=now,
            last_used_at=None,
        )
        await self._credentials.add(credential)
        await self._audit.emit(
            AuditEvent(
                type=AuditEventType.REGISTRATION_SUCCEEDED,
                timestamp=now,
                user_id=stored.user.id,
                credential_id=bytes_to_b64url(verified.credential_id),
            )
        )
        return credential

    async def _fail(self, event_type: AuditEventType, *, user_id: str | None) -> None:
        await self._audit.emit(
            AuditEvent(type=event_type, timestamp=self._clock.now(), user_id=user_id)
        )
