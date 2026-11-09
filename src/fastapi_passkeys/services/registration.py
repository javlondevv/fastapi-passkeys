"""Registration ceremony orchestration."""

from __future__ import annotations

import dataclasses
import secrets
from typing import Any

from fastapi_passkeys._b64 import bytes_to_b64url
from fastapi_passkeys.audit import (
    AuditEvent,
    AuditEventType,
    AuditSink,
    NullAuditSink,
    emit_safely,
)
from fastapi_passkeys.config import PasskeyConfig
from fastapi_passkeys.domain.enums import ResidentKeyRequirement
from fastapi_passkeys.domain.models import Credential, PasskeyUser, RegistrationChallenge
from fastapi_passkeys.engine.base import WebAuthnEngine
from fastapi_passkeys.exceptions import (
    ChallengeNotFound,
    ConfigurationError,
    CredentialAlreadyExists,
    CredentialLimitReached,
    PasskeyError,
    RegistrationUserMismatch,
)
from fastapi_passkeys.repositories.challenges import ChallengeStore
from fastapi_passkeys.repositories.credentials import CredentialRepository
from fastapi_passkeys.services.clock import Clock, SystemClock

_CHALLENGE_BYTES = 32
_MAX_USER_HANDLE_BYTES = 64  # WebAuthn §5.4.3


def user_handle(user_id: str) -> bytes:
    """The WebAuthn user handle for ``user_id`` (its UTF-8 bytes)."""
    return user_id.encode("utf-8")


def _validated(user: PasskeyUser) -> PasskeyUser:
    handle = user_handle(user.id)
    if not handle or len(handle) > _MAX_USER_HANDLE_BYTES:
        raise ConfigurationError(
            "PasskeyUser.id must be 1-64 bytes when UTF-8 encoded (it becomes the WebAuthn "
            "user handle). Use an opaque id such as a UUID, never an email address."
        )
    if not user.name.strip():
        raise ConfigurationError("PasskeyUser.name must not be empty.")
    if not user.display_name.strip():
        # Some authenticators (e.g. 1Password) refuse an empty displayName.
        return dataclasses.replace(user, display_name=user.name)
    return user


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
        user = _validated(user)
        existing = await self._credentials.list_by_user(user.id)
        self._check_limit(existing)
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
        await emit_safely(
            self._audit,
            AuditEvent(type=AuditEventType.REGISTRATION_BEGAN, timestamp=now, user_id=user.id),
        )
        return options, handle

    async def finish(
        self,
        *,
        response: dict[str, Any] | str,
        handle: str,
        device_name: str = "",
        user: PasskeyUser | None = None,
    ) -> Credential:
        """Verify the attestation response and persist the new credential.

        Pass ``user`` — the user authenticated on *this* request — to bind the
        ceremony to them: a handle issued to someone else is rejected. The
        bundled router always does this. Without it, anyone holding a valid
        handle can attach their own authenticator to the account it was issued
        for.
        """
        stored = await self._challenges.consume(handle)
        if not isinstance(stored, RegistrationChallenge):
            await self._fail(AuditEventType.CHALLENGE_EXPIRED, user_id=None)
            raise ChallengeNotFound()

        try:
            if user is not None and user.id != stored.user.id:
                raise RegistrationUserMismatch()
            verified = self._engine.verify_registration(
                config=self._config, response=response, expected_challenge=stored.challenge
            )
            if await self._credentials.get_by_credential_id(verified.credential_id) is not None:
                raise CredentialAlreadyExists()
            self._check_limit(await self._credentials.list_by_user(stored.user.id))

            now = self._clock.now()
            discoverable = verified.is_discoverable
            if discoverable is None:  # client did not report credProps
                discoverable = self._config.resident_key is ResidentKeyRequirement.REQUIRED
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
                is_discoverable=discoverable,
                attestation_fmt=verified.attestation_fmt,
                created_at=now,
                last_used_at=None,
            )
            # Repositories raise CredentialAlreadyExists on a concurrent duplicate.
            await self._credentials.add(credential)
        except PasskeyError as exc:
            await self._fail(
                AuditEventType.REGISTRATION_FAILED, user_id=stored.user.id, reason=exc.code
            )
            raise

        await emit_safely(
            self._audit,
            AuditEvent(
                type=AuditEventType.REGISTRATION_SUCCEEDED,
                timestamp=now,
                user_id=stored.user.id,
                credential_id=bytes_to_b64url(verified.credential_id),
            ),
        )
        return credential

    def _check_limit(self, existing: list[Credential]) -> None:
        limit = self._config.max_credentials_per_user
        if limit is not None and len(existing) >= limit:
            raise CredentialLimitReached()

    async def _fail(
        self, event_type: AuditEventType, *, user_id: str | None, reason: str | None = None
    ) -> None:
        await emit_safely(
            self._audit,
            AuditEvent(
                type=event_type,
                timestamp=self._clock.now(),
                user_id=user_id,
                detail={"reason": reason} if reason else {},
            ),
        )
