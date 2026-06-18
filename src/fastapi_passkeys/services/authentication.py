"""Authentication ceremony orchestration, including clone detection."""

from __future__ import annotations

import dataclasses
import json
import secrets
from typing import Any

from fastapi_passkeys._b64 import b64url_to_bytes, bytes_to_b64url
from fastapi_passkeys.audit import AuditEvent, AuditEventType, AuditSink, NullAuditSink
from fastapi_passkeys.config import PasskeyConfig
from fastapi_passkeys.domain.enums import SignCountPolicy
from fastapi_passkeys.domain.models import (
    AuthenticationChallenge,
    AuthenticationResult,
    Credential,
    VerifiedAuthentication,
)
from fastapi_passkeys.engine.base import WebAuthnEngine
from fastapi_passkeys.exceptions import (
    ChallengeNotFound,
    CloneDetectedError,
    CredentialNotFound,
    PasskeyError,
)
from fastapi_passkeys.repositories.challenges import ChallengeStore
from fastapi_passkeys.repositories.credentials import CredentialRepository
from fastapi_passkeys.services.clock import Clock, SystemClock

_CHALLENGE_BYTES = 32


class AuthenticationService:
    """Begins and finishes passkey authentication (assertion) ceremonies."""

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

    async def begin(self, *, user_id: str | None = None) -> tuple[dict[str, Any], str]:
        """Issue request options and a challenge handle.

        Pass ``user_id`` for a username-first flow (restricts allowed credentials)
        or omit it for a usernameless / discoverable-credential flow.
        """
        allow = await self._credentials.list_by_user(user_id) if user_id else []
        challenge = secrets.token_bytes(_CHALLENGE_BYTES)
        now = self._clock.now()
        options = self._engine.authentication_options(
            config=self._config, challenge=challenge, allow=allow
        )
        handle = await self._challenges.put(
            AuthenticationChallenge(
                challenge=challenge,
                user_id=user_id,
                created_at=now,
                expires_at=now + self._config.challenge_ttl,
            )
        )
        await self._audit.emit(
            AuditEvent(type=AuditEventType.AUTHENTICATION_BEGAN, timestamp=now, user_id=user_id)
        )
        return options, handle

    async def finish(self, *, response: dict[str, Any] | str, handle: str) -> AuthenticationResult:
        """Verify the assertion, enforce the signature counter, and record usage."""
        stored = await self._challenges.consume(handle)
        if not isinstance(stored, AuthenticationChallenge):
            await self._fail(AuditEventType.CHALLENGE_EXPIRED, user_id=None)
            raise ChallengeNotFound()

        credential = await self._resolve_credential(response, stored)

        try:
            verified = self._engine.verify_authentication(
                config=self._config,
                response=response,
                expected_challenge=stored.challenge,
                credential=credential,
            )
        except PasskeyError:
            await self._fail(AuditEventType.AUTHENTICATION_FAILED, user_id=credential.user_id)
            raise

        await self._enforce_sign_count(credential, verified)

        now = self._clock.now()
        await self._credentials.update_usage(
            credential.credential_id, sign_count=verified.new_sign_count, last_used_at=now
        )
        await self._audit.emit(
            AuditEvent(
                type=AuditEventType.AUTHENTICATION_SUCCEEDED,
                timestamp=now,
                user_id=credential.user_id,
                credential_id=bytes_to_b64url(credential.credential_id),
            )
        )
        updated = dataclasses.replace(
            credential, sign_count=verified.new_sign_count, last_used_at=now
        )
        return AuthenticationResult(
            user_id=credential.user_id,
            credential=updated,
            detail={"user_verified": verified.user_verified},
        )

    async def _resolve_credential(
        self, response: dict[str, Any] | str, stored: AuthenticationChallenge
    ) -> Credential:
        credential_id = _credential_id_from(response)
        credential = (
            await self._credentials.get_by_credential_id(credential_id)
            if credential_id is not None
            else None
        )
        # When the ceremony was bound to a user, reject credentials owned by anyone
        # else — using the same generic error so we do not leak which check failed.
        if credential is None or (
            stored.user_id is not None and credential.user_id != stored.user_id
        ):
            await self._fail(AuditEventType.AUTHENTICATION_FAILED, user_id=stored.user_id)
            raise CredentialNotFound()
        return credential

    async def _enforce_sign_count(
        self, credential: Credential, verified: VerifiedAuthentication
    ) -> None:
        old, new = credential.sign_count, verified.new_sign_count
        # Counter of 0 on both sides means the authenticator does not implement one.
        if new == 0 and old == 0:
            return
        if new > old:
            return
        await self._audit.emit(
            AuditEvent(
                type=AuditEventType.CLONE_SUSPECTED,
                timestamp=self._clock.now(),
                user_id=credential.user_id,
                credential_id=bytes_to_b64url(credential.credential_id),
                detail={"stored_sign_count": old, "presented_sign_count": new},
            )
        )
        if self._config.sign_count_policy is SignCountPolicy.FLAG_DISABLE:
            await self._credentials.delete(credential.credential_id, credential.user_id)
        raise CloneDetectedError()

    async def _fail(self, event_type: AuditEventType, *, user_id: str | None) -> None:
        await self._audit.emit(
            AuditEvent(type=event_type, timestamp=self._clock.now(), user_id=user_id)
        )


def _credential_id_from(response: dict[str, Any] | str) -> bytes | None:
    data = json.loads(response) if isinstance(response, str) else response
    if not isinstance(data, dict):
        return None
    raw = data.get("rawId") or data.get("id")
    if not isinstance(raw, str):
        return None
    try:
        return b64url_to_bytes(raw)
    except (ValueError, TypeError):
        return None
