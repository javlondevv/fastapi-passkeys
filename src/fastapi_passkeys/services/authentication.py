"""Authentication ceremony orchestration, including clone detection."""

from __future__ import annotations

import dataclasses
import inspect
import json
import secrets
from typing import Any

from fastapi_passkeys._b64 import b64url_to_bytes, bytes_to_b64url
from fastapi_passkeys.audit import (
    AuditEvent,
    AuditEventType,
    AuditSink,
    NullAuditSink,
    emit_safely,
)
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
    AssertionVerificationError,
    ChallengeNotFound,
    CloneDetectedError,
    CredentialNotFound,
    PasskeyError,
)
from fastapi_passkeys.repositories.challenges import ChallengeStore
from fastapi_passkeys.repositories.credentials import CredentialRepository
from fastapi_passkeys.services.clock import Clock, SystemClock
from fastapi_passkeys.services.registration import user_handle

_CHALLENGE_BYTES = 32
_ATTACHMENTS = frozenset({"platform", "cross-platform"})


def _accepts_kwarg(func: Any, name: str) -> bool:
    try:
        params = inspect.signature(func).parameters
    except (TypeError, ValueError):
        return False
    return name in params or any(p.kind is p.VAR_KEYWORD for p in params.values())


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
        # Repositories written against 0.1 have no ``backup_state`` parameter.
        self._persist_backup_state = _accepts_kwarg(credentials.update_usage, "backup_state")

    async def begin(self, *, user_id: str | None = None) -> tuple[dict[str, Any], str]:
        """Issue request options and a challenge handle.

        Pass ``user_id`` for a username-first flow (restricts allowed credentials)
        or omit it for a usernameless / discoverable-credential flow.
        """
        user_id = user_id or None
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
        await self._emit(AuditEventType.AUTHENTICATION_BEGAN, user_id=user_id)
        return options, handle

    async def finish(self, *, response: dict[str, Any] | str, handle: str) -> AuthenticationResult:
        """Verify the assertion, enforce the signature counter, and record usage."""
        stored = await self._challenges.consume(handle)
        if not isinstance(stored, AuthenticationChallenge):
            await self._emit(AuditEventType.CHALLENGE_EXPIRED)
            raise ChallengeNotFound()

        data = _as_dict(response)
        credential = await self._resolve_credential(data, stored)
        cred_b64 = bytes_to_b64url(credential.credential_id)

        try:
            verified = self._engine.verify_authentication(
                config=self._config,
                response=response,
                expected_challenge=stored.challenge,
                credential=credential,
            )
            if verified.credential_id != credential.credential_id:
                raise AssertionVerificationError()
            self._check_backup_eligibility(credential, verified)
        except PasskeyError as exc:
            await self._emit(
                AuditEventType.AUTHENTICATION_FAILED,
                user_id=credential.user_id,
                credential_id=cred_b64,
                reason=exc.code,
            )
            raise

        await self._enforce_sign_count(credential, verified)

        now = self._clock.now()
        backup_state = (
            verified.backup_state if verified.backup_state is not None else credential.backup_state
        )
        if self._persist_backup_state:
            await self._credentials.update_usage(
                credential.credential_id,
                sign_count=verified.new_sign_count,
                last_used_at=now,
                backup_state=backup_state,
            )
        else:
            await self._credentials.update_usage(
                credential.credential_id, sign_count=verified.new_sign_count, last_used_at=now
            )
        await self._emit(
            AuditEventType.AUTHENTICATION_SUCCEEDED,
            user_id=credential.user_id,
            credential_id=cred_b64,
        )
        updated = dataclasses.replace(
            credential,
            sign_count=verified.new_sign_count,
            last_used_at=now,
            backup_state=backup_state,
        )
        attachment = data.get("authenticatorAttachment")
        return AuthenticationResult(
            user_id=credential.user_id,
            credential=updated,
            detail={
                "user_verified": verified.user_verified,
                # Flags as presented by *this* assertion.
                "backup_eligible": (
                    verified.backup_eligible
                    if verified.backup_eligible is not None
                    else credential.backup_eligible
                ),
                "backup_state": backup_state,
                "authenticator_attachment": attachment if attachment in _ATTACHMENTS else None,
            },
        )

    async def _resolve_credential(
        self, data: dict[str, Any], stored: AuthenticationChallenge
    ) -> Credential:
        credential_id = _b64_field(data.get("rawId") or data.get("id"))
        credential = (
            await self._credentials.get_by_credential_id(credential_id) if credential_id else None
        )
        if credential is None:
            await self._emit(AuditEventType.AUTHENTICATION_FAILED, user_id=stored.user_id)
            error = CredentialNotFound()
            if credential_id:
                # Lets the browser prune a passkey we no longer know about
                # (PublicKeyCredential.signalUnknownCredential).
                error.extra["signal"] = {
                    "unknownCredential": {
                        "rpId": self._config.rp_id,
                        "credentialId": bytes_to_b64url(credential_id),
                    }
                }
            raise error

        if not self._owner_matches(credential, data, stored):
            # Same generic error as "unknown" so we do not leak which check failed.
            await self._emit(
                AuditEventType.AUTHENTICATION_FAILED,
                user_id=stored.user_id,
                credential_id=bytes_to_b64url(credential.credential_id),
                reason="owner_mismatch",
            )
            raise CredentialNotFound()
        return credential

    def _owner_matches(
        self, credential: Credential, data: dict[str, Any], stored: AuthenticationChallenge
    ) -> bool:
        """WebAuthn §7.2 step 6: the credential must belong to the identified user."""
        if stored.user_id is not None and credential.user_id != stored.user_id:
            return False
        if not self._config.verify_user_handle:
            return True
        inner = data.get("response")
        raw_handle = inner.get("userHandle") if isinstance(inner, dict) else None
        if raw_handle is None:
            # Optional only when the user was identified before the ceremony.
            return stored.user_id is not None
        return _b64_field(raw_handle) == user_handle(credential.user_id)

    def _check_backup_eligibility(
        self, credential: Credential, verified: VerifiedAuthentication
    ) -> None:
        if (
            self._config.enforce_backup_eligibility
            and verified.backup_eligible is not None
            and verified.backup_eligible != credential.backup_eligible
        ):
            # BE is fixed for a credential's lifetime (WebAuthn §6.1.3); a change
            # means a different or misbehaving authenticator.
            raise AssertionVerificationError()

    async def _enforce_sign_count(
        self, credential: Credential, verified: VerifiedAuthentication
    ) -> None:
        old, new = credential.sign_count, verified.new_sign_count
        # Counter of 0 on both sides means the authenticator does not implement one.
        if new == 0 and old == 0:
            return
        if new > old:
            return
        cred_b64 = bytes_to_b64url(credential.credential_id)
        await emit_safely(
            self._audit,
            AuditEvent(
                type=AuditEventType.CLONE_SUSPECTED,
                timestamp=self._clock.now(),
                user_id=credential.user_id,
                credential_id=cred_b64,
                detail={
                    "stored_sign_count": old,
                    "presented_sign_count": new,
                    "policy": self._config.sign_count_policy.value,
                },
            ),
        )
        policy = self._config.sign_count_policy
        if policy is SignCountPolicy.AUDIT_ONLY:
            return
        if policy is SignCountPolicy.FLAG_DISABLE:
            await self._credentials.delete(credential.credential_id, credential.user_id)
            await self._emit(
                AuditEventType.CREDENTIAL_REVOKED,
                user_id=credential.user_id,
                credential_id=cred_b64,
                reason="clone_suspected",
            )
        raise CloneDetectedError()

    async def _emit(
        self,
        event_type: AuditEventType,
        *,
        user_id: str | None = None,
        credential_id: str | None = None,
        reason: str | None = None,
    ) -> None:
        await emit_safely(
            self._audit,
            AuditEvent(
                type=event_type,
                timestamp=self._clock.now(),
                user_id=user_id,
                credential_id=credential_id,
                detail={"reason": reason} if reason else {},
            ),
        )


def _as_dict(response: dict[str, Any] | str) -> dict[str, Any]:
    try:
        data = json.loads(response) if isinstance(response, str) else response
    except json.JSONDecodeError:
        return {}
    return data if isinstance(data, dict) else {}


def _b64_field(value: Any) -> bytes | None:
    if not isinstance(value, str):
        return None
    try:
        return b64url_to_bytes(value)
    except ValueError:
        return None
