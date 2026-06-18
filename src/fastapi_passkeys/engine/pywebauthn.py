"""py_webauthn-backed :class:`WebAuthnEngine`.

This is the ONLY module in the package that imports ``webauthn``. If we ever need
to swap the backing library, this file is the blast radius.
"""

from __future__ import annotations

import json
import uuid
from typing import Any, cast

from webauthn import (
    generate_authentication_options,
    generate_registration_options,
    options_to_json,
    verify_authentication_response,
    verify_registration_response,
)
from webauthn.helpers.structs import (
    AttestationConveyancePreference,
    AuthenticatorAttachment,
    AuthenticatorSelectionCriteria,
    AuthenticatorTransport,
    PublicKeyCredentialDescriptor,
    ResidentKeyRequirement,
    UserVerificationRequirement,
)

from fastapi_passkeys.config import PasskeyConfig
from fastapi_passkeys.domain.enums import Transport
from fastapi_passkeys.domain.models import (
    Credential,
    PasskeyUser,
    VerifiedAuthentication,
    VerifiedRegistration,
)
from fastapi_passkeys.exceptions import (
    AssertionVerificationError,
    AttestationVerificationError,
)

_ZERO_AAGUID = uuid.UUID(int=0)


def _descriptors(credentials: list[Credential]) -> list[PublicKeyCredentialDescriptor]:
    return [
        PublicKeyCredentialDescriptor(
            id=cred.credential_id,
            transports=[AuthenticatorTransport(t.value) for t in cred.transports] or None,
        )
        for cred in credentials
    ]


def _as_dict(response: dict[str, Any] | str) -> dict[str, Any]:
    if isinstance(response, str):
        return cast("dict[str, Any]", json.loads(response))
    return response


def _transports_from(response: dict[str, Any] | str) -> tuple[Transport, ...]:
    data = _as_dict(response)
    raw = data.get("response", {}).get("transports") or []
    out: list[Transport] = []
    for item in raw:
        try:
            out.append(Transport(item))
        except ValueError:
            continue  # ignore transports we do not model
    return tuple(out)


def _aaguid_to_bytes(value: str | None) -> bytes | None:
    if not value:
        return None
    try:
        parsed = uuid.UUID(value)
    except (ValueError, AttributeError):
        return None
    return None if parsed == _ZERO_AAGUID else parsed.bytes


def _is_backed_up(result: Any) -> tuple[bool, bool]:
    device_type = getattr(result, "credential_device_type", None)
    eligible = str(getattr(device_type, "value", device_type)) == "multi_device"
    state = bool(getattr(result, "credential_backed_up", False))
    return eligible, state


class PyWebAuthnEngine:
    """Default engine implementation built on py_webauthn."""

    def registration_options(
        self,
        *,
        config: PasskeyConfig,
        user: PasskeyUser,
        challenge: bytes,
        exclude: list[Credential],
    ) -> dict[str, Any]:
        selection = AuthenticatorSelectionCriteria(
            authenticator_attachment=(
                AuthenticatorAttachment(config.authenticator_attachment.value)
                if config.authenticator_attachment is not None
                else None
            ),
            resident_key=ResidentKeyRequirement(config.resident_key.value),
            user_verification=UserVerificationRequirement(config.user_verification.value),
        )
        options = generate_registration_options(
            rp_id=config.rp_id,
            rp_name=config.rp_name,
            user_id=user.id.encode("utf-8"),
            user_name=user.name,
            user_display_name=user.display_name,
            attestation=AttestationConveyancePreference(config.attestation.value),
            authenticator_selection=selection,
            challenge=challenge,
            exclude_credentials=_descriptors(exclude),
            timeout=config.timeout_ms,
        )
        return cast("dict[str, Any]", json.loads(options_to_json(options)))

    def verify_registration(
        self,
        *,
        config: PasskeyConfig,
        response: dict[str, Any] | str,
        expected_challenge: bytes,
    ) -> VerifiedRegistration:
        try:
            result = verify_registration_response(
                credential=_as_dict(response),
                expected_challenge=expected_challenge,
                expected_rp_id=config.rp_id,
                expected_origin=config.expected_origins,
                require_user_verification=config.require_user_verification,
            )
        except Exception as exc:  # py_webauthn raises a family of validation errors
            raise AttestationVerificationError() from exc

        eligible, state = _is_backed_up(result)
        return VerifiedRegistration(
            credential_id=result.credential_id,
            public_key=result.credential_public_key,
            sign_count=result.sign_count,
            transports=_transports_from(response),
            aaguid=_aaguid_to_bytes(getattr(result, "aaguid", None)),
            backup_eligible=eligible,
            backup_state=state,
            attestation_fmt=str(getattr(getattr(result, "fmt", None), "value", "") or "") or None,
        )

    def authentication_options(
        self,
        *,
        config: PasskeyConfig,
        challenge: bytes,
        allow: list[Credential],
    ) -> dict[str, Any]:
        options = generate_authentication_options(
            rp_id=config.rp_id,
            challenge=challenge,
            timeout=config.timeout_ms,
            allow_credentials=_descriptors(allow) or None,
            user_verification=UserVerificationRequirement(config.user_verification.value),
        )
        return cast("dict[str, Any]", json.loads(options_to_json(options)))

    def verify_authentication(
        self,
        *,
        config: PasskeyConfig,
        response: dict[str, Any] | str,
        expected_challenge: bytes,
        credential: Credential,
    ) -> VerifiedAuthentication:
        try:
            result = verify_authentication_response(
                credential=_as_dict(response),
                expected_challenge=expected_challenge,
                expected_rp_id=config.rp_id,
                expected_origin=config.expected_origins,
                credential_public_key=credential.public_key,
                # Pass 0 to disable py_webauthn's own counter check: clone detection
                # is owned by AuthenticationService so we control the policy, the
                # typed error, and the audit event. See _enforce_sign_count.
                credential_current_sign_count=0,
                require_user_verification=config.require_user_verification,
            )
        except Exception as exc:
            raise AssertionVerificationError() from exc

        return VerifiedAuthentication(
            credential_id=result.credential_id,
            new_sign_count=result.new_sign_count,
            user_verified=bool(getattr(result, "user_verified", config.require_user_verification)),
        )
