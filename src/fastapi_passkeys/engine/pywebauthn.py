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

from fastapi_passkeys._b64 import b64url_to_bytes
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
    data = json.loads(response) if isinstance(response, str) else response
    return data if isinstance(data, dict) else {}


def _transports_from(data: dict[str, Any]) -> tuple[Transport, ...]:
    inner = data.get("response")
    raw = inner.get("transports") if isinstance(inner, dict) else None
    out: list[Transport] = []
    for item in raw if isinstance(raw, list) else []:
        try:
            transport = Transport(item)
        except ValueError:
            continue  # ignore transports we do not model
        if transport not in out:
            out.append(transport)
    return tuple(out)


def _cred_props_rk(data: dict[str, Any]) -> bool | None:
    """``clientExtensionResults.credProps.rk``: did the client create a discoverable key?"""
    results = data.get("clientExtensionResults")
    props = results.get("credProps") if isinstance(results, dict) else None
    rk = props.get("rk") if isinstance(props, dict) else None
    return rk if isinstance(rk, bool) else None


_FLAG_UV = 0x04


def _uv_flag(data: dict[str, Any]) -> bool:
    """Read the UV bit from ``authenticatorData`` (byte 32).

    Only called *after* py_webauthn verified the signature over that data, so
    the flags are authentic. Needed because py_webauthn releases before 2.5.0 do
    not expose ``user_verified`` on authentication results.
    """
    inner = data.get("response")
    raw = inner.get("authenticatorData") if isinstance(inner, dict) else None
    try:
        auth_data = b64url_to_bytes(raw) if isinstance(raw, str) else b""
    except ValueError:
        return False
    return len(auth_data) > 32 and bool(auth_data[32] & _FLAG_UV)


def _with_l3_options(options: dict[str, Any], config: PasskeyConfig) -> dict[str, Any]:
    if config.hints:
        options["hints"] = [h.value for h in config.hints]
    return options


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
        data = cast("dict[str, Any]", json.loads(options_to_json(options)))
        # Ask the client to report whether it made a discoverable credential, so
        # ``Credential.is_discoverable`` reflects reality under resident_key=preferred.
        data.setdefault("extensions", {})["credProps"] = True
        return _with_l3_options(data, config)

    def verify_registration(
        self,
        *,
        config: PasskeyConfig,
        response: dict[str, Any] | str,
        expected_challenge: bytes,
    ) -> VerifiedRegistration:
        data = _as_dict(response)
        try:
            result = verify_registration_response(
                credential=data,
                expected_challenge=expected_challenge,
                expected_rp_id=config.rp_id,
                expected_origin=config.allowed_origins,
                require_user_verification=config.require_user_verification,
            )
        except Exception as exc:  # py_webauthn raises a family of validation errors
            raise AttestationVerificationError() from exc

        eligible, state = _is_backed_up(result)
        return VerifiedRegistration(
            credential_id=result.credential_id,
            public_key=result.credential_public_key,
            sign_count=result.sign_count,
            transports=_transports_from(data),
            aaguid=_aaguid_to_bytes(getattr(result, "aaguid", None)),
            backup_eligible=eligible,
            backup_state=state,
            is_discoverable=_cred_props_rk(data),
            attestation_fmt=str(getattr(getattr(result, "fmt", None), "value", "") or "") or None,
            user_verified=bool(getattr(result, "user_verified", False)),
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
        data = cast("dict[str, Any]", json.loads(options_to_json(options)))
        return _with_l3_options(data, config)

    def verify_authentication(
        self,
        *,
        config: PasskeyConfig,
        response: dict[str, Any] | str,
        expected_challenge: bytes,
        credential: Credential,
    ) -> VerifiedAuthentication:
        data = _as_dict(response)
        try:
            result = verify_authentication_response(
                credential=data,
                expected_challenge=expected_challenge,
                expected_rp_id=config.rp_id,
                expected_origin=config.allowed_origins,
                credential_public_key=credential.public_key,
                # Pass 0 to disable py_webauthn's own counter check: clone detection
                # is owned by AuthenticationService so we control the policy, the
                # typed error, and the audit event. See _enforce_sign_count.
                credential_current_sign_count=0,
                require_user_verification=config.require_user_verification,
            )
        except Exception as exc:
            raise AssertionVerificationError() from exc

        eligible, state = _is_backed_up(result)
        return VerifiedAuthentication(
            credential_id=result.credential_id,
            new_sign_count=result.new_sign_count,
            user_verified=bool(getattr(result, "user_verified", None) or _uv_flag(data)),
            backup_eligible=eligible,
            backup_state=state,
        )
