"""HTTP wire contract.

These Pydantic models are intentionally separate from the domain entities: they
are the public, versioned shape exchanged with browsers, using the camelCase
field names the WebAuthn JS API expects.

Every client-supplied string is length-bounded: the ``begin`` endpoints are
typically unauthenticated, and names end up in your database and UI.
"""

from __future__ import annotations

import unicodedata
import uuid
from datetime import datetime
from typing import Any

from pydantic import BaseModel, ConfigDict, Field, field_validator

from fastapi_passkeys._b64 import bytes_to_b64url
from fastapi_passkeys.domain.models import Credential

MAX_DEVICE_NAME = 64
MAX_STATE = 8192
MAX_USER_ID = 64


def _clean_name(value: str) -> str:
    """Strip and validate a user-supplied device name.

    Names are stored and returned verbatim (minus surrounding whitespace). They
    are user input — HTML-escape them wherever you render them.
    """
    value = value.strip()
    if len(value) > MAX_DEVICE_NAME:
        raise ValueError(f"device name must be at most {MAX_DEVICE_NAME} characters")
    if any(unicodedata.category(ch) in {"Cc", "Cf", "Zl", "Zp"} for ch in value):
        raise ValueError("device name must not contain control or format characters")
    return value


class _Schema(BaseModel):
    model_config = ConfigDict(populate_by_name=True)


class BeginResponse(_Schema):
    """Options for ``navigator.credentials`` plus the challenge handle to echo back."""

    public_key: dict[str, Any] = Field(alias="publicKey")
    state: str


class RegisterFinishRequest(_Schema):
    credential: dict[str, Any]
    state: str = Field(min_length=1, max_length=MAX_STATE)
    device_name: str = Field(default="", alias="deviceName", max_length=1024)

    @field_validator("device_name")
    @classmethod
    def _check_name(cls, value: str) -> str:
        return _clean_name(value)


class RegisterFinishResponse(_Schema):
    status: str = "ok"
    credential_id: str = Field(alias="credentialId")


class AuthBeginRequest(_Schema):
    user_id: str | None = Field(default=None, alias="userId", max_length=MAX_USER_ID)


class AuthFinishRequest(_Schema):
    credential: dict[str, Any]
    state: str = Field(min_length=1, max_length=MAX_STATE)


class RenameRequest(_Schema):
    device_name: str = Field(alias="deviceName", max_length=1024)

    @field_validator("device_name")
    @classmethod
    def _check_name(cls, value: str) -> str:
        value = _clean_name(value)
        if not value:
            raise ValueError("device name must not be empty")
        return value


class CredentialView(_Schema):
    """A sanitized credential for listing — never exposes the public key."""

    id: str
    device_name: str = Field(alias="deviceName")
    transports: list[str]
    aaguid: str | None = Field(
        default=None,
        description="Authenticator model id (UUID). Map it to a provider name/icon, e.g. "
        "with the FIDO Metadata Service.",
    )
    discoverable: bool | None = None
    backup_eligible: bool = Field(alias="backupEligible")
    backup_state: bool = Field(alias="backupState")
    created_at: datetime | None = Field(alias="createdAt")
    last_used_at: datetime | None = Field(alias="lastUsedAt")

    @classmethod
    def from_domain(cls, credential: Credential) -> CredentialView:
        return cls(
            id=bytes_to_b64url(credential.credential_id),
            deviceName=credential.device_name,
            transports=[t.value for t in credential.transports],
            aaguid=str(uuid.UUID(bytes=credential.aaguid)) if credential.aaguid else None,
            discoverable=credential.is_discoverable,
            backupEligible=credential.backup_eligible,
            backupState=credential.backup_state,
            createdAt=credential.created_at,
            lastUsedAt=credential.last_used_at,
        )


class SignalsResponse(_Schema):
    """Payloads for the WebAuthn Signal API, ready to pass to the browser.

    ``PublicKeyCredential.signalAllAcceptedCredentials(body.allAcceptedCredentials)``
    and ``PublicKeyCredential.signalCurrentUserDetails(body.currentUserDetails)``.
    """

    all_accepted_credentials: dict[str, Any] = Field(alias="allAcceptedCredentials")
    current_user_details: dict[str, Any] = Field(alias="currentUserDetails")
