"""HTTP wire contract.

These Pydantic models are intentionally separate from the domain entities: they
are the public, versioned shape exchanged with browsers, using the camelCase
field names the WebAuthn JS API expects.
"""

from __future__ import annotations

from datetime import datetime
from typing import Any

from pydantic import BaseModel, ConfigDict, Field

from fastapi_passkeys._b64 import bytes_to_b64url
from fastapi_passkeys.domain.models import Credential


class _Schema(BaseModel):
    model_config = ConfigDict(populate_by_name=True)


class BeginResponse(_Schema):
    """Options for ``navigator.credentials`` plus the challenge handle to echo back."""

    public_key: dict[str, Any] = Field(alias="publicKey")
    state: str


class RegisterFinishRequest(_Schema):
    credential: dict[str, Any]
    state: str
    device_name: str = Field(default="", alias="deviceName")


class RegisterFinishResponse(_Schema):
    status: str = "ok"
    credential_id: str = Field(alias="credentialId")


class AuthBeginRequest(_Schema):
    user_id: str | None = Field(default=None, alias="userId")


class AuthFinishRequest(_Schema):
    credential: dict[str, Any]
    state: str


class RenameRequest(_Schema):
    device_name: str = Field(alias="deviceName")


class CredentialView(_Schema):
    """A sanitized credential for listing — never exposes the public key."""

    id: str
    device_name: str = Field(alias="deviceName")
    transports: list[str]
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
            backupEligible=credential.backup_eligible,
            backupState=credential.backup_state,
            createdAt=credential.created_at,
            lastUsedAt=credential.last_used_at,
        )
