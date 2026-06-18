"""Domain entities and value objects.

These are plain frozen dataclasses with no dependency on FastAPI, any ORM, or the
WebAuthn implementation. They are the lingua franca between the engine, services,
and repositories.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime

from fastapi_passkeys.domain.enums import CeremonyType, Transport


@dataclass(frozen=True, slots=True)
class PasskeyUser:
    """The subject of a ceremony.

    ``id`` is your stable internal identifier (it becomes the WebAuthn user
    handle). ``name`` and ``display_name`` are shown by the authenticator UI.
    """

    id: str
    name: str
    display_name: str


@dataclass(frozen=True, slots=True)
class Credential:
    """A registered passkey, as persisted by a :class:`CredentialRepository`."""

    credential_id: bytes
    user_id: str
    public_key: bytes
    sign_count: int
    transports: tuple[Transport, ...] = ()
    aaguid: bytes | None = None
    backup_eligible: bool = False
    backup_state: bool = False
    device_name: str = ""
    is_discoverable: bool = False
    attestation_fmt: str | None = None
    created_at: datetime | None = None
    last_used_at: datetime | None = None


@dataclass(frozen=True, slots=True)
class RegistrationChallenge:
    """A challenge issued for a registration ceremony, stored single-use."""

    challenge: bytes
    user: PasskeyUser
    created_at: datetime
    expires_at: datetime
    ceremony: CeremonyType = CeremonyType.REGISTER


@dataclass(frozen=True, slots=True)
class AuthenticationChallenge:
    """A challenge issued for an authentication ceremony, stored single-use.

    ``user_id`` is ``None`` for usernameless (discoverable credential) flows.
    """

    challenge: bytes
    user_id: str | None
    created_at: datetime
    expires_at: datetime
    ceremony: CeremonyType = CeremonyType.AUTHENTICATE


@dataclass(frozen=True, slots=True)
class VerifiedRegistration:
    """Result of verifying a registration response, before persistence."""

    credential_id: bytes
    public_key: bytes
    sign_count: int
    transports: tuple[Transport, ...] = ()
    aaguid: bytes | None = None
    backup_eligible: bool = False
    backup_state: bool = False
    is_discoverable: bool = False
    attestation_fmt: str | None = None


@dataclass(frozen=True, slots=True)
class VerifiedAuthentication:
    """Result of verifying an authentication response."""

    credential_id: bytes
    new_sign_count: int
    user_verified: bool


@dataclass(frozen=True, slots=True)
class AuthenticationResult:
    """Returned to the application once a passkey assertion is verified."""

    user_id: str
    credential: Credential
    detail: dict[str, object] = field(default_factory=dict)
