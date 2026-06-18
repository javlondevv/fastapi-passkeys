"""Typed configuration.

A single :class:`PasskeyConfig` object is the policy surface for the whole
library. It is a ``pydantic-settings`` model, so every field can be supplied in
code or via ``PASSKEYS_*`` environment variables. Keep one instance per relying
party; for multi-tenant apps build the config per request and pass it to the
services (see the configuration guide).
"""

from __future__ import annotations

from datetime import timedelta
from urllib.parse import urlparse

from pydantic import Field, SecretStr, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

from fastapi_passkeys.domain.enums import (
    AttestationPreference,
    AuthenticatorAttachment,
    ResidentKeyRequirement,
    SignCountPolicy,
    UserVerification,
)


class PasskeyConfig(BaseSettings):
    """Relying-party policy for passkey ceremonies."""

    model_config = SettingsConfigDict(env_prefix="PASSKEYS_", extra="ignore")

    rp_id: str = Field(description="Relying Party ID — the registrable domain, e.g. 'example.com'.")
    rp_name: str = Field(description="Human-readable RP name shown by authenticators.")
    expected_origins: list[str] = Field(
        description="Allowed web origins, e.g. ['https://example.com']. At least one required.",
    )

    challenge_ttl: timedelta = Field(
        default=timedelta(seconds=300),
        description="Server-enforced challenge lifetime, independent of the client timeout.",
    )
    timeout_ms: int = Field(
        default=60_000,
        ge=1_000,
        description="Client-side ceremony timeout hint passed to the authenticator.",
    )

    user_verification: UserVerification = UserVerification.PREFERRED
    attestation: AttestationPreference = AttestationPreference.NONE
    authenticator_attachment: AuthenticatorAttachment | None = None
    resident_key: ResidentKeyRequirement = ResidentKeyRequirement.PREFERRED
    sign_count_policy: SignCountPolicy = SignCountPolicy.STRICT_REJECT

    signing_secret: SecretStr | None = Field(
        default=None,
        description="HMAC secret for the stateless challenge store. Required only when used.",
    )

    @field_validator("expected_origins")
    @classmethod
    def _validate_origins(cls, value: list[str]) -> list[str]:
        if not value:
            raise ValueError("expected_origins must contain at least one origin")
        for origin in value:
            parsed = urlparse(origin)
            if parsed.scheme not in {"http", "https"} or not parsed.netloc:
                raise ValueError(f"invalid origin: {origin!r} (expected scheme://host[:port])")
            if parsed.path not in ("", "/"):
                raise ValueError(f"origin must not contain a path: {origin!r}")
        return value

    @property
    def require_user_verification(self) -> bool:
        """Whether assertions/attestations must prove user verification."""
        return self.user_verification is UserVerification.REQUIRED
