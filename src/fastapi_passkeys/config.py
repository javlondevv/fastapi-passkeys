"""Typed configuration.

A single :class:`PasskeyConfig` object is the policy surface for the whole
library. It is a ``pydantic-settings`` model, so every field can be supplied in
code or via ``PASSKEYS_*`` environment variables. Keep one instance per relying
party; for multi-tenant apps build the config per request and pass it to the
services (see the configuration guide).
"""

from __future__ import annotations

import warnings
from datetime import timedelta
from urllib.parse import urlsplit

from pydantic import Field, SecretStr, field_validator, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

from fastapi_passkeys.domain.enums import (
    AttestationPreference,
    AuthenticatorAttachment,
    Hint,
    ResidentKeyRequirement,
    SignCountPolicy,
    UserVerification,
)

_DEFAULT_PORTS = {"http": 80, "https": 443}
_ANDROID_ORIGIN_PREFIX = "android:apk-key-hash:"


def _normalize_origin(origin: str) -> str:
    """Return ``origin`` exactly as a browser serializes it in ``clientDataJSON``.

    Browsers emit a lowercase scheme and host, no trailing slash, and no default
    port. A configured ``https://Example.com:443/`` would therefore *never* match
    and every ceremony would fail, so we normalize instead of comparing raw.
    """
    if origin.startswith(_ANDROID_ORIGIN_PREFIX):
        # Native Android apps; the hash is case-sensitive base64url — keep verbatim.
        if len(origin) == len(_ANDROID_ORIGIN_PREFIX):
            raise ValueError(f"invalid origin: {origin!r} (missing APK key hash)")
        return origin

    parts = urlsplit(origin.strip())
    scheme = parts.scheme.lower()
    if scheme not in _DEFAULT_PORTS or not parts.hostname:
        raise ValueError(f"invalid origin: {origin!r} (expected scheme://host[:port])")
    if parts.path not in ("", "/") or parts.query or parts.fragment:
        raise ValueError(f"origin must not contain a path, query or fragment: {origin!r}")
    if parts.username is not None or parts.password is not None:
        raise ValueError(f"origin must not contain credentials: {origin!r}")
    try:
        port = parts.port
    except ValueError as exc:
        raise ValueError(f"invalid origin port: {origin!r}") from exc

    host = parts.hostname  # already lowercased by urlsplit
    if ":" in host:  # IPv6 literal
        host = f"[{host}]"
    if port is not None and port != _DEFAULT_PORTS[scheme]:
        host = f"{host}:{port}"
    return f"{scheme}://{host}"


class PasskeyConfig(BaseSettings):
    """Relying-party policy for passkey ceremonies."""

    model_config = SettingsConfigDict(env_prefix="PASSKEYS_", extra="ignore")

    rp_id: str = Field(
        description="Relying Party ID — a bare registrable domain such as 'example.com' "
        "(no scheme, port or path). Every web origin must be this domain or a subdomain.",
    )
    rp_name: str = Field(description="Human-readable RP name shown by authenticators.")
    expected_origins: list[str] = Field(
        description="Allowed origins, e.g. ['https://example.com']. Normalized to the "
        "browser's serialization. Android app origins ('android:apk-key-hash:...') are "
        "accepted verbatim.",
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

    hints: list[Hint] = Field(
        default_factory=list,
        description="WebAuthn L3 hints sent with both ceremonies, most preferred first.",
    )
    max_credentials_per_user: int | None = Field(
        default=None,
        ge=1,
        description="Refuse to register more passkeys than this per user. None = no limit.",
    )
    verify_user_handle: bool = Field(
        default=True,
        description="Require the assertion's userHandle to identify the credential's owner "
        "(WebAuthn §7.2 step 6). Disable only for credentials imported from a library that "
        "used a different user-handle scheme.",
    )
    enforce_backup_eligibility: bool = Field(
        default=True,
        description="Reject an assertion whose backup-eligible (BE) flag differs from the one "
        "recorded at registration; BE is fixed for a credential's lifetime.",
    )
    related_origins: list[str] = Field(
        default_factory=list,
        description="WebAuthn Related Origin Requests: extra web origins (on other domains) "
        "allowed to use this rp_id. Served from /.well-known/webauthn and accepted at verify.",
    )

    signing_secret: SecretStr | None = Field(
        default=None,
        description="HMAC secret for the stateless challenge store. Required only when used.",
    )

    @field_validator("rp_id")
    @classmethod
    def _validate_rp_id(cls, value: str) -> str:
        rp_id = value.strip().lower().rstrip(".")
        if not rp_id or any(c in rp_id for c in ":/?#@ \t") or rp_id.startswith("."):
            raise ValueError(
                f"rp_id must be a bare domain such as 'example.com' (no scheme, port or "
                f"path), got {value!r}"
            )
        return rp_id

    @field_validator("expected_origins")
    @classmethod
    def _validate_origins(cls, value: list[str]) -> list[str]:
        if not value:
            raise ValueError("expected_origins must contain at least one origin")
        normalized: list[str] = []
        for origin in value:
            item = _normalize_origin(origin)
            if item not in normalized:
                normalized.append(item)
        return normalized

    @field_validator("related_origins")
    @classmethod
    def _validate_related_origins(cls, value: list[str]) -> list[str]:
        normalized: list[str] = []
        for origin in value:
            item = _normalize_origin(origin)
            if item.startswith(_ANDROID_ORIGIN_PREFIX):
                raise ValueError("related_origins must be web origins (http/https)")
            if item not in normalized:
                normalized.append(item)
        return normalized

    @field_validator("challenge_ttl")
    @classmethod
    def _validate_ttl(cls, value: timedelta) -> timedelta:
        if value <= timedelta(0):
            raise ValueError("challenge_ttl must be positive")
        return value

    @model_validator(mode="after")
    def _check_origins_match_rp_id(self) -> PasskeyConfig:
        for origin in self.expected_origins:
            if origin.startswith(_ANDROID_ORIGIN_PREFIX):
                continue
            host = urlsplit(origin).hostname or ""
            if host != self.rp_id and not host.endswith("." + self.rp_id):
                # Browsers refuse such a pairing ("The RP ID is not a registrable
                # domain suffix of the origin"), so fail at startup, not at runtime.
                raise ValueError(
                    f"origin {origin!r} is not on rp_id {self.rp_id!r} or one of its subdomains"
                )
        if self.challenge_ttl < timedelta(milliseconds=self.timeout_ms):
            warnings.warn(
                "challenge_ttl is shorter than timeout_ms: a user who takes the full "
                "client timeout will find the challenge already expired.",
                stacklevel=2,
            )
        return self

    @property
    def allowed_origins(self) -> list[str]:
        """Every origin accepted at verification: ``expected_origins`` + ``related_origins``."""
        return self.expected_origins + [
            o for o in self.related_origins if o not in self.expected_origins
        ]

    @property
    def require_user_verification(self) -> bool:
        """Whether assertions/attestations must prove user verification."""
        return self.user_verification is UserVerification.REQUIRED
