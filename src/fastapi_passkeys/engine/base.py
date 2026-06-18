"""The WebAuthn engine seam.

Everything WebAuthn-implementation-specific lives behind this Protocol. Services
depend only on this interface, so the underlying library (currently py_webauthn)
can be upgraded or swapped by replacing a single module without touching the
public API or the domain.

The methods are synchronous: option generation and signature verification are
fast, CPU-bound operations with no I/O.
"""

from __future__ import annotations

from typing import Any, Protocol

from fastapi_passkeys.config import PasskeyConfig
from fastapi_passkeys.domain.models import (
    Credential,
    PasskeyUser,
    VerifiedAuthentication,
    VerifiedRegistration,
)


class WebAuthnEngine(Protocol):
    """Generates ceremony options and verifies authenticator responses."""

    def registration_options(
        self,
        *,
        config: PasskeyConfig,
        user: PasskeyUser,
        challenge: bytes,
        exclude: list[Credential],
    ) -> dict[str, Any]:
        """Build ``PublicKeyCredentialCreationOptions`` as a JSON-ready dict."""
        ...

    def verify_registration(
        self,
        *,
        config: PasskeyConfig,
        response: dict[str, Any] | str,
        expected_challenge: bytes,
    ) -> VerifiedRegistration:
        """Verify an attestation response. Raises on any failure."""
        ...

    def authentication_options(
        self,
        *,
        config: PasskeyConfig,
        challenge: bytes,
        allow: list[Credential],
    ) -> dict[str, Any]:
        """Build ``PublicKeyCredentialRequestOptions`` as a JSON-ready dict."""
        ...

    def verify_authentication(
        self,
        *,
        config: PasskeyConfig,
        response: dict[str, Any] | str,
        expected_challenge: bytes,
        credential: Credential,
    ) -> VerifiedAuthentication:
        """Verify an assertion response against a stored credential. Raises on failure."""
        ...
