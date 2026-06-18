"""fastapi-passkeys — Passkeys / WebAuthn authentication for FastAPI.

Quick start (Layer A)::

    from fastapi import FastAPI
    from fastapi_passkeys import Passkeys, PasskeyConfig
    from fastapi_passkeys.contrib import InMemoryCredentialRepository

    passkeys = Passkeys(
        config=PasskeyConfig(rp_id="example.com", rp_name="Example",
                             expected_origins=["https://example.com"]),
        credential_repository=InMemoryCredentialRepository(),
        get_user=get_user,            # -> PasskeyUser
        on_authenticated=issue_token, # (request, result) -> response body
    )
    app = FastAPI()
    app.include_router(passkeys.router, prefix="/auth/passkeys")
    passkeys.install_exception_handlers(app)
"""

from __future__ import annotations

from importlib.metadata import PackageNotFoundError
from importlib.metadata import version as _version

from fastapi_passkeys.api import GetUser, OnAuthenticated, Passkeys, install_exception_handlers
from fastapi_passkeys.audit import (
    AuditEvent,
    AuditEventType,
    AuditSink,
    LoggingAuditSink,
    NullAuditSink,
)
from fastapi_passkeys.config import PasskeyConfig
from fastapi_passkeys.domain import (
    AttestationPreference,
    AuthenticationResult,
    AuthenticatorAttachment,
    Credential,
    PasskeyUser,
    ResidentKeyRequirement,
    SignCountPolicy,
    Transport,
    UserVerification,
)
from fastapi_passkeys.engine import PyWebAuthnEngine, WebAuthnEngine
from fastapi_passkeys.exceptions import (
    AssertionVerificationError,
    AttestationVerificationError,
    AuthenticationError,
    ChallengeExpired,
    ChallengeNotFound,
    CloneDetectedError,
    ConfigurationError,
    CredentialAlreadyExists,
    CredentialNotFound,
    PasskeyError,
    RegistrationError,
)
from fastapi_passkeys.repositories import ChallengeStore, CredentialRepository
from fastapi_passkeys.services import (
    AuthenticationService,
    Clock,
    RegistrationService,
    SystemClock,
)

# Single source of truth: the installed package metadata (set from pyproject.toml).
# This never drifts from the released version on PyPI.
try:
    __version__ = _version("fastapi-passkeys")
except PackageNotFoundError:  # running from a source tree without an install
    __version__ = "0.0.0"

__all__ = [
    "AssertionVerificationError",
    "AttestationPreference",
    "AttestationVerificationError",
    "AuditEvent",
    "AuditEventType",
    "AuditSink",
    "AuthenticationError",
    "AuthenticationResult",
    "AuthenticationService",
    "AuthenticatorAttachment",
    "ChallengeExpired",
    "ChallengeNotFound",
    "ChallengeStore",
    "Clock",
    "CloneDetectedError",
    "ConfigurationError",
    "Credential",
    "CredentialAlreadyExists",
    "CredentialNotFound",
    "CredentialRepository",
    "GetUser",
    "LoggingAuditSink",
    "NullAuditSink",
    "OnAuthenticated",
    "PasskeyConfig",
    "PasskeyError",
    "PasskeyUser",
    "Passkeys",
    "PyWebAuthnEngine",
    "RegistrationError",
    "RegistrationService",
    "ResidentKeyRequirement",
    "SignCountPolicy",
    "SystemClock",
    "Transport",
    "UserVerification",
    "WebAuthnEngine",
    "__version__",
    "install_exception_handlers",
]
