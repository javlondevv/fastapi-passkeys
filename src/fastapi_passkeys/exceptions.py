"""Typed exception hierarchy.

Every error the library raises carries a machine-readable ``code`` and a default
``status_code``. ``install_exception_handlers`` (see :mod:`fastapi_passkeys.api`)
turns these into JSON responses without leaking internal detail. The messages are
intentionally generic for verification failures to avoid handing attackers an
oracle (e.g. we do not say *why* an assertion failed).
"""

from __future__ import annotations


class PasskeyError(Exception):
    """Base class for every error raised by fastapi-passkeys."""

    code = "passkey_error"
    status_code = 400

    def __init__(self, message: str | None = None) -> None:
        super().__init__(message or self.__doc__ or self.code)
        self.message = message or (self.__doc__ or self.code)


class ConfigurationError(PasskeyError):
    """The library was configured incorrectly."""

    code = "configuration_error"
    status_code = 500


# --- Challenge ---------------------------------------------------------------


class ChallengeError(PasskeyError):
    """A challenge could not be validated."""

    code = "challenge_error"
    status_code = 400


class ChallengeNotFound(ChallengeError):
    """The challenge is unknown, already used, or has expired."""

    code = "challenge_not_found"
    status_code = 400


class ChallengeExpired(ChallengeError):
    """The challenge is no longer valid."""

    code = "challenge_expired"
    status_code = 400


# --- Registration ------------------------------------------------------------


class RegistrationError(PasskeyError):
    """Registration could not be completed."""

    code = "registration_error"
    status_code = 400


class CredentialAlreadyExists(RegistrationError):
    """This credential is already registered."""

    code = "credential_already_exists"
    status_code = 409


class AttestationVerificationError(RegistrationError):
    """The registration response failed verification."""

    code = "attestation_verification_failed"
    status_code = 400


# --- Authentication ----------------------------------------------------------


class AuthenticationError(PasskeyError):
    """Authentication could not be completed."""

    code = "authentication_error"
    status_code = 401


class CredentialNotFound(AuthenticationError):
    """No matching registered credential was found."""

    code = "credential_not_found"
    status_code = 401


class AssertionVerificationError(AuthenticationError):
    """The authentication response failed verification."""

    code = "assertion_verification_failed"
    status_code = 401


class CloneDetectedError(AuthenticationError):
    """The signature counter did not advance; the authenticator may be cloned."""

    code = "clone_detected"
    status_code = 401
