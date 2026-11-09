"""Enumerations used across the public API and domain.

These mirror the WebAuthn vocabulary but are defined here so the public surface
never depends on the underlying WebAuthn implementation. ``str`` mix-in keeps
them JSON-serialisable and stable on the wire across Python 3.10-3.13 (we avoid
``enum.StrEnum`` because it only exists from 3.11).
"""

from __future__ import annotations

from enum import Enum


class UserVerification(str, Enum):
    """How strongly the authenticator must verify the user (PIN/biometric)."""

    REQUIRED = "required"
    PREFERRED = "preferred"
    DISCOURAGED = "discouraged"


class AttestationPreference(str, Enum):
    """How much attestation metadata the RP requests from the authenticator."""

    NONE = "none"
    INDIRECT = "indirect"
    DIRECT = "direct"


class AuthenticatorAttachment(str, Enum):
    """Whether to prefer platform (built-in) or roaming (cross-platform) keys."""

    PLATFORM = "platform"
    CROSS_PLATFORM = "cross-platform"


class ResidentKeyRequirement(str, Enum):
    """Discoverable-credential (resident key) preference for usernameless flows."""

    DISCOURAGED = "discouraged"
    PREFERRED = "preferred"
    REQUIRED = "required"


class Transport(str, Enum):
    """Reported transports a credential can be used over."""

    USB = "usb"
    NFC = "nfc"
    BLE = "ble"
    INTERNAL = "internal"
    HYBRID = "hybrid"
    SMART_CARD = "smart-card"


class CeremonyType(str, Enum):
    """Binds a stored challenge to the ceremony it was issued for."""

    REGISTER = "register"
    AUTHENTICATE = "authenticate"


class SignCountPolicy(str, Enum):
    """What to do when an authenticator's signature counter does not advance.

    - ``STRICT_REJECT`` — reject the assertion; keep the credential for review.
    - ``FLAG_DISABLE`` — reject the assertion **and delete** the credential.
    - ``AUDIT_ONLY`` — accept the assertion but emit ``CLONE_SUSPECTED``. Useful
      where false positives are costlier than the risk (counters are a weak
      signal for multi-device passkeys).
    """

    STRICT_REJECT = "strict-reject"
    FLAG_DISABLE = "flag-disable"
    AUDIT_ONLY = "audit-only"


class Hint(str, Enum):
    """WebAuthn L3 ``hints``: steer the browser UI toward a kind of authenticator."""

    SECURITY_KEY = "security-key"
    CLIENT_DEVICE = "client-device"
    HYBRID = "hybrid"
