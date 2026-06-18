"""A minimal software WebAuthn authenticator for tests.

Produces real attestation ("none" format) and assertion responses that the
engine verifies for real — so flow tests exercise actual signature verification,
not mocks. Built on ``cbor2`` and ``cryptography`` (already present via the
WebAuthn dependency); no extra test dependency required.

Not for production use.
"""

from __future__ import annotations

import json
import os
import struct
from hashlib import sha256
from typing import Any

import cbor2
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec

from fastapi_passkeys._b64 import b64url_to_bytes, bytes_to_b64url

_FLAG_UP = 0x01
_FLAG_UV = 0x04
_FLAG_BE = 0x08
_FLAG_BS = 0x10
_FLAG_AT = 0x40


class _StoredKey:
    __slots__ = ("key", "rp_id", "sign_count", "user_handle")

    def __init__(self, key: ec.EllipticCurvePrivateKey, user_handle: bytes, rp_id: str) -> None:
        self.key = key
        self.user_handle = user_handle
        self.rp_id = rp_id
        self.sign_count = 0


def _cose_key(key: ec.EllipticCurvePrivateKey) -> bytes:
    numbers = key.public_key().public_numbers()
    return cbor2.dumps(
        {
            1: 2,  # kty: EC2
            3: -7,  # alg: ES256
            -1: 1,  # crv: P-256
            -2: numbers.x.to_bytes(32, "big"),
            -3: numbers.y.to_bytes(32, "big"),
        }
    )


class SoftwareAuthenticator:
    """An in-memory authenticator that signs ceremonies with ES256 keys."""

    def __init__(
        self,
        *,
        aaguid: bytes = b"\x00" * 16,
        user_verified: bool = True,
        backup_eligible: bool = False,
        backup_state: bool = False,
    ) -> None:
        self.aaguid = aaguid
        self.user_verified = user_verified
        self.backup_eligible = backup_eligible
        self.backup_state = backup_state
        self._creds: dict[bytes, _StoredKey] = {}

    def _flags(self, *, attested: bool) -> int:
        flags = _FLAG_UP
        if self.user_verified:
            flags |= _FLAG_UV
        if self.backup_eligible:
            flags |= _FLAG_BE
        if self.backup_state:
            flags |= _FLAG_BS
        if attested:
            flags |= _FLAG_AT
        return flags

    def create(
        self,
        options: dict[str, Any],
        *,
        origin: str,
        credential_id: bytes | None = None,
    ) -> dict[str, Any]:
        """Emulate ``navigator.credentials.create`` for a registration ceremony.

        Pass ``credential_id`` to force a specific id (e.g. to test the
        duplicate-credential guard).
        """
        rp_id = options["rp"]["id"]
        challenge = b64url_to_bytes(options["challenge"])
        user_handle = b64url_to_bytes(options["user"]["id"])

        key = ec.generate_private_key(ec.SECP256R1())
        credential_id = credential_id or os.urandom(16)
        self._creds[credential_id] = _StoredKey(key, user_handle, rp_id)

        client_data = _client_data("webauthn.create", challenge, origin)
        attested = (
            self.aaguid + struct.pack(">H", len(credential_id)) + credential_id + _cose_key(key)
        )
        auth_data = (
            sha256(rp_id.encode()).digest()
            + bytes([self._flags(attested=True)])
            + struct.pack(">I", 0)
            + attested
        )
        attestation_object = cbor2.dumps({"fmt": "none", "attStmt": {}, "authData": auth_data})
        return {
            "id": bytes_to_b64url(credential_id),
            "rawId": bytes_to_b64url(credential_id),
            "type": "public-key",
            "response": {
                "clientDataJSON": bytes_to_b64url(client_data),
                "attestationObject": bytes_to_b64url(attestation_object),
                "transports": ["internal"],
            },
            "clientExtensionResults": {},
        }

    def get(
        self,
        options: dict[str, Any],
        *,
        origin: str,
        sign_count: int | None = None,
    ) -> dict[str, Any]:
        """Emulate ``navigator.credentials.get`` for an authentication ceremony.

        Pass ``sign_count`` to force a specific counter value (e.g. to simulate a
        cloned authenticator that fails to advance it).
        """
        rp_id = options.get("rpId") or next(iter(self._creds.values())).rp_id
        challenge = b64url_to_bytes(options["challenge"])
        credential_id = self._select_credential(options)
        stored = self._creds[credential_id]

        if sign_count is None:
            stored.sign_count += 1
            counter = stored.sign_count
        else:
            counter = sign_count

        client_data = _client_data("webauthn.get", challenge, origin)
        auth_data = (
            sha256(rp_id.encode()).digest()
            + bytes([self._flags(attested=False)])
            + struct.pack(">I", counter)
        )
        signature = stored.key.sign(
            auth_data + sha256(client_data).digest(), ec.ECDSA(hashes.SHA256())
        )
        return {
            "id": bytes_to_b64url(credential_id),
            "rawId": bytes_to_b64url(credential_id),
            "type": "public-key",
            "response": {
                "clientDataJSON": bytes_to_b64url(client_data),
                "authenticatorData": bytes_to_b64url(auth_data),
                "signature": bytes_to_b64url(signature),
                "userHandle": bytes_to_b64url(stored.user_handle),
            },
            "clientExtensionResults": {},
        }

    def _select_credential(self, options: dict[str, Any]) -> bytes:
        allowed = options.get("allowCredentials") or []
        for descriptor in allowed:
            candidate = b64url_to_bytes(descriptor["id"])
            if candidate in self._creds:
                return candidate
        if not self._creds:
            raise LookupError("authenticator holds no credentials")
        return next(iter(self._creds))


def _client_data(ceremony_type: str, challenge: bytes, origin: str) -> bytes:
    return json.dumps(
        {
            "type": ceremony_type,
            "challenge": bytes_to_b64url(challenge),
            "origin": origin,
            "crossOrigin": False,
        },
        separators=(",", ":"),
    ).encode("utf-8")
