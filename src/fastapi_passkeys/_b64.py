"""Internal base64url helpers.

Kept dependency-free (stdlib only) so modules outside :mod:`fastapi_passkeys.engine`
never need to import the underlying WebAuthn library just to encode an id.
"""

from __future__ import annotations

import base64


def bytes_to_b64url(data: bytes) -> str:
    """Encode bytes as unpadded base64url."""
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def b64url_to_bytes(value: str) -> bytes:
    """Decode unpadded (or padded) base64url back to bytes."""
    padding = "=" * (-len(value) % 4)
    return base64.urlsafe_b64decode(value + padding)
