"""Internal base64url helpers.

Kept dependency-free (stdlib only) so modules outside :mod:`fastapi_passkeys.engine`
never need to import the underlying WebAuthn library just to encode an id.
"""

from __future__ import annotations

import base64
import binascii
import re

# RFC 4648 §5 alphabet, optional trailing padding. ``base64.urlsafe_b64decode``
# silently *discards* characters outside the alphabet and also accepts the
# standard ``+``/``/`` characters, so several distinct strings could decode to
# the same credential id. We reject anything non-canonical up front.
_B64URL = re.compile(r"[A-Za-z0-9_-]*={0,2}")


def bytes_to_b64url(data: bytes) -> str:
    """Encode bytes as unpadded base64url."""
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def b64url_to_bytes(value: str) -> bytes:
    """Decode unpadded (or padded) base64url back to bytes.

    Raises :class:`ValueError` for anything outside the base64url alphabet.
    """
    if not isinstance(value, str) or _B64URL.fullmatch(value) is None:
        raise ValueError("value is not base64url")
    stripped = value.rstrip("=")
    try:
        return base64.urlsafe_b64decode(stripped + "=" * (-len(stripped) % 4))
    except binascii.Error as exc:
        raise ValueError("value is not base64url") from exc
