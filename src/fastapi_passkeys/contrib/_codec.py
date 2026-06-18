"""Shared (de)serialization for challenges held outside the process.

Used by the stateless and Redis stores so the on-the-wire payload shape is
defined in exactly one place.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

from fastapi_passkeys._b64 import b64url_to_bytes, bytes_to_b64url
from fastapi_passkeys.domain.enums import CeremonyType
from fastapi_passkeys.domain.models import (
    AuthenticationChallenge,
    PasskeyUser,
    RegistrationChallenge,
)


def challenge_to_payload(
    challenge: RegistrationChallenge | AuthenticationChallenge,
) -> dict[str, Any]:
    payload: dict[str, Any] = {
        "c": bytes_to_b64url(challenge.challenge),
        "iat": int(challenge.created_at.timestamp()),
        "exp": int(challenge.expires_at.timestamp()),
        "k": challenge.ceremony.value,
    }
    if isinstance(challenge, RegistrationChallenge):
        payload["u"] = {
            "id": challenge.user.id,
            "n": challenge.user.name,
            "d": challenge.user.display_name,
        }
    else:
        payload["uid"] = challenge.user_id
    return payload


def payload_to_challenge(
    payload: dict[str, Any],
) -> RegistrationChallenge | AuthenticationChallenge | None:
    try:
        created_at = datetime.fromtimestamp(payload["iat"], tz=timezone.utc)
        expires_at = datetime.fromtimestamp(payload["exp"], tz=timezone.utc)
        challenge = b64url_to_bytes(payload["c"])
        ceremony = CeremonyType(payload["k"])
    except (KeyError, ValueError, TypeError):
        return None

    if ceremony is CeremonyType.REGISTER:
        user = payload.get("u") or {}
        try:
            subject = PasskeyUser(id=user["id"], name=user["n"], display_name=user["d"])
        except KeyError:
            return None
        return RegistrationChallenge(
            challenge=challenge,
            user=subject,
            created_at=created_at,
            expires_at=expires_at,
        )
    return AuthenticationChallenge(
        challenge=challenge,
        user_id=payload.get("uid"),
        created_at=created_at,
        expires_at=expires_at,
    )
