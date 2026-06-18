"""Config validation and property-based encoding tests."""

from __future__ import annotations

import pytest
from hypothesis import given
from hypothesis import strategies as st
from pydantic import ValidationError

from fastapi_passkeys import PasskeyConfig
from fastapi_passkeys._b64 import b64url_to_bytes, bytes_to_b64url
from fastapi_passkeys.domain.enums import UserVerification


@given(st.binary(max_size=512))
def test_base64url_round_trips(data: bytes) -> None:
    assert b64url_to_bytes(bytes_to_b64url(data)) == data


def test_config_rejects_malformed_origin() -> None:
    with pytest.raises(ValidationError):
        PasskeyConfig(rp_id="x", rp_name="y", expected_origins=["not-a-url"])


def test_config_rejects_origin_with_path() -> None:
    with pytest.raises(ValidationError):
        PasskeyConfig(rp_id="x", rp_name="y", expected_origins=["https://x.com/login"])


def test_config_requires_at_least_one_origin() -> None:
    with pytest.raises(ValidationError):
        PasskeyConfig(rp_id="x", rp_name="y", expected_origins=[])


def test_require_user_verification_reflects_policy() -> None:
    required = PasskeyConfig(
        rp_id="x",
        rp_name="y",
        expected_origins=["https://x.com"],
        user_verification=UserVerification.REQUIRED,
    )
    preferred = PasskeyConfig(rp_id="x", rp_name="y", expected_origins=["https://x.com"])
    assert required.require_user_verification is True
    assert preferred.require_user_verification is False
