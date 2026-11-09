"""Edge cases: malformed input, tampering, and backward compatibility with 0.1 plug-ins."""

from __future__ import annotations

import dataclasses
import json
import secrets
import warnings
from datetime import datetime, timedelta
from typing import Any

import pytest

from fastapi_passkeys import PasskeyConfig
from fastapi_passkeys._b64 import bytes_to_b64url
from fastapi_passkeys.config import _normalize_origin
from fastapi_passkeys.contrib._codec import payload_to_challenge
from fastapi_passkeys.contrib.memory import InMemoryChallengeStore, InMemoryCredentialRepository
from fastapi_passkeys.contrib.stateless import StatelessChallengeStore
from fastapi_passkeys.domain.models import (
    AuthenticationChallenge,
    PasskeyUser,
    VerifiedAuthentication,
)
from fastapi_passkeys.engine.pywebauthn import PyWebAuthnEngine
from fastapi_passkeys.exceptions import (
    AssertionVerificationError,
    ConfigurationError,
    CredentialNotFound,
)
from fastapi_passkeys.services.authentication import AuthenticationService
from fastapi_passkeys.services.registration import RegistrationService
from fastapi_passkeys.testing import SoftwareAuthenticator

ORIGIN = "https://example.com"


def _cfg(**overrides: Any) -> PasskeyConfig:
    base: dict[str, Any] = {
        "rp_id": "example.com",
        "rp_name": "Example",
        "expected_origins": [ORIGIN],
    }
    base.update(overrides)
    return PasskeyConfig(**base)


async def _register(registration, authenticator, user):
    options, handle = await registration.begin(user)
    return await registration.finish(
        response=authenticator.create(options, origin=ORIGIN), handle=handle
    )


# --- Config ---------------------------------------------------------------------


@pytest.mark.parametrize(
    "origin",
    [
        "ftp://example.com",
        "https://user:pw@example.com",
        "https://example.com:99999",
        "https://example.com?x=1",
        "https://example.com#frag",
        "android:apk-key-hash:",
    ],
)
def test_malformed_origins_are_rejected(origin: str) -> None:
    with pytest.raises(ValueError):
        _cfg(expected_origins=[origin])


def test_ipv6_origin_keeps_brackets() -> None:
    # (An IP literal is never a valid RP ID, so exercise the normalizer directly.)
    assert _normalize_origin("http://[::1]:8000/") == "http://[::1]:8000"


def test_duplicate_origins_are_collapsed() -> None:
    cfg = _cfg(expected_origins=[ORIGIN, "https://EXAMPLE.com/"])
    assert cfg.expected_origins == [ORIGIN]


def test_related_origins_must_be_web_origins() -> None:
    with pytest.raises(ValueError, match="related_origins"):
        _cfg(related_origins=["android:apk-key-hash:abc"])


def test_short_challenge_ttl_warns() -> None:
    with warnings.catch_warnings(record=True) as caught:
        warnings.simplefilter("always")
        _cfg(challenge_ttl=timedelta(seconds=10), timeout_ms=60_000)
    assert any("challenge_ttl" in str(w.message) for w in caught)


# --- Registration input ---------------------------------------------------------


@pytest.mark.parametrize(
    "user",
    [
        PasskeyUser(id="", name="a@example.com", display_name="A"),
        PasskeyUser(id="u1", name="  ", display_name="A"),
    ],
)
async def test_invalid_users_are_rejected(registration, user) -> None:
    with pytest.raises(ConfigurationError):
        await registration.begin(user)


async def test_cred_props_absent_falls_back_to_resident_key_policy(registration, user):
    credential = await _register(registration, SoftwareAuthenticator(resident_key=None), user)
    assert credential.is_discoverable is False  # resident_key=preferred, unknown


# --- Malformed assertion bodies -------------------------------------------------


@pytest.mark.parametrize(
    "response",
    [
        "not json",
        "[]",
        {"rawId": 123},
        {"rawId": "!!!"},
        {"id": "AAAA", "response": "nope"},
    ],
)
async def test_malformed_assertions_fail_cleanly(authentication, response) -> None:
    _, handle = await authentication.begin()
    with pytest.raises(CredentialNotFound):
        await authentication.finish(response=response, handle=handle)


async def test_assertion_as_json_string_is_accepted(
    registration, authentication, authenticator, user
) -> None:
    await _register(registration, authenticator, user)
    options, handle = await authentication.begin(user_id=user.id)
    raw = json.dumps(authenticator.get(options, origin=ORIGIN))
    assert (await authentication.finish(response=raw, handle=handle)).user_id == user.id


async def test_bound_flow_rejects_wrong_user_handle(
    registration, authentication, authenticator, user
) -> None:
    await _register(registration, authenticator, user)
    options, handle = await authentication.begin(user_id=user.id)
    assertion = authenticator.get(options, origin=ORIGIN)
    assertion["response"]["userHandle"] = bytes_to_b64url(b"someone-else")
    with pytest.raises(CredentialNotFound):
        await authentication.finish(response=assertion, handle=handle)


# --- Stateless store tampering --------------------------------------------------


@pytest.mark.parametrize("handle", ["no-dot", "a.b.c", "!!.!!", "e30.AAAA"])
async def test_stateless_store_rejects_garbage(clock, handle: str) -> None:
    store = StatelessChallengeStore("secret", clock=clock)
    assert await store.consume(handle) is None


async def test_stateless_store_rejects_tampered_body(clock) -> None:
    store = StatelessChallengeStore("secret", clock=clock)
    handle = await store.put(
        AuthenticationChallenge(
            challenge=b"c",
            user_id="alice",
            created_at=clock.now(),
            expires_at=clock.now() + timedelta(minutes=5),
        )
    )
    _, sig = handle.split(".")
    forged = json.dumps({"c": "Yw", "iat": 0, "exp": 2**40, "k": "authenticate", "uid": "eve"})
    assert await store.consume(f"{bytes_to_b64url(forged.encode())}.{sig}") is None


async def test_stateless_store_forgets_consumed_tokens_after_expiry(clock) -> None:
    store = StatelessChallengeStore("secret", clock=clock)

    async def issue() -> str:
        return await store.put(
            AuthenticationChallenge(
                challenge=b"c",
                user_id=None,
                created_at=clock.now(),
                expires_at=clock.now() + timedelta(minutes=5),
            )
        )

    assert await store.consume(await issue()) is not None
    clock.advance(timedelta(minutes=6))
    assert await store.consume(await issue()) is not None
    assert len(store._consumed) == 1  # the first, expired entry was dropped


def test_stateless_store_requires_secret() -> None:
    with pytest.raises(ConfigurationError):
        StatelessChallengeStore("")


@pytest.mark.parametrize(
    "payload",
    [
        {},
        {"c": "Yw", "iat": 0, "exp": 1, "k": "nope"},
        {"c": "Yw", "iat": 0, "exp": 1, "k": "register", "u": "not-a-dict"},
        {"c": "Yw", "iat": 0, "exp": 1, "k": "authenticate", "uid": 42},
    ],
)
def test_codec_rejects_malformed_payloads(payload: dict[str, Any]) -> None:
    assert payload_to_challenge(payload) is None


def test_in_memory_store_rejects_zero_capacity() -> None:
    with pytest.raises(ValueError):
        InMemoryChallengeStore(max_entries=0)


# --- Backward compatibility with 0.1-style plug-ins -----------------------------


def _services(config, repo, store, engine, clock):
    kwargs = {
        "config": config,
        "credentials": repo,
        "challenges": store,
        "engine": engine,
        "clock": clock,
    }
    return RegistrationService(**kwargs), AuthenticationService(**kwargs)


class LegacyRepository(InMemoryCredentialRepository):
    """A third-party repository written against the 0.1 Protocol."""

    async def update_usage(  # type: ignore[override]
        self, credential_id: bytes, *, sign_count: int, last_used_at: datetime
    ) -> None:
        await super().update_usage(credential_id, sign_count=sign_count, last_used_at=last_used_at)


async def test_legacy_repository_without_backup_state_still_works(
    config, store, engine, clock, user
) -> None:
    repo = LegacyRepository()
    registration, authentication = _services(config, repo, store, engine, clock)
    authenticator = SoftwareAuthenticator(backup_eligible=True)
    await _register(registration, authenticator, user)
    authenticator.backup_state = True
    options, handle = await authentication.begin(user_id=user.id)
    result = await authentication.finish(
        response=authenticator.get(options, origin=ORIGIN), handle=handle
    )
    assert result.credential.backup_state is True  # reported even if not persisted


class LegacyEngine(PyWebAuthnEngine):
    """A custom engine written against 0.1: no backup flags in its result."""

    def verify_authentication(self, **kwargs: Any) -> VerifiedAuthentication:
        full = super().verify_authentication(**kwargs)
        return VerifiedAuthentication(
            credential_id=full.credential_id,
            new_sign_count=full.new_sign_count,
            user_verified=full.user_verified,
        )


async def test_legacy_engine_without_backup_flags_still_works(
    config, repo, store, clock, authenticator, user
) -> None:
    registration, authentication = _services(config, repo, store, LegacyEngine(), clock)
    await _register(registration, authenticator, user)
    options, handle = await authentication.begin(user_id=user.id)
    result = await authentication.finish(
        response=authenticator.get(options, origin=ORIGIN), handle=handle
    )
    assert result.detail["backup_eligible"] is False


class SwappingEngine(PyWebAuthnEngine):
    """Simulates an engine that reports a different credential than it was given."""

    def verify_authentication(self, **kwargs: Any) -> VerifiedAuthentication:
        return dataclasses.replace(super().verify_authentication(**kwargs), credential_id=b"other")


async def test_engine_credential_id_mismatch_is_rejected(
    config, repo, store, clock, authenticator, user
) -> None:
    registration, authentication = _services(config, repo, store, SwappingEngine(), clock)
    await _register(registration, authenticator, user)
    options, handle = await authentication.begin(user_id=user.id)
    with pytest.raises(AssertionVerificationError):
        await authentication.finish(
            response=authenticator.get(options, origin=ORIGIN), handle=handle
        )


async def test_stateless_store_never_evicts_live_consumed_tokens(clock) -> None:
    # Flooding the consumed-set must not push out a live token's record (that
    # would re-open replay); when full of live records the store fails closed.
    store = StatelessChallengeStore("secret", clock=clock, max_consumed=3)

    async def issue() -> str:
        return await store.put(
            AuthenticationChallenge(
                challenge=secrets.token_bytes(32),
                user_id=None,
                created_at=clock.now(),
                expires_at=clock.now() + timedelta(minutes=5),
            )
        )

    captured = await issue()
    assert await store.consume(captured) is not None
    for _ in range(2):
        assert await store.consume(await issue()) is not None
    assert await store.consume(await issue()) is None  # full of live records: refuse
    assert await store.consume(captured) is None  # replay still blocked
    clock.advance(timedelta(minutes=6))
    assert await store.consume(await issue()) is not None  # capacity returns on expiry
