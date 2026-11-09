"""Regression tests for defects found in the 0.2.0 audit.

Each test reproduces a confirmed defect against the 0.1.x code base. See
``docs/audit.md`` for the mapping from finding id (``F*``) to root cause.
"""

from __future__ import annotations

from datetime import timedelta

import pytest

from fastapi_passkeys import PasskeyConfig
from fastapi_passkeys._b64 import b64url_to_bytes, bytes_to_b64url
from fastapi_passkeys.audit import AuditEvent
from fastapi_passkeys.contrib.memory import InMemoryChallengeStore
from fastapi_passkeys.contrib.stateless import StatelessChallengeStore
from fastapi_passkeys.domain.models import AuthenticationChallenge, PasskeyUser
from fastapi_passkeys.exceptions import (
    ChallengeNotFound,
    ConfigurationError,
    CredentialNotFound,
    RegistrationError,
)
from fastapi_passkeys.services.authentication import AuthenticationService
from fastapi_passkeys.services.registration import RegistrationService
from fastapi_passkeys.testing import SoftwareAuthenticator

ORIGIN = "https://example.com"


async def _register(registration, authenticator, user):
    options, handle = await registration.begin(user)
    response = authenticator.create(options, origin=ORIGIN)
    return await registration.finish(response=response, handle=handle)


# --- F1: userHandle must identify the credential's owner -------------------------


async def test_f1_usernameless_rejects_mismatched_user_handle(
    registration, authentication, authenticator, user
) -> None:
    await _register(registration, authenticator, user)
    options, handle = await authentication.begin()
    assertion = authenticator.get(options, origin=ORIGIN)
    # userHandle is not covered by the signature; a client can rewrite it freely.
    assertion["response"]["userHandle"] = bytes_to_b64url(b"someone-else")

    with pytest.raises(CredentialNotFound):
        await authentication.finish(response=assertion, handle=handle)


async def test_f1_usernameless_requires_user_handle(
    registration, authentication, authenticator, user
) -> None:
    await _register(registration, authenticator, user)
    options, handle = await authentication.begin()
    assertion = authenticator.get(options, origin=ORIGIN)
    assertion["response"]["userHandle"] = None

    with pytest.raises(CredentialNotFound):
        await authentication.finish(response=assertion, handle=handle)


async def test_f1_user_bound_flow_tolerates_absent_user_handle(
    registration, authentication, authenticator, user
) -> None:
    # Non-discoverable credentials may legitimately omit userHandle when the
    # user was identified up front (WebAuthn §7.2 step 6).
    await _register(registration, authenticator, user)
    options, handle = await authentication.begin(user_id=user.id)
    assertion = authenticator.get(options, origin=ORIGIN)
    assertion["response"]["userHandle"] = None

    result = await authentication.finish(response=assertion, handle=handle)
    assert result.user_id == user.id


# --- F2: registration finish is bound to the user who began it -------------------


async def test_f2_registration_finish_rejects_different_user(
    registration, authenticator, user
) -> None:
    options, handle = await registration.begin(user)
    response = authenticator.create(options, origin=ORIGIN)
    intruder = PasskeyUser(id="intruder", name="eve@example.com", display_name="Eve")

    with pytest.raises(RegistrationError):
        await registration.finish(response=response, handle=handle, user=intruder)


# --- F3: stateless store must not accept a replayed handle -----------------------


async def test_f3_stateless_store_rejects_replayed_assertion_with_zero_counter(
    config, repo, engine, clock, user
) -> None:
    # Synced passkeys (iCloud Keychain, Google Password Manager) always report a
    # signature counter of 0, so the counter check cannot catch a replay.
    store = StatelessChallengeStore("s3cret-for-tests", clock=clock)
    registration = RegistrationService(
        config=config, credentials=repo, challenges=store, engine=engine, clock=clock
    )
    authentication = AuthenticationService(
        config=config, credentials=repo, challenges=store, engine=engine, clock=clock
    )
    authenticator = SoftwareAuthenticator()
    await _register(registration, authenticator, user)

    options, handle = await authentication.begin()
    assertion = authenticator.get(options, origin=ORIGIN, sign_count=0)
    await authentication.finish(response=assertion, handle=handle)

    with pytest.raises(ChallengeNotFound):
        await authentication.finish(response=assertion, handle=handle)


# --- F4: in-memory challenge store must not grow without bound -------------------


async def test_f4_in_memory_store_evicts_expired_challenges(clock) -> None:
    store = InMemoryChallengeStore(clock=clock)
    for _ in range(500):
        await store.put(
            AuthenticationChallenge(
                challenge=b"c",
                user_id=None,
                created_at=clock.now(),
                expires_at=clock.now() + timedelta(minutes=5),
            )
        )
    clock.advance(timedelta(minutes=6))
    await store.put(
        AuthenticationChallenge(
            challenge=b"c",
            user_id=None,
            created_at=clock.now(),
            expires_at=clock.now() + timedelta(minutes=5),
        )
    )
    assert len(store) == 1


async def test_f4_in_memory_store_caps_live_challenges(clock) -> None:
    store = InMemoryChallengeStore(clock=clock, max_entries=10)
    handles = [
        await store.put(
            AuthenticationChallenge(
                challenge=b"c",
                user_id=None,
                created_at=clock.now(),
                expires_at=clock.now() + timedelta(minutes=5),
            )
        )
        for _ in range(25)
    ]
    assert len(store) == 10
    assert await store.consume(handles[0]) is None  # oldest evicted
    assert await store.consume(handles[-1]) is not None


# --- F5: configuration normalization and validation -----------------------------


def _cfg(**overrides):
    base = {"rp_id": "example.com", "rp_name": "Example", "expected_origins": [ORIGIN]}
    base.update(overrides)
    return PasskeyConfig(**base)


@pytest.mark.parametrize(
    "raw",
    [
        "https://example.com/",
        "https://EXAMPLE.com",
        "https://example.com:443",
        "HTTPS://example.com",
    ],
)
def test_f5_origins_are_normalized_to_browser_serialization(raw: str) -> None:
    assert _cfg(expected_origins=[raw]).expected_origins == ["https://example.com"]


def test_f5_non_default_port_is_preserved() -> None:
    cfg = _cfg(rp_id="localhost", expected_origins=["http://localhost:8000"])
    assert cfg.expected_origins == ["http://localhost:8000"]


def test_f5_subdomain_origin_is_allowed() -> None:
    assert _cfg(expected_origins=["https://login.example.com"]).expected_origins


@pytest.mark.parametrize(
    "origin", ["https://evil.com", "https://notexample.com", "https://example.com.evil.com"]
)
def test_f5_origin_outside_rp_id_is_rejected(origin: str) -> None:
    with pytest.raises(ValueError, match="rp_id"):
        _cfg(expected_origins=[origin])


@pytest.mark.parametrize("rp_id", ["https://example.com", "example.com:8000", "example.com/"])
def test_f5_rp_id_must_be_a_bare_domain(rp_id: str) -> None:
    with pytest.raises(ValueError, match="rp_id"):
        _cfg(rp_id=rp_id)


def test_f5_rp_id_is_lowercased() -> None:
    assert _cfg(rp_id="Example.COM").rp_id == "example.com"


def test_f5_android_app_origin_is_accepted() -> None:
    origin = "android:apk-key-hash:Q1nB2xHbXg1H0p8eQ3U2zQ1nB2xHbXg1H0p8eQ3U2zQ"
    assert origin in _cfg(expected_origins=[ORIGIN, origin]).expected_origins


@pytest.mark.parametrize("ttl", [timedelta(0), timedelta(seconds=-1)])
def test_f5_non_positive_challenge_ttl_is_rejected(ttl: timedelta) -> None:
    with pytest.raises(ValueError, match="challenge_ttl"):
        _cfg(challenge_ttl=ttl)


# --- F7: miscellaneous hardening ------------------------------------------------


async def test_f7_user_handle_over_64_bytes_is_rejected(registration) -> None:
    long_user = PasskeyUser(id="u" * 65, name="a@example.com", display_name="A")
    with pytest.raises(ConfigurationError):
        await registration.begin(long_user)


async def test_f7_empty_display_name_falls_back_to_name(registration) -> None:
    # 1Password and others refuse an empty displayName (django-passkeys #58/#76).
    options, _ = await registration.begin(
        PasskeyUser(id="u1", name="ada@example.com", display_name="")
    )
    assert options["user"]["displayName"] == "ada@example.com"


@pytest.mark.parametrize("value", ["ab!c", "ab+c", "ab/c", "ab c"])
def test_f7_b64url_decoding_is_strict(value: str) -> None:
    with pytest.raises(ValueError):
        b64url_to_bytes(value)


async def test_f7_failing_audit_sink_does_not_break_ceremony(
    config, repo, store, engine, clock, authenticator, user
) -> None:
    class ExplodingSink:
        async def emit(self, event: AuditEvent) -> None:
            raise RuntimeError("log pipeline down")

    registration = RegistrationService(
        config=config,
        credentials=repo,
        challenges=store,
        engine=engine,
        clock=clock,
        audit=ExplodingSink(),
    )
    credential = await _register(registration, authenticator, user)
    assert await repo.get_by_credential_id(credential.credential_id) is not None


async def test_f7_discoverability_comes_from_cred_props(registration, user) -> None:
    authenticator = SoftwareAuthenticator(resident_key=True)
    options, handle = await registration.begin(user)
    assert options["extensions"]["credProps"] is True
    response = authenticator.create(options, origin=ORIGIN)
    credential = await registration.finish(response=response, handle=handle)
    assert credential.is_discoverable is True


async def test_f7_authentication_reports_current_backup_state(
    registration, authentication, user
) -> None:
    authenticator = SoftwareAuthenticator(backup_eligible=True, backup_state=False)
    await _register(registration, authenticator, user)
    authenticator.backup_state = True  # the passkey has since been synced

    options, handle = await authentication.begin(user_id=user.id)
    result = await authentication.finish(
        response=authenticator.get(options, origin=ORIGIN), handle=handle
    )
    assert result.credential.backup_state is True
    assert result.detail["backup_state"] is True
