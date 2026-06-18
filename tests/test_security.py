"""Security-property tests: replay, expiry, origin, RP, cloning, binding."""

from __future__ import annotations

from datetime import timedelta

import pytest

from fastapi_passkeys import PasskeyConfig
from fastapi_passkeys.domain.enums import SignCountPolicy
from fastapi_passkeys.exceptions import (
    AssertionVerificationError,
    AttestationVerificationError,
    ChallengeNotFound,
    CloneDetectedError,
    CredentialAlreadyExists,
    CredentialNotFound,
)
from fastapi_passkeys.services.authentication import AuthenticationService
from fastapi_passkeys.testing import SoftwareAuthenticator

ORIGIN = "https://example.com"


async def _register(registration, authenticator, user, **kwargs):
    options, handle = await registration.begin(user)
    response = authenticator.create(options, origin=ORIGIN, **kwargs)
    return await registration.finish(response=response, handle=handle)


async def test_replayed_registration_challenge_is_rejected(
    registration, authenticator, user
) -> None:
    options, handle = await registration.begin(user)
    response = authenticator.create(options, origin=ORIGIN)
    await registration.finish(response=response, handle=handle)

    with pytest.raises(ChallengeNotFound):
        await registration.finish(response=response, handle=handle)


async def test_expired_challenge_is_rejected(
    registration, authenticator, user, clock, config
) -> None:
    options, handle = await registration.begin(user)
    response = authenticator.create(options, origin=ORIGIN)
    clock.advance(config.challenge_ttl + timedelta(seconds=1))

    with pytest.raises(ChallengeNotFound):
        await registration.finish(response=response, handle=handle)


async def test_wrong_origin_is_rejected(registration, authenticator, user) -> None:
    options, handle = await registration.begin(user)
    response = authenticator.create(options, origin="https://evil.example")

    with pytest.raises(AttestationVerificationError):
        await registration.finish(response=response, handle=handle)


async def test_wrong_rp_id_is_rejected(registration, authenticator, user) -> None:
    options, handle = await registration.begin(user)
    options["rp"]["id"] = "evil.example"  # authenticator will hash the wrong RP
    response = authenticator.create(options, origin=ORIGIN)

    with pytest.raises(AttestationVerificationError):
        await registration.finish(response=response, handle=handle)


async def test_duplicate_credential_is_rejected(registration, authenticator, user) -> None:
    fixed_id = b"fixed-credential"
    await _register(registration, authenticator, user, credential_id=fixed_id)

    options, handle = await registration.begin(user)
    response = authenticator.create(options, origin=ORIGIN, credential_id=fixed_id)
    with pytest.raises(CredentialAlreadyExists):
        await registration.finish(response=response, handle=handle)


async def test_unknown_credential_is_rejected(registration, authentication, user) -> None:
    # An authenticator that holds a key never persisted to the repository.
    rogue = SoftwareAuthenticator()
    options, _ = await registration.begin(user)
    rogue.create(options, origin=ORIGIN)  # generates a key, but we never finish()

    options, handle = await authentication.begin()
    assertion = rogue.get(options, origin=ORIGIN)
    with pytest.raises(CredentialNotFound):
        await authentication.finish(response=assertion, handle=handle)


async def test_credential_bound_to_other_user_is_rejected(
    registration, authentication, authenticator, user
) -> None:
    await _register(registration, authenticator, user)

    options, handle = await authentication.begin(user_id="someone-else")
    assertion = authenticator.get(options, origin=ORIGIN)
    with pytest.raises(CredentialNotFound):
        await authentication.finish(response=assertion, handle=handle)


async def test_tampered_assertion_is_rejected(
    registration, authentication, authenticator, user
) -> None:
    await _register(registration, authenticator, user)
    options, handle = await authentication.begin(user_id=user.id)
    assertion = authenticator.get(options, origin=ORIGIN)
    assertion["response"]["signature"] = assertion["response"]["signature"][:-4] + "AAAA"

    with pytest.raises(AssertionVerificationError):
        await authentication.finish(response=assertion, handle=handle)


async def test_clone_detected_on_sign_count_regression(
    registration, authentication, authenticator, user
) -> None:
    await _register(registration, authenticator, user)

    options, handle = await authentication.begin(user_id=user.id)
    await authentication.finish(response=authenticator.get(options, origin=ORIGIN), handle=handle)

    # Replay with a counter that does not advance — the clone signal.
    options, handle = await authentication.begin(user_id=user.id)
    frozen = authenticator.get(options, origin=ORIGIN, sign_count=1)
    with pytest.raises(CloneDetectedError):
        await authentication.finish(response=frozen, handle=handle)


async def test_flag_disable_policy_revokes_cloned_credential(
    registration, authenticator, user, repo, store, engine, clock
) -> None:
    flag_config = PasskeyConfig(
        rp_id="example.com",
        rp_name="Example",
        expected_origins=[ORIGIN],
        sign_count_policy=SignCountPolicy.FLAG_DISABLE,
    )
    authentication = AuthenticationService(
        config=flag_config, credentials=repo, challenges=store, engine=engine, clock=clock
    )
    credential = await _register(registration, authenticator, user)

    options, handle = await authentication.begin(user_id=user.id)
    await authentication.finish(response=authenticator.get(options, origin=ORIGIN), handle=handle)

    options, handle = await authentication.begin(user_id=user.id)
    frozen = authenticator.get(options, origin=ORIGIN, sign_count=1)
    with pytest.raises(CloneDetectedError):
        await authentication.finish(response=frozen, handle=handle)

    assert await repo.get_by_credential_id(credential.credential_id) is None
