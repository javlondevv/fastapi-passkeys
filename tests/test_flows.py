"""End-to-end registration and authentication flows with real signatures."""

from __future__ import annotations

from fastapi_passkeys.domain.models import AuthenticationResult, Credential

ORIGIN = "https://example.com"


async def _register(registration, authenticator, user) -> Credential:
    options, handle = await registration.begin(user)
    response = authenticator.create(options, origin=ORIGIN)
    return await registration.finish(response=response, handle=handle, device_name="My Laptop")


async def test_registration_persists_full_credential(
    registration, authenticator, user, repo
) -> None:
    credential = await _register(registration, authenticator, user)

    assert credential.user_id == user.id
    assert credential.device_name == "My Laptop"
    assert credential.public_key  # COSE key stored, not an opaque token
    assert credential.sign_count == 0
    assert credential.created_at is not None

    stored = await repo.get_by_credential_id(credential.credential_id)
    assert stored is not None
    assert stored.public_key == credential.public_key


async def test_authentication_round_trip(registration, authentication, authenticator, user) -> None:
    await _register(registration, authenticator, user)

    options, handle = await authentication.begin(user_id=user.id)
    assertion = authenticator.get(options, origin=ORIGIN)
    result = await authentication.finish(response=assertion, handle=handle)

    assert isinstance(result, AuthenticationResult)
    assert result.user_id == user.id
    assert result.credential.sign_count == 1  # counter advanced from 0


async def test_usernameless_authentication(
    registration, authentication, authenticator, user
) -> None:
    await _register(registration, authenticator, user)

    options, handle = await authentication.begin()  # no user_id
    assertion = authenticator.get(options, origin=ORIGIN)
    result = await authentication.finish(response=assertion, handle=handle)

    assert result.user_id == user.id


async def test_sign_count_advances_across_logins(
    registration, authentication, authenticator, user
) -> None:
    await _register(registration, authenticator, user)

    counts = []
    for _ in range(3):
        options, handle = await authentication.begin(user_id=user.id)
        assertion = authenticator.get(options, origin=ORIGIN)
        result = await authentication.finish(response=assertion, handle=handle)
        counts.append(result.credential.sign_count)

    assert counts == [1, 2, 3]
