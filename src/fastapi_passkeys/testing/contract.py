"""Reusable conformance suite for storage adapters.

Call these from your own test module to prove a custom repository or challenge
store behaves correctly — the shipped SQLAlchemy/Redis/in-memory adapters are
verified the same way::

    import pytest
    from fastapi_passkeys.testing import check_credential_repository

    @pytest.mark.asyncio
    async def test_my_repo():
        await check_credential_repository(MyRepository)
"""

from __future__ import annotations

from collections.abc import Callable
from datetime import timedelta

from fastapi_passkeys.domain.models import (
    AuthenticationChallenge,
    Credential,
    PasskeyUser,
    RegistrationChallenge,
)
from fastapi_passkeys.repositories.challenges import ChallengeStore
from fastapi_passkeys.repositories.credentials import CredentialRepository
from fastapi_passkeys.services.clock import Clock
from fastapi_passkeys.testing.clock import FrozenClock


def _sample_credential(user_id: str = "user-1") -> Credential:
    return Credential(
        credential_id=b"cred-id-0001",
        user_id=user_id,
        public_key=b"cose-public-key",
        sign_count=0,
        device_name="Test Key",
    )


async def check_credential_repository(make_repo: Callable[[], CredentialRepository]) -> None:
    """Assert a :class:`CredentialRepository` implementation is correct."""
    repo = make_repo()
    cred = _sample_credential()

    assert await repo.get_by_credential_id(cred.credential_id) is None
    assert await repo.list_by_user(cred.user_id) == []

    await repo.add(cred)
    fetched = await repo.get_by_credential_id(cred.credential_id)
    assert fetched is not None
    assert fetched.user_id == cred.user_id
    assert fetched.public_key == cred.public_key

    listed = await repo.list_by_user(cred.user_id)
    assert [c.credential_id for c in listed] == [cred.credential_id]

    used_at = FrozenClock().now() + timedelta(minutes=1)
    await repo.update_usage(cred.credential_id, sign_count=42, last_used_at=used_at)
    after = await repo.get_by_credential_id(cred.credential_id)
    assert after is not None and after.sign_count == 42

    await repo.rename(cred.credential_id, cred.user_id, "Renamed")
    renamed = await repo.get_by_credential_id(cred.credential_id)
    assert renamed is not None and renamed.device_name == "Renamed"

    # Wrong-user operations must be no-ops, not cross-tenant mutations.
    await repo.rename(cred.credential_id, "intruder", "Hacked")
    await repo.delete(cred.credential_id, "intruder")
    still_there = await repo.get_by_credential_id(cred.credential_id)
    assert still_there is not None and still_there.device_name == "Renamed"

    await repo.delete(cred.credential_id, cred.user_id)
    assert await repo.get_by_credential_id(cred.credential_id) is None


async def check_challenge_store(
    make_store: Callable[[Clock], ChallengeStore],
    *,
    single_use: bool = True,
) -> None:
    """Assert a :class:`ChallengeStore` implementation is correct.

    Set ``single_use=False`` for stores (like the stateless one) that cannot
    enforce single-use at the challenge layer; the replay assertion is skipped.
    """
    clock = FrozenClock()
    store = make_store(clock)

    reg = RegistrationChallenge(
        challenge=b"reg-challenge-bytes",
        user=PasskeyUser(id="user-1", name="user@example.com", display_name="User One"),
        created_at=clock.now(),
        expires_at=clock.now() + timedelta(minutes=5),
    )
    handle = await store.put(reg)
    got = await store.consume(handle)
    assert isinstance(got, RegistrationChallenge)
    assert got.challenge == reg.challenge
    assert got.user.id == "user-1"

    if single_use:
        assert await store.consume(handle) is None

    # Expiry is enforced regardless of single-use semantics.
    auth = AuthenticationChallenge(
        challenge=b"auth-challenge-bytes",
        user_id=None,
        created_at=clock.now(),
        expires_at=clock.now() + timedelta(minutes=5),
    )
    expiring_handle = await store.put(auth)
    clock.advance(timedelta(minutes=6))
    assert await store.consume(expiring_handle) is None

    # An unknown handle yields None, never an error.
    assert await store.consume("definitely-not-a-handle") is None
