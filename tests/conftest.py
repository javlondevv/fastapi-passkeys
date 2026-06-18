from __future__ import annotations

import pytest

from fastapi_passkeys import PasskeyConfig
from fastapi_passkeys.contrib.memory import InMemoryChallengeStore, InMemoryCredentialRepository
from fastapi_passkeys.domain.models import PasskeyUser
from fastapi_passkeys.engine.pywebauthn import PyWebAuthnEngine
from fastapi_passkeys.services.authentication import AuthenticationService
from fastapi_passkeys.services.registration import RegistrationService
from fastapi_passkeys.testing import FrozenClock, SoftwareAuthenticator

ORIGIN = "https://example.com"


@pytest.fixture
def config() -> PasskeyConfig:
    return PasskeyConfig(
        rp_id="example.com",
        rp_name="Example",
        expected_origins=[ORIGIN],
    )


@pytest.fixture
def clock() -> FrozenClock:
    return FrozenClock()


@pytest.fixture
def repo() -> InMemoryCredentialRepository:
    return InMemoryCredentialRepository()


@pytest.fixture
def store(clock: FrozenClock) -> InMemoryChallengeStore:
    return InMemoryChallengeStore(clock=clock)


@pytest.fixture
def engine() -> PyWebAuthnEngine:
    return PyWebAuthnEngine()


@pytest.fixture
def registration(config, repo, store, engine, clock) -> RegistrationService:
    return RegistrationService(
        config=config, credentials=repo, challenges=store, engine=engine, clock=clock
    )


@pytest.fixture
def authentication(config, repo, store, engine, clock) -> AuthenticationService:
    return AuthenticationService(
        config=config, credentials=repo, challenges=store, engine=engine, clock=clock
    )


@pytest.fixture
def authenticator() -> SoftwareAuthenticator:
    return SoftwareAuthenticator()


@pytest.fixture
def user() -> PasskeyUser:
    return PasskeyUser(id="user-1", name="ada@example.com", display_name="Ada Lovelace")
