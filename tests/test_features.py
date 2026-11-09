"""Tests for features added in 0.2.0."""

from __future__ import annotations

import pytest
from fastapi import FastAPI, Request
from httpx import ASGITransport, AsyncClient
from sqlalchemy import insert
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine
from sqlalchemy.pool import StaticPool

from fastapi_passkeys import PasskeyConfig, Passkeys
from fastapi_passkeys._b64 import bytes_to_b64url
from fastapi_passkeys.audit import AuditEvent, AuditEventType
from fastapi_passkeys.contrib.memory import InMemoryChallengeStore, InMemoryCredentialRepository
from fastapi_passkeys.contrib.sqlalchemy import (
    PasskeyBase,
    PasskeyCredential,
    SqlAlchemyCredentialRepository,
)
from fastapi_passkeys.domain.enums import Hint, SignCountPolicy
from fastapi_passkeys.domain.models import PasskeyUser
from fastapi_passkeys.exceptions import (
    AssertionVerificationError,
    CloneDetectedError,
    CredentialLimitReached,
    CredentialNotFound,
)
from fastapi_passkeys.services.authentication import AuthenticationService
from fastapi_passkeys.services.registration import RegistrationService
from fastapi_passkeys.testing import FrozenClock, SoftwareAuthenticator

ORIGIN = "https://example.com"
PREFIX = "/auth/passkeys"


class RecordingSink:
    def __init__(self) -> None:
        self.events: list[AuditEvent] = []

    async def emit(self, event: AuditEvent) -> None:
        self.events.append(event)

    def types(self) -> list[AuditEventType]:
        return [e.type for e in self.events]


def _config(**overrides) -> PasskeyConfig:
    base = {"rp_id": "example.com", "rp_name": "Example", "expected_origins": [ORIGIN]}
    base.update(overrides)
    return PasskeyConfig(**base)


def _services(config, repo, store, engine, clock, sink=None):
    kwargs = {
        "config": config,
        "credentials": repo,
        "challenges": store,
        "engine": engine,
        "clock": clock,
        "audit": sink,
    }
    return RegistrationService(**kwargs), AuthenticationService(**kwargs)


async def _register(registration, authenticator, user):
    options, handle = await registration.begin(user)
    return await registration.finish(
        response=authenticator.create(options, origin=ORIGIN), handle=handle
    )


async def _login(authentication, authenticator, user_id=None, **get_kwargs):
    options, handle = await authentication.begin(user_id=user_id)
    return await authentication.finish(
        response=authenticator.get(options, origin=ORIGIN, **get_kwargs), handle=handle
    )


# --- Hints (WebAuthn L3) --------------------------------------------------------


async def test_hints_are_sent_in_both_ceremonies(repo, store, engine, clock, user) -> None:
    config = _config(hints=[Hint.SECURITY_KEY, Hint.HYBRID])
    registration, authentication = _services(config, repo, store, engine, clock)
    reg_options, _ = await registration.begin(user)
    auth_options, _ = await authentication.begin()
    assert reg_options["hints"] == ["security-key", "hybrid"]
    assert auth_options["hints"] == ["security-key", "hybrid"]


async def test_hints_are_omitted_by_default(registration, user) -> None:
    options, _ = await registration.begin(user)
    assert "hints" not in options


# --- Credential limit -----------------------------------------------------------


async def test_max_credentials_per_user(repo, store, engine, clock, user) -> None:
    registration, _ = _services(_config(max_credentials_per_user=1), repo, store, engine, clock)
    await _register(registration, SoftwareAuthenticator(), user)
    with pytest.raises(CredentialLimitReached):
        await registration.begin(user)


# --- Sign-count policies --------------------------------------------------------


async def test_audit_only_policy_allows_login_but_records_clone(
    repo, store, engine, clock, user, authenticator
) -> None:
    sink = RecordingSink()
    registration, authentication = _services(
        _config(sign_count_policy=SignCountPolicy.AUDIT_ONLY), repo, store, engine, clock, sink
    )
    await _register(registration, authenticator, user)
    await _login(authentication, authenticator, user.id)
    result = await _login(authentication, authenticator, user.id, sign_count=1)
    assert result.user_id == user.id
    assert AuditEventType.CLONE_SUSPECTED in sink.types()


async def test_flag_disable_emits_revocation_event(
    repo, store, engine, clock, user, authenticator
) -> None:
    sink = RecordingSink()
    registration, authentication = _services(
        _config(sign_count_policy=SignCountPolicy.FLAG_DISABLE), repo, store, engine, clock, sink
    )
    await _register(registration, authenticator, user)
    await _login(authentication, authenticator, user.id)
    with pytest.raises(CloneDetectedError):
        await _login(authentication, authenticator, user.id, sign_count=1)
    assert AuditEventType.CREDENTIAL_REVOKED in sink.types()


# --- Backup flags ---------------------------------------------------------------


async def test_backup_state_is_persisted_after_login(registration, authentication, repo, user):
    authenticator = SoftwareAuthenticator(backup_eligible=True, backup_state=False)
    credential = await _register(registration, authenticator, user)
    authenticator.backup_state = True
    await _login(authentication, authenticator, user.id)
    stored = await repo.get_by_credential_id(credential.credential_id)
    assert stored is not None and stored.backup_state is True


async def test_backup_eligibility_change_is_rejected(registration, authentication, user):
    authenticator = SoftwareAuthenticator(backup_eligible=False)
    await _register(registration, authenticator, user)
    authenticator.backup_eligible = True
    with pytest.raises(AssertionVerificationError):
        await _login(authentication, authenticator, user.id)


async def test_backup_eligibility_enforcement_can_be_disabled(
    repo, store, engine, clock, user
) -> None:
    registration, authentication = _services(
        _config(enforce_backup_eligibility=False), repo, store, engine, clock
    )
    authenticator = SoftwareAuthenticator(backup_eligible=False)
    await _register(registration, authenticator, user)
    authenticator.backup_eligible = True
    result = await _login(authentication, authenticator, user.id)
    assert result.detail["backup_eligible"] is True


# --- userHandle escape hatch for migrated credentials ---------------------------


async def test_user_handle_check_can_be_disabled_for_migrations(
    repo, store, engine, clock, user, authenticator
) -> None:
    registration, authentication = _services(
        _config(verify_user_handle=False), repo, store, engine, clock
    )
    await _register(registration, authenticator, user)
    options, handle = await authentication.begin()
    assertion = authenticator.get(options, origin=ORIGIN)
    assertion["response"]["userHandle"] = bytes_to_b64url(b"legacy-handle")
    result = await authentication.finish(response=assertion, handle=handle)
    assert result.user_id == user.id


# --- Result detail --------------------------------------------------------------


async def test_result_reports_authenticator_attachment(
    registration, authentication, authenticator, user
) -> None:
    await _register(registration, authenticator, user)
    result = await _login(authentication, authenticator, user.id)
    assert result.detail["authenticator_attachment"] == "platform"
    assert result.detail["user_verified"] is True


# --- Storage hardening ----------------------------------------------------------


async def _sqlite_repo():
    engine = create_async_engine(
        "sqlite+aiosqlite://", poolclass=StaticPool, connect_args={"check_same_thread": False}
    )
    async with engine.begin() as conn:
        await conn.run_sync(PasskeyBase.metadata.create_all)
    return engine, async_sessionmaker(engine, expire_on_commit=False)


async def test_sqlalchemy_tolerates_unknown_stored_transports() -> None:
    engine, factory = await _sqlite_repo()
    try:
        async with factory() as session:
            await session.execute(
                insert(PasskeyCredential).values(
                    credential_id=b"legacy",
                    user_id="u1",
                    public_key=b"k",
                    sign_count=0,
                    transports=["usb", "smart-card", "from-the-future"],
                )
            )
            await session.commit()
        credential = await SqlAlchemyCredentialRepository(factory).get_by_credential_id(b"legacy")
        assert credential is not None
        assert [t.value for t in credential.transports] == ["usb", "smart-card"]
    finally:
        await engine.dispose()


def test_sqlalchemy_credential_id_is_bounded_varbinary_on_mysql() -> None:
    from sqlalchemy.dialects import mysql
    from sqlalchemy.schema import CreateTable

    ddl = str(CreateTable(PasskeyCredential.__table__).compile(dialect=mysql.dialect()))
    assert "credential_id VARBINARY(1023) NOT NULL" in ddl


# --- HTTP: signals, discoverability, related origins ----------------------------


def _app(config: PasskeyConfig) -> tuple[FastAPI, Passkeys]:
    clock = FrozenClock()

    async def get_user(_: Request) -> PasskeyUser:
        return PasskeyUser(id="user-1", name="ada@example.com", display_name="Ada")

    passkeys = Passkeys(
        config=config,
        credential_repository=InMemoryCredentialRepository(),
        challenge_store=InMemoryChallengeStore(clock=clock),
        get_user=get_user,
        clock=clock,
    )
    app = FastAPI()
    app.include_router(passkeys.router, prefix=PREFIX)
    app.include_router(passkeys.well_known_router)
    passkeys.install_exception_handlers(app)
    return app, passkeys


async def _http_register(client, authenticator, origin=ORIGIN) -> str:
    begin = (await client.post(f"{PREFIX}/register/begin")).json()
    finish = await client.post(
        f"{PREFIX}/register/finish",
        json={
            "credential": authenticator.create(begin["publicKey"], origin=origin),
            "state": begin["state"],
        },
    )
    assert finish.status_code == 200, finish.text
    return str(finish.json()["credentialId"])


async def test_signals_endpoint_reports_accepted_credentials_and_user_details() -> None:
    app, _ = _app(_config())
    async with AsyncClient(transport=ASGITransport(app=app), base_url=ORIGIN) as client:
        cred_id = await _http_register(client, SoftwareAuthenticator())
        body = (await client.get(f"{PREFIX}/credentials/signals")).json()
    user_handle = bytes_to_b64url(b"user-1")
    assert body["allAcceptedCredentials"] == {
        "rpId": "example.com",
        "userId": user_handle,
        "allAcceptedCredentialIds": [cred_id],
    }
    assert body["currentUserDetails"] == {
        "rpId": "example.com",
        "userId": user_handle,
        "name": "ada@example.com",
        "displayName": "Ada",
    }


async def test_unknown_credential_error_carries_signal_payload() -> None:
    app, _ = _app(_config())
    rogue = SoftwareAuthenticator()
    async with AsyncClient(transport=ASGITransport(app=app), base_url=ORIGIN) as client:
        begin = (await client.post(f"{PREFIX}/register/begin")).json()
        rogue.create(begin["publicKey"], origin=ORIGIN)  # never finished
        begin = (await client.post(f"{PREFIX}/authenticate/begin", json={})).json()
        assertion = rogue.get(begin["publicKey"], origin=ORIGIN)
        resp = await client.post(
            f"{PREFIX}/authenticate/finish",
            json={"credential": assertion, "state": begin["state"]},
        )
    assert resp.status_code == 401
    error = resp.json()["error"]
    assert error["code"] == CredentialNotFound.code
    assert error["signal"] == {
        "unknownCredential": {"rpId": "example.com", "credentialId": assertion["rawId"]}
    }


async def test_credential_view_exposes_aaguid_and_discoverability() -> None:
    app, _ = _app(_config())
    aaguid = bytes.fromhex("fbfc3007154e4ecc8c0b6e020557d7bd")
    async with AsyncClient(transport=ASGITransport(app=app), base_url=ORIGIN) as client:
        await _http_register(client, SoftwareAuthenticator(aaguid=aaguid, resident_key=True))
        listing = (await client.get(f"{PREFIX}/credentials")).json()
    assert listing[0]["aaguid"] == "fbfc3007-154e-4ecc-8c0b-6e020557d7bd"
    assert listing[0]["discoverable"] is True


async def test_related_origins_are_served_and_accepted() -> None:
    related = "https://example.co.uk"
    app, _ = _app(_config(related_origins=[related]))
    async with AsyncClient(transport=ASGITransport(app=app), base_url=ORIGIN) as client:
        well_known = (await client.get("/.well-known/webauthn")).json()
        assert well_known == {"origins": [ORIGIN, related]}
        await _http_register(client, SoftwareAuthenticator(), origin=related)


async def test_well_known_route_is_404_without_related_origins() -> None:
    app, _ = _app(_config())
    async with AsyncClient(transport=ASGITransport(app=app), base_url=ORIGIN) as client:
        assert (await client.get("/.well-known/webauthn")).status_code == 404
