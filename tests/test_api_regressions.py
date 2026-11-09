"""HTTP-level regression tests for the 0.2.0 audit (router behaviour)."""

from __future__ import annotations

import pytest
from fastapi import FastAPI, HTTPException, Request
from httpx import ASGITransport, AsyncClient

from fastapi_passkeys import PasskeyConfig, Passkeys
from fastapi_passkeys.audit import AuditEvent, AuditEventType
from fastapi_passkeys.contrib.memory import InMemoryChallengeStore, InMemoryCredentialRepository
from fastapi_passkeys.domain.models import PasskeyUser
from fastapi_passkeys.testing import FrozenClock, SoftwareAuthenticator

ORIGIN = "https://example.com"
PREFIX = "/auth/passkeys"


class RecordingSink:
    def __init__(self) -> None:
        self.events: list[AuditEvent] = []

    async def emit(self, event: AuditEvent) -> None:
        self.events.append(event)


@pytest.fixture
def sink() -> RecordingSink:
    return RecordingSink()


@pytest.fixture
def app(sink: RecordingSink) -> FastAPI:
    """An app whose `get_user` trusts an `X-User` header (stand-in for a session)."""
    clock = FrozenClock()

    async def get_user(request: Request) -> PasskeyUser:
        uid = request.headers.get("x-user")
        if not uid:
            raise HTTPException(status_code=401)
        return PasskeyUser(id=uid, name=f"{uid}@example.com", display_name=uid)

    passkeys = Passkeys(
        config=PasskeyConfig(rp_id="example.com", rp_name="Example", expected_origins=[ORIGIN]),
        credential_repository=InMemoryCredentialRepository(),
        challenge_store=InMemoryChallengeStore(clock=clock),
        get_user=get_user,
        clock=clock,
        audit=sink,
    )
    application = FastAPI()
    application.include_router(passkeys.router, prefix=PREFIX)
    passkeys.install_exception_handlers(application)
    return application


async def _register(client: AsyncClient, uid: str, authenticator: SoftwareAuthenticator) -> str:
    begin = (await client.post(f"{PREFIX}/register/begin", headers={"x-user": uid})).json()
    response = authenticator.create(begin["publicKey"], origin=ORIGIN)
    finish = await client.post(
        f"{PREFIX}/register/finish",
        json={"credential": response, "state": begin["state"]},
        headers={"x-user": uid},
    )
    assert finish.status_code == 200, finish.text
    return str(finish.json()["credentialId"])


async def test_f2_register_finish_rejects_handle_started_by_another_user(app: FastAPI) -> None:
    async with AsyncClient(transport=ASGITransport(app=app), base_url=ORIGIN) as client:
        begin = (await client.post(f"{PREFIX}/register/begin", headers={"x-user": "alice"})).json()
        attacker_key = SoftwareAuthenticator().create(begin["publicKey"], origin=ORIGIN)
        resp = await client.post(
            f"{PREFIX}/register/finish",
            json={"credential": attacker_key, "state": begin["state"]},
            headers={"x-user": "mallory"},
        )
        assert resp.status_code == 400
        alice = await client.get(f"{PREFIX}/credentials", headers={"x-user": "alice"})
        assert alice.json() == []


async def test_f6_delete_foreign_credential_is_404_and_not_audited(
    app: FastAPI, sink: RecordingSink
) -> None:
    async with AsyncClient(transport=ASGITransport(app=app), base_url=ORIGIN) as client:
        cred_id = await _register(client, "alice", SoftwareAuthenticator())
        sink.events.clear()

        resp = await client.delete(f"{PREFIX}/credentials/{cred_id}", headers={"x-user": "bob"})
        assert resp.status_code == 404
        assert resp.json()["error"]["code"] == "credential_not_found"
        assert not [e for e in sink.events if e.type is AuditEventType.CREDENTIAL_REVOKED]

        alice = (await client.get(f"{PREFIX}/credentials", headers={"x-user": "alice"})).json()
        assert [c["id"] for c in alice] == [cred_id]


@pytest.mark.parametrize("cred_id", ["AAAA", "not!valid"])
async def test_f6_delete_unknown_credential_is_404(app: FastAPI, cred_id: str) -> None:
    async with AsyncClient(transport=ASGITransport(app=app), base_url=ORIGIN) as client:
        resp = await client.delete(f"{PREFIX}/credentials/{cred_id}", headers={"x-user": "bob"})
        assert resp.status_code == 404


async def test_f6_rename_foreign_credential_is_404(app: FastAPI) -> None:
    async with AsyncClient(transport=ASGITransport(app=app), base_url=ORIGIN) as client:
        cred_id = await _register(client, "alice", SoftwareAuthenticator())
        resp = await client.patch(
            f"{PREFIX}/credentials/{cred_id}",
            json={"deviceName": "pwned"},
            headers={"x-user": "bob"},
        )
        assert resp.status_code == 404


@pytest.mark.parametrize("name", ["x" * 65, "", "   ", "bad\x00name"])
async def test_f6_rename_rejects_invalid_device_names(app: FastAPI, name: str) -> None:
    async with AsyncClient(transport=ASGITransport(app=app), base_url=ORIGIN) as client:
        cred_id = await _register(client, "alice", SoftwareAuthenticator())
        resp = await client.patch(
            f"{PREFIX}/credentials/{cred_id}",
            json={"deviceName": name},
            headers={"x-user": "alice"},
        )
        assert resp.status_code == 422


async def test_f6_rename_strips_whitespace(app: FastAPI) -> None:
    async with AsyncClient(transport=ASGITransport(app=app), base_url=ORIGIN) as client:
        cred_id = await _register(client, "alice", SoftwareAuthenticator())
        resp = await client.patch(
            f"{PREFIX}/credentials/{cred_id}",
            json={"deviceName": "  Work laptop  "},
            headers={"x-user": "alice"},
        )
        assert resp.status_code == 204
        listing = (await client.get(f"{PREFIX}/credentials", headers={"x-user": "alice"})).json()
        assert listing[0]["deviceName"] == "Work laptop"


async def test_f6_oversized_state_and_user_id_are_rejected(app: FastAPI) -> None:
    async with AsyncClient(transport=ASGITransport(app=app), base_url=ORIGIN) as client:
        resp = await client.post(f"{PREFIX}/authenticate/begin", json={"userId": "u" * 1000})
        assert resp.status_code == 422
        resp = await client.post(
            f"{PREFIX}/authenticate/finish", json={"credential": {}, "state": "s" * 10_000}
        )
        assert resp.status_code == 422
