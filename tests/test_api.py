"""Full HTTP flow through the batteries-included router."""

from __future__ import annotations

import pytest
from fastapi import FastAPI, Request
from httpx import ASGITransport, AsyncClient

from fastapi_passkeys import PasskeyConfig, Passkeys
from fastapi_passkeys.contrib.memory import InMemoryChallengeStore, InMemoryCredentialRepository
from fastapi_passkeys.domain.models import AuthenticationResult, PasskeyUser
from fastapi_passkeys.testing import FrozenClock, SoftwareAuthenticator

ORIGIN = "https://example.com"


@pytest.fixture
def app() -> FastAPI:
    clock = FrozenClock()

    async def get_user(_: Request) -> PasskeyUser:
        return PasskeyUser(id="user-1", name="ada@example.com", display_name="Ada")

    async def on_authenticated(_: Request, result: AuthenticationResult) -> dict:
        return {"token": "session-token", "userId": result.user_id}

    passkeys = Passkeys(
        config=PasskeyConfig(rp_id="example.com", rp_name="Example", expected_origins=[ORIGIN]),
        credential_repository=InMemoryCredentialRepository(),
        challenge_store=InMemoryChallengeStore(clock=clock),
        get_user=get_user,
        on_authenticated=on_authenticated,
        clock=clock,
    )
    application = FastAPI()
    application.include_router(passkeys.router, prefix="/auth/passkeys")
    passkeys.install_exception_handlers(application)
    return application


async def test_full_http_lifecycle(app: FastAPI) -> None:
    authenticator = SoftwareAuthenticator()
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url=ORIGIN) as client:
        begin = (await client.post("/auth/passkeys/register/begin")).json()
        response = authenticator.create(begin["publicKey"], origin=ORIGIN)
        finish = await client.post(
            "/auth/passkeys/register/finish",
            json={"credential": response, "state": begin["state"], "deviceName": "Laptop"},
        )
        assert finish.status_code == 200, finish.text

        listing = (await client.get("/auth/passkeys/credentials")).json()
        assert len(listing) == 1
        assert listing[0]["deviceName"] == "Laptop"
        credential_id = listing[0]["id"]

        begin = (await client.post("/auth/passkeys/authenticate/begin", json={})).json()
        assertion = authenticator.get(begin["publicKey"], origin=ORIGIN)
        auth = await client.post(
            "/auth/passkeys/authenticate/finish",
            json={"credential": assertion, "state": begin["state"]},
        )
        assert auth.status_code == 200, auth.text
        assert auth.json() == {"token": "session-token", "userId": "user-1"}

        rename = await client.patch(
            f"/auth/passkeys/credentials/{credential_id}", json={"deviceName": "Renamed"}
        )
        assert rename.status_code == 204

        delete = await client.delete(f"/auth/passkeys/credentials/{credential_id}")
        assert delete.status_code == 204
        assert (await client.get("/auth/passkeys/credentials")).json() == []


async def test_error_responses_are_structured(app: FastAPI) -> None:
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url=ORIGIN) as client:
        resp = await client.post(
            "/auth/passkeys/register/finish",
            json={
                "credential": {"id": "AA", "rawId": "AA", "type": "public-key", "response": {}},
                "state": "not-a-real-handle",
            },
        )
        assert resp.status_code == 400
        assert resp.json()["error"]["code"] == "challenge_not_found"
