# Quickstart

## Install

```bash
pip install fastapi-passkeys
```

## Wire it up

You provide two hooks and a storage backend; the library provides the router.

```python
from fastapi import FastAPI, Request
from fastapi_passkeys import Passkeys, PasskeyConfig, PasskeyUser, AuthenticationResult
from fastapi_passkeys.contrib import InMemoryCredentialRepository


async def get_user(request: Request) -> PasskeyUser:
    # However your app identifies the in-progress user: a signup token, an
    # existing session, an email from the request body, etc.
    return PasskeyUser(id="user-123", name="ada@example.com", display_name="Ada Lovelace")


async def on_authenticated(request: Request, result: AuthenticationResult) -> dict:
    # The passkey is verified. Now mint *your* session or token.
    return {"access_token": issue_token(result.user_id)}


passkeys = Passkeys(
    config=PasskeyConfig(
        rp_id="example.com",
        rp_name="Example",
        expected_origins=["https://example.com"],
    ),
    credential_repository=InMemoryCredentialRepository(),
    get_user=get_user,
    on_authenticated=on_authenticated,
)

app = FastAPI()
app.include_router(passkeys.router, prefix="/auth/passkeys")
passkeys.install_exception_handlers(app)
```

## The two round-trips

Each ceremony is `begin` then `finish`. `begin` returns the options your frontend passes to
`navigator.credentials.create()` / `.get()`, plus an opaque `state` handle. Echo that `state`
back to `finish` alongside the authenticator's response. The challenge is single-use and
TTL-bound — no server session is required between the calls.

```
POST /auth/passkeys/register/begin      -> { publicKey, state }
POST /auth/passkeys/register/finish     <- { credential, state, deviceName? }

POST /auth/passkeys/authenticate/begin  -> { publicKey, state }
POST /auth/passkeys/authenticate/finish <- { credential, state }
```

A complete, runnable browser example lives in [`examples/app.py`](https://github.com/javlondevv/fastapi-passkeys/blob/main/examples/app.py).

## Need full control?

Skip the router and drive the services directly:

```python
options, state = await passkeys.registration.begin(user)
credential = await passkeys.registration.finish(response=response, handle=state)
```
