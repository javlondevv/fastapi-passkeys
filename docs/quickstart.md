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
    # Return the *authenticated* user — from your session or a verified sign-up
    # token. Never trust an email/user id sent by the client: whoever this
    # returns is who the new passkey is attached to.
    account = await current_account(request)  # your auth; raise HTTPException(401) if none
    return PasskeyUser(
        id=account.passkey_id,          # opaque, stable, 1-64 bytes (e.g. a UUID) — not an email
        name=account.email,             # shown in the passkey picker
        display_name=account.full_name,
    )


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

`register/finish` and the credential-management endpoints call `get_user` again, so the
ceremony stays bound to the user who started it.

!!! warning "Running more than one worker?"
    The default challenge store is in-memory and per-process. With `uvicorn --workers 4`
    (or several pods), `begin` and `finish` can hit different processes and fail with
    `challenge_not_found`. Pass `challenge_store=RedisChallengeStore(...)`.

## Frontend

Use the browser's JSON helpers where available —
`PublicKeyCredential.parseCreationOptionsFromJSON(begin.publicKey)` /
`parseRequestOptionsFromJSON(...)` and `credential.toJSON()` — and fall back to manual
base64url conversion elsewhere. If you convert by hand, handle `Uint8Array` as well as
`ArrayBuffer` (some password managers return typed arrays).

The wire format the `finish` endpoints expect is the standard WebAuthn JSON encoding:

```json
{
  "state": "<from begin>",
  "credential": {
    "id": "<base64url>", "rawId": "<base64url>", "type": "public-key",
    "authenticatorAttachment": "platform",
    "clientExtensionResults": {"credProps": {"rk": true}},
    "response": {
      "clientDataJSON": "<base64url>",
      "attestationObject": "<base64url, registration>",
      "transports": ["internal", "hybrid"],
      "authenticatorData": "<base64url, authentication>",
      "signature": "<base64url, authentication>",
      "userHandle": "<base64url or null, authentication>"
    }
  }
}
```

**Autofill (conditional UI):** add `autocomplete="username webauthn"` to your username
field and call `authenticate/begin` with no `userId`, then
`navigator.credentials.get({publicKey, mediation: "conditional", signal})`. Abort that
request (`AbortController`) before starting a modal one — browsers allow only one pending
WebAuthn request.

**Signal API:** when `authenticate/finish` fails with `credential_not_found`, the error body
carries `error.signal.unknownCredential`; pass it to
`PublicKeyCredential.signalUnknownCredential()` so the passkey provider forgets a credential
you deleted. `GET /credentials/signals` returns ready-made payloads for
`signalAllAcceptedCredentials()` and `signalCurrentUserDetails()`.

A complete, runnable browser example lives in [`examples/app.py`](https://github.com/javlondevv/fastapi-passkeys/blob/main/examples/app.py).

## Need full control?

Skip the router and drive the services directly:

```python
options, state = await passkeys.registration.begin(user)
credential = await passkeys.registration.finish(response=response, handle=state)
```
