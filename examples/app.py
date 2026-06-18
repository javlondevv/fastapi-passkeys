"""Runnable passkeys demo.

    pip install "fastapi-passkeys" uvicorn
    uvicorn examples.app:app --reload

Then open http://localhost:8000 and register / sign in with a real authenticator
(Touch ID, Windows Hello, a security key, your phone). This is a demo: it uses the
in-memory repository and a single hard-coded user, so data resets on restart.
"""

from __future__ import annotations

from fastapi import FastAPI, Request
from fastapi.responses import HTMLResponse

from fastapi_passkeys import AuthenticationResult, Passkeys, PasskeyConfig, PasskeyUser
from fastapi_passkeys.contrib import InMemoryChallengeStore, InMemoryCredentialRepository

DEMO_USER = PasskeyUser(id="demo-user", name="ada@example.com", display_name="Ada Lovelace")


async def get_user(_: Request) -> PasskeyUser:
    return DEMO_USER


async def on_authenticated(_: Request, result: AuthenticationResult) -> dict:
    return {"status": "signed-in", "userId": result.user_id}


passkeys = Passkeys(
    config=PasskeyConfig(
        rp_id="localhost",
        rp_name="fastapi-passkeys demo",
        expected_origins=["http://localhost:8000"],
    ),
    credential_repository=InMemoryCredentialRepository(),
    challenge_store=InMemoryChallengeStore(),
    get_user=get_user,
    on_authenticated=on_authenticated,
)

app = FastAPI(title="fastapi-passkeys demo")
app.include_router(passkeys.router, prefix="/auth/passkeys")
passkeys.install_exception_handlers(app)


@app.get("/", response_class=HTMLResponse)
async def index() -> str:
    return _PAGE


_PAGE = """<!doctype html>
<html><head><meta charset="utf-8"><title>fastapi-passkeys demo</title>
<style>body{font-family:system-ui;max-width:40rem;margin:4rem auto;padding:0 1rem}
button{font-size:1rem;padding:.6rem 1rem;margin:.25rem 0;cursor:pointer}
pre{background:#f4f4f5;padding:1rem;border-radius:.5rem;white-space:pre-wrap}</style>
</head><body>
<h1>fastapi-passkeys demo</h1>
<button onclick="register()">Register a passkey</button>
<button onclick="authenticate()">Sign in</button>
<pre id="out">Ready.</pre>
<script>
const out = document.getElementById('out');
const log = (m) => out.textContent = (typeof m === 'string' ? m : JSON.stringify(m, null, 2));

const b64urlToBuf = (s) => {
  s = s.replace(/-/g, '+').replace(/_/g, '/');
  const pad = '='.repeat((4 - (s.length % 4)) % 4);
  const bin = atob(s + pad);
  const buf = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) buf[i] = bin.charCodeAt(i);
  return buf.buffer;
};
const bufToB64url = (buf) => {
  const bytes = new Uint8Array(buf);
  let bin = '';
  for (const b of bytes) bin += String.fromCharCode(b);
  return btoa(bin).replace(/\\+/g, '-').replace(/\\//g, '_').replace(/=+$/, '');
};

async function register() {
  try {
    const begin = await (await fetch('/auth/passkeys/register/begin', {method: 'POST'})).json();
    const opts = begin.publicKey;
    opts.challenge = b64urlToBuf(opts.challenge);
    opts.user.id = b64urlToBuf(opts.user.id);
    (opts.excludeCredentials || []).forEach(c => c.id = b64urlToBuf(c.id));
    const cred = await navigator.credentials.create({publicKey: opts});
    const body = {
      state: begin.state,
      deviceName: 'Demo device',
      credential: {
        id: cred.id, rawId: bufToB64url(cred.rawId), type: cred.type,
        response: {
          clientDataJSON: bufToB64url(cred.response.clientDataJSON),
          attestationObject: bufToB64url(cred.response.attestationObject),
          transports: cred.response.getTransports ? cred.response.getTransports() : [],
        },
        clientExtensionResults: cred.getClientExtensionResults(),
      },
    };
    log(await (await fetch('/auth/passkeys/register/finish',
      {method: 'POST', headers: {'content-type': 'application/json'}, body: JSON.stringify(body)})).json());
  } catch (e) { log('Error: ' + e); }
}

async function authenticate() {
  try {
    const begin = await (await fetch('/auth/passkeys/authenticate/begin',
      {method: 'POST', headers: {'content-type': 'application/json'}, body: '{}'})).json();
    const opts = begin.publicKey;
    opts.challenge = b64urlToBuf(opts.challenge);
    (opts.allowCredentials || []).forEach(c => c.id = b64urlToBuf(c.id));
    const cred = await navigator.credentials.get({publicKey: opts});
    const body = {
      state: begin.state,
      credential: {
        id: cred.id, rawId: bufToB64url(cred.rawId), type: cred.type,
        response: {
          clientDataJSON: bufToB64url(cred.response.clientDataJSON),
          authenticatorData: bufToB64url(cred.response.authenticatorData),
          signature: bufToB64url(cred.response.signature),
          userHandle: cred.response.userHandle ? bufToB64url(cred.response.userHandle) : null,
        },
        clientExtensionResults: cred.getClientExtensionResults(),
      },
    };
    log(await (await fetch('/auth/passkeys/authenticate/finish',
      {method: 'POST', headers: {'content-type': 'application/json'}, body: JSON.stringify(body)})).json());
  } catch (e) { log('Error: ' + e); }
}
</script>
</body></html>"""
