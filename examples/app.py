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

from fastapi_passkeys import AuthenticationResult, PasskeyConfig, Passkeys, PasskeyUser
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
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>fastapi-passkeys demo</title>
<style>body{font-family:system-ui;max-width:40rem;margin:4rem auto;padding:0 1rem}
button{font-size:1rem;padding:.6rem 1rem;margin:.25rem 0;cursor:pointer}
input{font-size:1rem;padding:.5rem;width:100%;box-sizing:border-box}
pre{background:#f4f4f5;padding:1rem;border-radius:.5rem;white-space:pre-wrap}
li{margin:.25rem 0}</style>
</head><body>
<h1>fastapi-passkeys demo</h1>
<!-- autocomplete="username webauthn" lets the browser offer passkeys in autofill -->
<label for="username">Username</label>
<input id="username" name="username" autocomplete="username webauthn">
<p>
  <button id="register">Register a passkey</button>
  <button id="signin">Sign in with a passkey</button>
  <button id="list">My passkeys</button>
</p>
<ul id="keys"></ul>
<pre id="out">Ready.</pre>
<script>
const API = '/auth/passkeys';
const out = document.getElementById('out');
const log = (m) => out.textContent = (typeof m === 'string' ? m : JSON.stringify(m, null, 2));

// --- base64url <-> bytes. Accepts any BufferSource: some authenticators
// (1Password, Bitwarden, Firefox) hand back Uint8Array, not ArrayBuffer.
const b64urlToBuf = (s) => {
  s = s.replace(/-/g, '+').replace(/_/g, '/');
  const bin = atob(s + '='.repeat((4 - (s.length % 4)) % 4));
  return Uint8Array.from(bin, (c) => c.charCodeAt(0)).buffer;
};
const bufToB64url = (src) => {
  const bytes = ArrayBuffer.isView(src)
    ? new Uint8Array(src.buffer, src.byteOffset, src.byteLength)
    : new Uint8Array(src);
  let bin = '';
  for (const b of bytes) bin += String.fromCharCode(b);
  return btoa(bin).replace(/\\+/g, '-').replace(/\\//g, '_').replace(/=+$/, '');
};

// Prefer the native JSON helpers (WebAuthn L3); fall back to manual conversion.
const PKC = window.PublicKeyCredential;
const creationOptions = (json) => PKC.parseCreationOptionsFromJSON
  ? PKC.parseCreationOptionsFromJSON(json)
  : {...json, challenge: b64urlToBuf(json.challenge),
     user: {...json.user, id: b64urlToBuf(json.user.id)},
     excludeCredentials: (json.excludeCredentials || []).map(c => ({...c, id: b64urlToBuf(c.id)}))};
const requestOptions = (json) => PKC.parseRequestOptionsFromJSON
  ? PKC.parseRequestOptionsFromJSON(json)
  : {...json, challenge: b64urlToBuf(json.challenge),
     allowCredentials: (json.allowCredentials || []).map(c => ({...c, id: b64urlToBuf(c.id)}))};
const toJSON = (cred) => {
  if (typeof cred.toJSON === 'function') return cred.toJSON();
  const r = cred.response, json = {
    id: cred.id, rawId: bufToB64url(cred.rawId), type: cred.type,
    authenticatorAttachment: cred.authenticatorAttachment,
    clientExtensionResults: cred.getClientExtensionResults(), response: {
      clientDataJSON: bufToB64url(r.clientDataJSON)}};
  if (r.attestationObject) {
    json.response.attestationObject = bufToB64url(r.attestationObject);
    json.response.transports = r.getTransports ? r.getTransports() : [];
  } else {
    json.response.authenticatorData = bufToB64url(r.authenticatorData);
    json.response.signature = bufToB64url(r.signature);
    json.response.userHandle = r.userHandle ? bufToB64url(r.userHandle) : null;
  }
  return json;
};

const post = async (path, body) => {
  const resp = await fetch(API + path, {method: 'POST',
    headers: {'content-type': 'application/json'}, body: JSON.stringify(body ?? {})});
  const data = resp.status === 204 ? null : await resp.json();
  if (!resp.ok) throw Object.assign(new Error(data?.error?.message || resp.status), {data});
  return data;
};

// Only one WebAuthn request may be pending; abort the autofill one before a
// modal request starts (django-passkeys #16).
let conditional = null;
const abortConditional = () => { conditional?.abort(); conditional = null; };

async function finishSignIn(begin, cred) {
  try {
    log(await post('/authenticate/finish', {state: begin.state, credential: toJSON(cred)}));
  } catch (e) {
    // Tell the passkey provider to forget a credential the server no longer has.
    const signal = e.data?.error?.signal?.unknownCredential;
    if (signal && PKC.signalUnknownCredential) await PKC.signalUnknownCredential(signal);
    throw e;
  }
}

async function startConditionalUI() {
  const available = await PKC?.isConditionalMediationAvailable?.();
  if (!available) return;
  conditional = new AbortController();
  try {
    const begin = await post('/authenticate/begin');
    const cred = await navigator.credentials.get({
      publicKey: requestOptions(begin.publicKey), mediation: 'conditional',
      signal: conditional.signal});
    await finishSignIn(begin, cred);
  } catch (e) { if (e.name !== 'AbortError') log('Error: ' + e.message); }
}

document.getElementById('register').onclick = async () => {
  abortConditional();
  try {
    const begin = await post('/register/begin');
    const cred = await navigator.credentials.create({publicKey: creationOptions(begin.publicKey)});
    log(await post('/register/finish',
      {state: begin.state, deviceName: 'Demo device', credential: toJSON(cred)}));
  } catch (e) {
    // InvalidStateError: this authenticator already holds a passkey for the account.
    log(e.name === 'InvalidStateError'
      ? 'This device already has a passkey here.' : 'Error: ' + e.message);
  } finally { startConditionalUI(); }
};

document.getElementById('signin').onclick = async () => {
  abortConditional();
  try {
    const begin = await post('/authenticate/begin');
    const cred = await navigator.credentials.get({publicKey: requestOptions(begin.publicKey)});
    await finishSignIn(begin, cred);
  } catch (e) { log('Error: ' + e.message); }
  finally { startConditionalUI(); }
};

document.getElementById('list').onclick = async () => {
  const keys = await (await fetch(API + '/credentials')).json();
  const ul = document.getElementById('keys');
  ul.replaceChildren(...keys.map((k) => {
    const li = document.createElement('li');
    // textContent, never innerHTML: device names are user input (django-passkeys #11).
    li.textContent = `${k.deviceName || 'Unnamed'} — last used ${k.lastUsedAt ?? 'never'}`;
    return li;
  }));
  // Keep the passkey provider's list in sync with the server.
  const signals = await (await fetch(API + '/credentials/signals')).json();
  if (PKC.signalAllAcceptedCredentials) {
    await PKC.signalAllAcceptedCredentials(signals.allAcceptedCredentials);
  }
};

startConditionalUI();
</script>
</body></html>"""
