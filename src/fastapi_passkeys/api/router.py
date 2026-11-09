"""The batteries-included facade (Layer A of the public API).

Construct one :class:`Passkeys`, mount ``passkeys.router``, and you have the full
register/authenticate/manage flow. The underlying services remain available as
``passkeys.registration`` / ``passkeys.authentication`` for finer control.
"""

from __future__ import annotations

from typing import Any

from fastapi import APIRouter, FastAPI, HTTPException, Request, Response

from fastapi_passkeys._b64 import b64url_to_bytes, bytes_to_b64url
from fastapi_passkeys.api.dependencies import (
    GetUser,
    OnAuthenticated,
    maybe_await,
    resolve_user,
)
from fastapi_passkeys.api.handlers import install_exception_handlers
from fastapi_passkeys.api.schemas import (
    AuthBeginRequest,
    AuthFinishRequest,
    BeginResponse,
    CredentialView,
    RegisterFinishRequest,
    RegisterFinishResponse,
    RenameRequest,
    SignalsResponse,
)
from fastapi_passkeys.audit import (
    AuditEvent,
    AuditEventType,
    AuditSink,
    NullAuditSink,
    emit_safely,
)
from fastapi_passkeys.config import PasskeyConfig
from fastapi_passkeys.contrib.memory import InMemoryChallengeStore
from fastapi_passkeys.contrib.stateless import StatelessChallengeStore
from fastapi_passkeys.domain.models import Credential
from fastapi_passkeys.engine.base import WebAuthnEngine
from fastapi_passkeys.engine.pywebauthn import PyWebAuthnEngine
from fastapi_passkeys.exceptions import ManagedCredentialNotFound
from fastapi_passkeys.repositories.challenges import ChallengeStore
from fastapi_passkeys.repositories.credentials import CredentialRepository
from fastapi_passkeys.services.authentication import AuthenticationService
from fastapi_passkeys.services.clock import Clock, SystemClock
from fastapi_passkeys.services.registration import RegistrationService, user_handle


class Passkeys:
    """High-level entry point wiring config, storage, engine, and HTTP routes."""

    def __init__(
        self,
        *,
        config: PasskeyConfig,
        credential_repository: CredentialRepository,
        challenge_store: ChallengeStore | None = None,
        get_user: GetUser | None = None,
        on_authenticated: OnAuthenticated | None = None,
        engine: WebAuthnEngine | None = None,
        audit: AuditSink | None = None,
        clock: Clock | None = None,
    ) -> None:
        self.config = config
        self._clock = clock or SystemClock()
        self._audit = audit or NullAuditSink()
        self._engine = engine or PyWebAuthnEngine()
        self._credentials = credential_repository
        self._challenges = challenge_store or self._default_store(config, self._clock)
        self._get_user = get_user
        self._on_authenticated = on_authenticated

        self.registration = RegistrationService(
            config=config,
            credentials=self._credentials,
            challenges=self._challenges,
            engine=self._engine,
            clock=self._clock,
            audit=self._audit,
        )
        self.authentication = AuthenticationService(
            config=config,
            credentials=self._credentials,
            challenges=self._challenges,
            engine=self._engine,
            clock=self._clock,
            audit=self._audit,
        )
        self.router = self._build_router()

    @staticmethod
    def _default_store(config: PasskeyConfig, clock: Clock) -> ChallengeStore:
        if config.signing_secret is not None:
            return StatelessChallengeStore(config.signing_secret.get_secret_value(), clock=clock)
        return InMemoryChallengeStore(clock=clock)

    def install_exception_handlers(self, app: FastAPI) -> None:
        """Register JSON error responses for the library's exceptions."""
        install_exception_handlers(app)

    @property
    def well_known_router(self) -> APIRouter:
        """Serves ``/.well-known/webauthn`` for WebAuthn Related Origin Requests.

        Mount it **without a prefix** on the app served at ``rp_id``::

            app.include_router(passkeys.well_known_router)

        Responds 404 unless ``config.related_origins`` is set.
        """
        router = APIRouter()

        @router.get("/.well-known/webauthn", include_in_schema=False)
        async def related_origins() -> dict[str, list[str]]:
            if not self.config.related_origins:
                raise HTTPException(status_code=404)
            origins = [o for o in self.config.allowed_origins if o.startswith("http")]
            return {"origins": origins}

        return router

    def _build_router(self) -> APIRouter:
        router = APIRouter(tags=["passkeys"])

        @router.post("/register/begin", response_model=BeginResponse)
        async def register_begin(request: Request) -> BeginResponse:
            user = await resolve_user(self._get_user, request)
            options, handle = await self.registration.begin(user)
            return BeginResponse(publicKey=options, state=handle)

        @router.post("/register/finish", response_model=RegisterFinishResponse)
        async def register_finish(
            body: RegisterFinishRequest, request: Request
        ) -> RegisterFinishResponse:
            # Bind the ceremony to the caller: a handle issued to another user is
            # rejected, so a leaked handle cannot attach an attacker's key.
            user = await resolve_user(self._get_user, request)
            credential = await self.registration.finish(
                response=body.credential,
                handle=body.state,
                device_name=body.device_name,
                user=user,
            )
            return RegisterFinishResponse(credentialId=bytes_to_b64url(credential.credential_id))

        @router.post("/authenticate/begin", response_model=BeginResponse)
        async def authenticate_begin(body: AuthBeginRequest | None = None) -> BeginResponse:
            options, handle = await self.authentication.begin(
                user_id=body.user_id if body else None
            )
            return BeginResponse(publicKey=options, state=handle)

        @router.post("/authenticate/finish")
        async def authenticate_finish(body: AuthFinishRequest, request: Request) -> Any:
            result = await self.authentication.finish(response=body.credential, handle=body.state)
            if self._on_authenticated is not None:
                return await maybe_await(self._on_authenticated(request, result))
            return {"status": "ok", "userId": result.user_id}

        @router.get("/credentials", response_model=list[CredentialView])
        async def list_credentials(request: Request) -> list[CredentialView]:
            user = await resolve_user(self._get_user, request)
            credentials = await self._credentials.list_by_user(user.id)
            return [CredentialView.from_domain(c) for c in credentials]

        @router.get("/credentials/signals", response_model=SignalsResponse)
        async def credential_signals(request: Request) -> SignalsResponse:
            user = await resolve_user(self._get_user, request)
            credentials = await self._credentials.list_by_user(user.id)
            user_id = bytes_to_b64url(user_handle(user.id))
            return SignalsResponse(
                allAcceptedCredentials={
                    "rpId": self.config.rp_id,
                    "userId": user_id,
                    "allAcceptedCredentialIds": [
                        bytes_to_b64url(c.credential_id) for c in credentials
                    ],
                },
                currentUserDetails={
                    "rpId": self.config.rp_id,
                    "userId": user_id,
                    "name": user.name,
                    "displayName": user.display_name or user.name,
                },
            )

        @router.patch("/credentials/{credential_id}", status_code=204)
        async def rename_credential(
            credential_id: str, body: RenameRequest, request: Request
        ) -> Response:
            user = await resolve_user(self._get_user, request)
            credential = await self._owned_credential(credential_id, user.id)
            await self._credentials.rename(credential.credential_id, user.id, body.device_name)
            await self._emit(AuditEventType.CREDENTIAL_RENAMED, user.id, credential)
            return Response(status_code=204)

        @router.delete("/credentials/{credential_id}", status_code=204)
        async def delete_credential(credential_id: str, request: Request) -> Response:
            user = await resolve_user(self._get_user, request)
            credential = await self._owned_credential(credential_id, user.id)
            await self._credentials.delete(credential.credential_id, user.id)
            await self._emit(AuditEventType.CREDENTIAL_REVOKED, user.id, credential)
            return Response(status_code=204)

        return router

    async def _owned_credential(self, credential_id: str, user_id: str) -> Credential:
        """Resolve a credential the caller owns, or 404 — identically for "absent"
        and "someone else's", so ids cannot be probed across accounts."""
        try:
            raw = b64url_to_bytes(credential_id)
        except ValueError:
            raise ManagedCredentialNotFound() from None
        credential = await self._credentials.get_by_credential_id(raw)
        if credential is None or credential.user_id != user_id:
            raise ManagedCredentialNotFound()
        return credential

    async def _emit(self, kind: AuditEventType, user_id: str, credential: Credential) -> None:
        await emit_safely(
            self._audit,
            AuditEvent(
                type=kind,
                timestamp=self._clock.now(),
                user_id=user_id,
                credential_id=bytes_to_b64url(credential.credential_id),
            ),
        )
