"""Exception handling for the FastAPI shell."""

from __future__ import annotations

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse

from fastapi_passkeys.exceptions import PasskeyError


def install_exception_handlers(app: FastAPI) -> None:
    """Render every :class:`PasskeyError` as a structured JSON error response."""

    @app.exception_handler(PasskeyError)
    async def _on_passkey_error(_: Request, exc: PasskeyError) -> JSONResponse:
        return JSONResponse(
            status_code=exc.status_code,
            content={"error": {"code": exc.code, "message": exc.message}},
        )
