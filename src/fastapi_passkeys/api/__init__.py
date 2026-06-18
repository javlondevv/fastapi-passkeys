"""FastAPI shell: facade, router, schemas, exception handlers."""

from fastapi_passkeys.api.dependencies import GetUser, OnAuthenticated
from fastapi_passkeys.api.handlers import install_exception_handlers
from fastapi_passkeys.api.router import Passkeys

__all__ = ["GetUser", "OnAuthenticated", "Passkeys", "install_exception_handlers"]
