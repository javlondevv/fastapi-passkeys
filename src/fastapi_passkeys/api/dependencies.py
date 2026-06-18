"""Hook plumbing shared by the router."""

from __future__ import annotations

import inspect
from collections.abc import Awaitable, Callable
from typing import Any, cast

from fastapi import Request

from fastapi_passkeys.domain.models import AuthenticationResult, PasskeyUser
from fastapi_passkeys.exceptions import ConfigurationError

# An app-supplied resolver: given the request, return the user being registered.
GetUser = Callable[[Request], "PasskeyUser | Awaitable[PasskeyUser]"]

# An app-supplied callback invoked after a successful assertion. Whatever it
# returns becomes the HTTP response body (e.g. a token payload). May be async.
OnAuthenticated = Callable[[Request, AuthenticationResult], "Any | Awaitable[Any]"]


async def maybe_await(value: Any) -> Any:
    """Await ``value`` if it is awaitable, otherwise return it as-is."""
    if inspect.isawaitable(value):
        return await value
    return value


async def resolve_user(get_user: GetUser | None, request: Request) -> PasskeyUser:
    if get_user is None:
        raise ConfigurationError(
            "A `get_user` hook is required for registration and credential management."
        )
    return cast("PasskeyUser", await maybe_await(get_user(request)))
