"""Storage implementations.

Core (no extras): :class:`InMemoryCredentialRepository`,
:class:`InMemoryChallengeStore`, :class:`StatelessChallengeStore`.

Optional extras import lazily — ``contrib.sqlalchemy`` needs ``[sqlalchemy]`` and
``contrib.redis`` needs ``[redis]``.
"""

from fastapi_passkeys.contrib.memory import (
    InMemoryChallengeStore,
    InMemoryCredentialRepository,
)
from fastapi_passkeys.contrib.stateless import StatelessChallengeStore

__all__ = [
    "InMemoryChallengeStore",
    "InMemoryCredentialRepository",
    "StatelessChallengeStore",
]
