"""Storage contracts. Implementations live in :mod:`fastapi_passkeys.contrib`."""

from fastapi_passkeys.repositories.challenges import ChallengeStore
from fastapi_passkeys.repositories.credentials import CredentialRepository

__all__ = ["ChallengeStore", "CredentialRepository"]
