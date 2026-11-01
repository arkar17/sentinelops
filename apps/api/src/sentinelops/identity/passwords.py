"""Argon2id hashing and the password policy.

Policy (G1 choice; the baseline does not fix one): 12-128 characters, not mainly the account's
email, not a single repeated character and not on a short list of very common passwords.
"""

from argon2 import PasswordHasher, Type
from argon2.exceptions import InvalidHashError, VerificationError, VerifyMismatchError

from sentinelops.config import Settings
from sentinelops.errors import AppError

MIN_PASSWORD_LENGTH = 12
MAX_PASSWORD_LENGTH = 128

_COMMON_PASSWORDS = frozenset(
    {
        "123456789012",
        "password1234",
        "passwordpassword",
        "qwertyuiopas",
        "letmein12345",
        "administrator",
        "sentinelops123",
        "changeme1234",
        "welcome12345",
        "iloveyou1234",
    }
)


class PasswordPolicyError(AppError):
    def __init__(self, message: str) -> None:
        super().__init__(422, "PASSWORD_POLICY", message)


def validate_new_password(password: str, email: str) -> None:
    if len(password) < MIN_PASSWORD_LENGTH:
        raise PasswordPolicyError(f"Password must be at least {MIN_PASSWORD_LENGTH} characters")
    if len(password) > MAX_PASSWORD_LENGTH:
        raise PasswordPolicyError(f"Password must be at most {MAX_PASSWORD_LENGTH} characters")
    lowered = password.casefold()
    if len(set(password)) == 1 or lowered in _COMMON_PASSWORDS:
        raise PasswordPolicyError("Password is too easy to guess")
    local_part = email.split("@", 1)[0].casefold()
    if len(local_part) >= 4 and local_part in lowered:
        raise PasswordPolicyError("Password must not contain your email address")


class PasswordService:
    def __init__(self, settings: Settings) -> None:
        self._hasher = PasswordHasher(
            time_cost=settings.password_hash_time_cost,
            memory_cost=settings.password_hash_memory_kib,
            parallelism=4,
            type=Type.ID,
        )
        # Verified against when the account is unknown, so response time does not reveal it.
        self._dummy_hash = self._hasher.hash("sentinelops-timing-equalizer")

    def hash(self, password: str) -> str:
        return self._hasher.hash(password)

    def verify(self, password_hash: str | None, password: str) -> bool:
        try:
            return self._hasher.verify(password_hash or self._dummy_hash, password) and (
                password_hash is not None
            )
        except VerifyMismatchError, VerificationError, InvalidHashError:
            return False

    def needs_rehash(self, password_hash: str) -> bool:
        return self._hasher.check_needs_rehash(password_hash)
