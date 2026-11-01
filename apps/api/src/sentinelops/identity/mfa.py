"""SYSTEM_ADMIN multi-factor authentication (OD-01): TOTP (RFC 6238) plus recovery codes.

- TOTP: SHA-1, 6 digits, 30 s steps, +/-1 step of clock drift. A code's step must be newer than
  the last accepted one, so a code can never be replayed.
- Secrets are AES-256-GCM sealed with the dedicated MFA key ring (``SENTINELOPS_MFA_KEYS``),
  bound to the user ID; they are shown once at enrolment and never logged or returned again.
- Recovery codes: 10 single-use codes (60 bits each), stored only as SHA-256 hashes.
- Login: a SYSTEM_ADMIN with MFA gets a session marked ``VERIFY``; without MFA while the policy
  requires it, ``ENROLL``. Such sessions reach only /api/auth/me, /api/auth/logout and
  /api/auth/mfa/* until verified, then the session is rotated.
- Failed codes count against the account login throttle; 5 failures revoke the pending session.
"""

import base64
import hashlib
import hmac
import secrets
import struct
import uuid
from dataclasses import dataclass
from datetime import datetime
from urllib.parse import quote

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from sqlalchemy import delete, func, select, update
from sqlalchemy.ext.asyncio import AsyncSession

from sentinelops.config import Settings
from sentinelops.errors import AppError
from sentinelops.identity.models import AdminMfa, AdminRecoveryCode

STEP_SECONDS = 30
DIGITS = 6
DRIFT_STEPS = 1
RECOVERY_CODES = 10
MAX_PENDING_FAILURES = 5
ISSUER = "SentinelOps"
VERIFY = "VERIFY"
ENROLL = "ENROLL"
_NONCE = 12


class MfaUnavailableError(AppError):
    def __init__(self) -> None:
        super().__init__(503, "MFA_UNAVAILABLE", "Multi-factor authentication is not configured")


def invalid_code() -> AppError:
    return AppError(401, "INVALID_MFA_CODE", "The code is not valid")


# --- TOTP ---------------------------------------------------------------------------------------


def new_secret() -> str:
    return base64.b32encode(secrets.token_bytes(20)).decode().rstrip("=")


def _key(secret: str) -> bytes:
    return base64.b32decode(secret + "=" * (-len(secret) % 8), casefold=True)


def code_at(secret: str, step: int) -> str:
    digest = hmac.new(_key(secret), struct.pack(">Q", step), hashlib.sha1).digest()
    offset = digest[-1] & 0x0F
    value = struct.unpack(">I", digest[offset : offset + 4])[0] & 0x7FFFFFFF
    return str(value % 10**DIGITS).zfill(DIGITS)


def step_of(now: datetime) -> int:
    return int(now.timestamp()) // STEP_SECONDS


def matching_step(secret: str, code: str, now: datetime, after: int | None) -> int | None:
    """The step a code belongs to (within drift), if it is newer than ``after``."""
    candidate = code.strip().replace(" ", "")
    if len(candidate) != DIGITS or not candidate.isdigit():
        return None
    current = step_of(now)
    for step in range(current - DRIFT_STEPS, current + DRIFT_STEPS + 1):
        if after is not None and step <= after:
            continue
        if hmac.compare_digest(code_at(secret, step), candidate):
            return step
    return None


def otpauth_uri(secret: str, email: str) -> str:
    label = quote(f"{ISSUER}:{email}")
    return (
        f"otpauth://totp/{label}?secret={secret}&issuer={ISSUER}"
        f"&algorithm=SHA1&digits={DIGITS}&period={STEP_SECONDS}"
    )


# --- sealing ------------------------------------------------------------------------------------


@dataclass(frozen=True)
class MfaCipher:
    keys: dict[str, bytes]
    active: str | None

    @classmethod
    def from_settings(cls, settings: Settings) -> MfaCipher:
        keys = {k: base64.b64decode(v.get_secret_value()) for k, v in settings.mfa_keys.items()}
        for key in keys.values():
            if len(key) != 32:
                raise ValueError("MFA keys must be 32 bytes (base64)")
        return cls(keys, settings.mfa_active_key_id)

    @staticmethod
    def _aad(user_id: uuid.UUID) -> bytes:
        return f"platform_admin_mfa|{user_id}|totp_secret".encode()

    def seal(self, user_id: uuid.UUID, secret: str) -> tuple[str, str]:
        if self.active is None or self.active not in self.keys:
            raise MfaUnavailableError
        nonce = secrets.token_bytes(_NONCE)
        sealed = AESGCM(self.keys[self.active]).encrypt(nonce, secret.encode(), self._aad(user_id))
        return self.active, base64.b64encode(nonce + sealed).decode()

    def open(self, user_id: uuid.UUID, key_id: str, ciphertext: str) -> str:
        key = self.keys.get(key_id)
        if key is None:
            raise MfaUnavailableError
        raw = base64.b64decode(ciphertext)
        return AESGCM(key).decrypt(raw[:_NONCE], raw[_NONCE:], self._aad(user_id)).decode()


# --- recovery codes -----------------------------------------------------------------------------

_ALPHABET = "abcdefghjkmnpqrstuvwxyz23456789"  # no 0/o/1/l/i


def _normalize(code: str) -> str:
    return code.strip().lower().replace("-", "").replace(" ", "")


def hash_recovery_code(code: str) -> str:
    return hashlib.sha256(_normalize(code).encode()).hexdigest()


def new_recovery_codes() -> list[str]:
    codes: list[str] = []
    for _ in range(RECOVERY_CODES):
        raw = "".join(secrets.choice(_ALPHABET) for _ in range(12))
        codes.append(f"{raw[:4]}-{raw[4:8]}-{raw[8:]}")
    return codes


async def replace_recovery_codes(db: AsyncSession, user_id: uuid.UUID, now: datetime) -> list[str]:
    await db.execute(delete(AdminRecoveryCode).where(AdminRecoveryCode.user_id == user_id))
    codes = new_recovery_codes()
    for code in codes:
        db.add(
            AdminRecoveryCode(user_id=user_id, code_hash=hash_recovery_code(code), created_at=now)
        )
    return codes


async def consume_recovery_code(
    db: AsyncSession, user_id: uuid.UUID, code: str, now: datetime
) -> bool:
    result = await db.execute(
        update(AdminRecoveryCode)
        .where(
            AdminRecoveryCode.user_id == user_id,
            AdminRecoveryCode.code_hash == hash_recovery_code(code),
            AdminRecoveryCode.used_at.is_(None),
        )
        .values(used_at=now)
    )
    return bool(getattr(result, "rowcount", 0))


async def recovery_codes_left(db: AsyncSession, user_id: uuid.UUID) -> int:
    return int(
        await db.scalar(
            select(func.count())
            .select_from(AdminRecoveryCode)
            .where(AdminRecoveryCode.user_id == user_id, AdminRecoveryCode.used_at.is_(None))
        )
        or 0
    )


# --- enrolment state ----------------------------------------------------------------------------


async def confirmed_mfa(
    db: AsyncSession, user_id: uuid.UUID, *, lock: bool = False
) -> AdminMfa | None:
    stmt = select(AdminMfa).where(AdminMfa.user_id == user_id, AdminMfa.confirmed_at.is_not(None))
    return await db.scalar(stmt.with_for_update() if lock else stmt)


async def login_requirement(
    db: AsyncSession, user_id: uuid.UUID, settings: Settings, *, is_admin: bool
) -> str | None:
    """What a new session of this user must complete before full access."""
    if not is_admin:
        return None
    if await confirmed_mfa(db, user_id) is not None:
        return VERIFY
    return ENROLL if settings.require_admin_mfa else None


async def verify_totp(
    db: AsyncSession, cipher: MfaCipher, user_id: uuid.UUID, code: str, now: datetime
) -> bool:
    """Check a TOTP code under a row lock and record its step (replay protection)."""
    mfa = await confirmed_mfa(db, user_id, lock=True)
    if mfa is None:
        return False
    secret = cipher.open(user_id, mfa.secret_key_id, mfa.secret_ciphertext)
    step = matching_step(secret, code, now, mfa.last_used_step)
    if step is None:
        return False
    mfa.last_used_step = step
    return True
