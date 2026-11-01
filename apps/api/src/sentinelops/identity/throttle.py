"""Login throttling and temporary lockout (FR-ID-001).

Counters are keyed by a hash of the normalized email whether or not an account exists, so
lockout behavior cannot be used to discover accounts. A separate per-IP counter limits spraying.
"""

from dataclasses import dataclass
from datetime import datetime, timedelta

from sqlalchemy import delete, select, text
from sqlalchemy.ext.asyncio import AsyncSession

from sentinelops.identity.models import AuthThrottle, ThrottleScope
from sentinelops.identity.tokens import hash_token


@dataclass(frozen=True)
class ThrottlePolicy:
    limit: int
    window: timedelta
    lockout: timedelta


POLICIES = {
    ThrottleScope.ACCOUNT: ThrottlePolicy(5, timedelta(minutes=15), timedelta(minutes=15)),
    ThrottleScope.IP: ThrottlePolicy(20, timedelta(minutes=15), timedelta(minutes=15)),
}

_REGISTER_FAILURE = text(
    """
    INSERT INTO auth_throttle AS t (scope, key_hash, failure_count, window_started_at,
                                    locked_until, updated_at)
    VALUES (:scope, :key_hash, 1, CAST(:now AS timestamptz),
            CASE WHEN CAST(:limit AS integer) <= 1 THEN CAST(:lock_until AS timestamptz) END,
            CAST(:now AS timestamptz))
    ON CONFLICT (scope, key_hash) DO UPDATE SET
        failure_count = CASE WHEN t.window_started_at < CAST(:window_start AS timestamptz)
                             THEN 1 ELSE t.failure_count + 1 END,
        window_started_at = CASE WHEN t.window_started_at < CAST(:window_start AS timestamptz)
                                 THEN CAST(:now AS timestamptz) ELSE t.window_started_at END,
        locked_until = CASE
            WHEN (CASE WHEN t.window_started_at < CAST(:window_start AS timestamptz) THEN 1
                       ELSE t.failure_count + 1 END) >= CAST(:limit AS integer)
            THEN CAST(:lock_until AS timestamptz)
            ELSE t.locked_until END,
        updated_at = CAST(:now AS timestamptz)
    """
)


def account_key(email_normalized: str) -> str:
    return hash_token(f"account:{email_normalized}")


def ip_key(ip: str) -> str:
    return hash_token(f"ip:{ip}")


async def is_locked(db: AsyncSession, keys: dict[str, str], now: datetime) -> bool:
    for scope, key in keys.items():
        locked_until = await db.scalar(
            select(AuthThrottle.locked_until).where(
                AuthThrottle.scope == scope, AuthThrottle.key_hash == key
            )
        )
        if locked_until is not None and locked_until > now:
            return True
    return False


async def register_failure(db: AsyncSession, scope: str, key: str, now: datetime) -> None:
    policy = POLICIES[scope]
    await db.execute(
        _REGISTER_FAILURE,
        {
            "scope": scope,
            "key_hash": key,
            "now": now,
            "limit": policy.limit,
            "window_start": now - policy.window,
            "lock_until": now + policy.lockout,
        },
    )


async def reset(db: AsyncSession, scope: str, key: str) -> None:
    await db.execute(
        delete(AuthThrottle).where(AuthThrottle.scope == scope, AuthThrottle.key_hash == key)
    )
