"""Global identity tables (03_DATABASE_DESIGN.md §2.1)."""

import uuid
from datetime import datetime

from sqlalchemy import BigInteger, CheckConstraint, ForeignKey, Index, Integer, Text, text
from sqlalchemy.orm import Mapped, mapped_column

from sentinelops import clock
from sentinelops.db.base import Base, new_id


class UserStatus:
    PENDING_ACTIVATION = "PENDING_ACTIVATION"
    ACTIVE = "ACTIVE"
    DISABLED = "DISABLED"


class TokenPurpose:
    ACTIVATION = "ACTIVATION"
    PASSWORD_RESET = "PASSWORD_RESET"  # noqa: S105  # identifier, not a credential


class ThrottleScope:
    ACCOUNT = "ACCOUNT"
    IP = "IP"


class AppUser(Base):
    __tablename__ = "app_user"
    __table_args__ = (
        CheckConstraint(
            "status IN ('PENDING_ACTIVATION', 'ACTIVE', 'DISABLED')", name="status_valid"
        ),
        CheckConstraint(
            "password_hash IS NOT NULL OR status = 'PENDING_ACTIVATION'",
            name="password_required_unless_pending",
        ),
    )

    id: Mapped[uuid.UUID] = mapped_column(primary_key=True, default=new_id)
    email: Mapped[str] = mapped_column(Text)
    email_normalized: Mapped[str] = mapped_column(Text, unique=True)
    password_hash: Mapped[str | None] = mapped_column(Text)
    status: Mapped[str] = mapped_column(Text)
    email_verified_at: Mapped[datetime | None]
    last_login_at: Mapped[datetime | None]
    timezone: Mapped[str] = mapped_column(Text, default="UTC")
    created_at: Mapped[datetime] = mapped_column(default=clock.now_default)
    updated_at: Mapped[datetime] = mapped_column(
        default=clock.now_default, onupdate=clock.now_default
    )
    version: Mapped[int] = mapped_column(Integer, default=1)


class UserSession(Base):
    """Server-side session. Only hashes of the session and CSRF tokens are stored."""

    __tablename__ = "session"
    __table_args__ = (
        Index("ix_session_user_id_active", "user_id", postgresql_where=text("revoked_at IS NULL")),
        CheckConstraint(
            "mfa_pending IS NULL OR mfa_pending IN ('VERIFY', 'ENROLL')", name="mfa_pending_valid"
        ),
    )

    id: Mapped[uuid.UUID] = mapped_column(primary_key=True, default=new_id)
    user_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("app_user.id", ondelete="RESTRICT"))
    token_hash: Mapped[str] = mapped_column(Text, unique=True)
    csrf_secret_hash: Mapped[str] = mapped_column(Text)
    created_at: Mapped[datetime] = mapped_column(default=clock.now_default)
    last_seen_at: Mapped[datetime] = mapped_column(default=clock.now_default)
    expires_at: Mapped[datetime]
    revoked_at: Mapped[datetime | None]
    ip_hash: Mapped[str | None] = mapped_column(Text)
    user_agent_hash: Mapped[str | None] = mapped_column(Text)
    # SYSTEM_ADMIN MFA gate (OD-01): VERIFY = TOTP still required, ENROLL = must enroll first.
    mfa_pending: Mapped[str | None] = mapped_column(Text)
    mfa_failures: Mapped[int] = mapped_column(Integer, default=0, server_default="0")


class AuthToken(Base):
    """Single-use activation and password-reset tokens (hash only)."""

    __tablename__ = "auth_token"
    __table_args__ = (
        CheckConstraint("purpose IN ('ACTIVATION', 'PASSWORD_RESET')", name="purpose_valid"),
        Index(
            "ix_auth_token_user_id_purpose_unused",
            "user_id",
            "purpose",
            postgresql_where=text("used_at IS NULL"),
        ),
    )

    id: Mapped[uuid.UUID] = mapped_column(primary_key=True, default=new_id)
    user_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("app_user.id", ondelete="RESTRICT"))
    purpose: Mapped[str] = mapped_column(Text)
    token_hash: Mapped[str] = mapped_column(Text, unique=True)
    expires_at: Mapped[datetime]
    used_at: Mapped[datetime | None]
    created_by: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("app_user.id", ondelete="RESTRICT")
    )
    created_at: Mapped[datetime] = mapped_column(default=clock.now_default)


class AuthThrottle(Base):
    """Failed-login counters keyed by hashed email (existing or not) and hashed client IP."""

    __tablename__ = "auth_throttle"
    __table_args__ = (CheckConstraint("scope IN ('ACCOUNT', 'IP')", name="scope_valid"),)

    scope: Mapped[str] = mapped_column(Text, primary_key=True)
    key_hash: Mapped[str] = mapped_column(Text, primary_key=True)
    failure_count: Mapped[int] = mapped_column(Integer)
    window_started_at: Mapped[datetime]
    locked_until: Mapped[datetime | None]
    updated_at: Mapped[datetime]


class AdminMfa(Base):
    """TOTP enrolment of a SYSTEM_ADMIN. The secret is AES-GCM sealed with the MFA key ring and
    bound to the user; ``last_used_step`` rejects replayed codes."""

    __tablename__ = "platform_admin_mfa"

    user_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("app_user.id", ondelete="RESTRICT"), primary_key=True
    )
    secret_ciphertext: Mapped[str] = mapped_column(Text)
    secret_key_id: Mapped[str] = mapped_column(Text)
    confirmed_at: Mapped[datetime | None]
    last_used_step: Mapped[int | None] = mapped_column(BigInteger)
    created_at: Mapped[datetime] = mapped_column(default=clock.now_default)
    updated_at: Mapped[datetime] = mapped_column(
        default=clock.now_default, onupdate=clock.now_default
    )


class AdminRecoveryCode(Base):
    """Single-use recovery codes, stored only as SHA-256 hashes."""

    __tablename__ = "platform_admin_recovery_code"
    __table_args__ = (
        Index(
            "ix_platform_admin_recovery_code_user_id_unused",
            "user_id",
            postgresql_where=text("used_at IS NULL"),
        ),
    )

    id: Mapped[uuid.UUID] = mapped_column(primary_key=True, default=new_id)
    user_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("app_user.id", ondelete="RESTRICT"))
    code_hash: Mapped[str] = mapped_column(Text, unique=True)
    used_at: Mapped[datetime | None]
    created_at: Mapped[datetime] = mapped_column(default=clock.now_default)
