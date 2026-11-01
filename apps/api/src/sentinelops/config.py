"""Shared configuration for every process, loaded from SENTINELOPS_* environment variables.

There are deliberately no defaults for credentials: the database URL must be supplied.
"""

import ipaddress
from enum import StrEnum
from functools import lru_cache
from typing import Literal

from pydantic import Field, SecretStr, field_validator, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class Environment(StrEnum):
    DEVELOPMENT = "development"
    TEST = "test"
    PRODUCTION = "production"


LogLevel = Literal["DEBUG", "INFO", "WARNING", "ERROR"]


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_prefix="SENTINELOPS_", extra="ignore", frozen=True)

    env: Environment = Environment.DEVELOPMENT
    database_url: SecretStr
    log_level: LogLevel = "INFO"
    db_pool_size: int = Field(default=5, ge=1, le=50)
    readiness_timeout_seconds: float = Field(default=2.0, gt=0, le=10)

    # Browser-facing origin of the web app; used in emailed and CLI-printed links.
    public_base_url: str = "http://localhost:5173"
    # Origins allowed to send state-changing requests (Origin/Referer check).
    allowed_origins: list[str] = ["http://localhost:5173", "http://127.0.0.1:5173"]
    # Secure cookies; None means "secure unless env is development or test".
    cookie_secure: bool | None = None

    # Sessions (FR-ID-001). Idle timeout and absolute lifetime.
    session_idle_minutes: int = Field(default=480, ge=5, le=1440)
    session_absolute_hours: int = Field(default=24, ge=1, le=168)

    # Argon2id cost. Defaults follow argon2-cffi's RFC 9106 low-memory profile.
    password_hash_time_cost: int = Field(default=3, ge=1, le=10)
    password_hash_memory_kib: int = Field(default=65536, ge=1024, le=1048576)

    # Platform transactional email (FR-ID-007). Unset host disables sending.
    smtp_host: str | None = None
    smtp_port: int = Field(default=587, ge=1, le=65535)
    smtp_starttls: bool = True
    smtp_username: str | None = None
    smtp_password: SecretStr | None = None
    smtp_from: str = "SentinelOps <no-reply@sentinelops.invalid>"

    # Organization secrets (ADR-015): key id -> base64 32-byte AES key. Never committed.
    secret_keys: dict[str, SecretStr] = {}
    secret_active_key_id: str | None = None

    # SYSTEM_ADMIN MFA (OD-01): TOTP, required in production unless explicitly set. The TOTP
    # secrets use their own key ring, separate from organization secrets (ADR-005/015).
    admin_mfa_required: bool | None = None
    mfa_keys: dict[str, SecretStr] = {}
    mfa_active_key_id: str | None = None

    # Reverse proxies whose X-Forwarded-For is trusted (CIDRs). Empty: the socket peer is the
    # client, and forwarded headers are ignored.
    trusted_proxies: list[str] = []

    # Probe engine (02_TECHNICAL_ARCHITECTURE.md §5, §7). The destination policy is code;
    # "dev-fixtures" additionally permits loopback and is refused outside development/test.
    probe_policy: Literal["strict", "dev-fixtures"] = "strict"
    worker_concurrency: int = Field(default=50, ge=1, le=500)
    worker_org_concurrency: int = Field(default=10, ge=1, le=100)
    worker_host_concurrency: int = Field(default=2, ge=1, le=20)
    worker_batch_size: int = Field(default=20, ge=1, le=200)
    worker_idle_seconds: float = Field(default=5.0, gt=0, le=60)
    worker_shutdown_grace_seconds: float = Field(default=60.0, ge=0, le=600)

    @field_validator("database_url")
    @classmethod
    def _require_asyncpg(cls, value: SecretStr) -> SecretStr:
        if not value.get_secret_value().startswith("postgresql+asyncpg://"):
            raise ValueError("database_url must use the postgresql+asyncpg:// scheme")
        return value

    @field_validator("public_base_url")
    @classmethod
    def _strip_trailing_slash(cls, value: str) -> str:
        return value.rstrip("/")

    @model_validator(mode="after")
    def _guard_dev_policy(self) -> Settings:
        if self.probe_policy == "dev-fixtures" and self.env not in (
            Environment.DEVELOPMENT,
            Environment.TEST,
        ):
            raise ValueError("probe_policy=dev-fixtures is only allowed in development or test")
        return self

    @model_validator(mode="after")
    def _guard_admin_mfa(self) -> Settings:
        if self.require_admin_mfa and (
            not self.mfa_active_key_id or self.mfa_active_key_id not in self.mfa_keys
        ):
            raise ValueError("admin MFA is required: set mfa_keys and mfa_active_key_id")
        return self

    @field_validator("trusted_proxies")
    @classmethod
    def _valid_networks(cls, value: list[str]) -> list[str]:
        for entry in value:
            ipaddress.ip_network(entry, strict=False)  # raises ValueError if malformed
        return value

    @property
    def require_admin_mfa(self) -> bool:
        if self.admin_mfa_required is not None:
            return self.admin_mfa_required
        return self.is_production

    @property
    def is_production(self) -> bool:
        return self.env is Environment.PRODUCTION

    @property
    def secure_cookies(self) -> bool:
        if self.cookie_secure is not None:
            return self.cookie_secure
        return self.env not in (Environment.DEVELOPMENT, Environment.TEST)


@lru_cache
def get_settings() -> Settings:
    return Settings()  # pyright: ignore[reportCallIssue]  # values come from the environment
