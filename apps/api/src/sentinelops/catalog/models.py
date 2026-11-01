"""Catalog tables: projects (G2), verified domains and monitors (G3).

Pattern: organization_id on every row, UNIQUE(organization_id, id) on parents, composite FKs on
children so no row can reference another organization's row.
"""

import uuid
from datetime import datetime
from typing import Any

from sqlalchemy import (
    CheckConstraint,
    ForeignKey,
    ForeignKeyConstraint,
    Index,
    Integer,
    Text,
    UniqueConstraint,
    func,
    text,
)
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column

from sentinelops import clock
from sentinelops.db.base import Base, new_id


class Project(Base):
    __tablename__ = "project"
    __table_args__ = (
        UniqueConstraint("organization_id", "id"),
        Index(
            "uq_project_organization_id_name_active",
            "organization_id",
            func.lower(text("name")),
            unique=True,
            postgresql_where=text("archived_at IS NULL"),
        ),
    )

    id: Mapped[uuid.UUID] = mapped_column(primary_key=True, default=new_id)
    organization_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("organization.id", ondelete="RESTRICT")
    )
    name: Mapped[str] = mapped_column(Text)
    description: Mapped[str | None] = mapped_column(Text)
    archived_at: Mapped[datetime | None]
    created_by: Mapped[uuid.UUID] = mapped_column(ForeignKey("app_user.id", ondelete="RESTRICT"))
    created_at: Mapped[datetime] = mapped_column(default=clock.now_default)
    updated_at: Mapped[datetime] = mapped_column(
        default=clock.now_default, onupdate=clock.now_default
    )
    version: Mapped[int] = mapped_column(Integer, default=1)


class DomainStatus:
    PENDING = "PENDING"
    VERIFIED = "VERIFIED"
    EXPIRED = "EXPIRED"
    REJECTED = "REJECTED"
    REVOKED = "REVOKED"


class DomainMethod:
    DNS_TXT = "DNS_TXT"
    ADMIN_EXCEPTION = "ADMIN_EXCEPTION"


class VerifiedDomain(Base):
    """Domain ownership proof (OD-05). Covers the FQDN and its subdomains while VERIFIED and
    unexpired. Only the challenge token's hash is stored."""

    __tablename__ = "verified_domain"
    __table_args__ = (
        UniqueConstraint("organization_id", "id"),
        UniqueConstraint("organization_id", "fqdn"),
        CheckConstraint("method IN ('DNS_TXT', 'ADMIN_EXCEPTION')", name="method_valid"),
        CheckConstraint(
            "status IN ('PENDING', 'VERIFIED', 'EXPIRED', 'REJECTED', 'REVOKED')",
            name="status_valid",
        ),
        CheckConstraint(
            "status <> 'VERIFIED' OR (verified_at IS NOT NULL AND expires_at IS NOT NULL)",
            name="verified_has_window",
        ),
    )

    id: Mapped[uuid.UUID] = mapped_column(primary_key=True, default=new_id)
    organization_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("organization.id", ondelete="RESTRICT")
    )
    fqdn: Mapped[str] = mapped_column(Text)
    method: Mapped[str] = mapped_column(Text)
    status: Mapped[str] = mapped_column(Text)
    challenge_token_hash: Mapped[str | None] = mapped_column(Text)
    challenge_expires_at: Mapped[datetime | None]
    verified_at: Mapped[datetime | None]
    expires_at: Mapped[datetime | None]
    last_checked_at: Mapped[datetime | None]
    exception_reason: Mapped[str | None] = mapped_column(Text)
    decided_by: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("app_user.id", ondelete="RESTRICT")
    )
    created_by: Mapped[uuid.UUID] = mapped_column(ForeignKey("app_user.id", ondelete="RESTRICT"))
    created_at: Mapped[datetime] = mapped_column(default=clock.now_default)
    updated_at: Mapped[datetime] = mapped_column(
        default=clock.now_default, onupdate=clock.now_default
    )
    version: Mapped[int] = mapped_column(Integer, default=1)


class MonitorLifecycle:
    DRAFT = "DRAFT"
    ACTIVE = "ACTIVE"
    PAUSED = "PAUSED"
    ARCHIVED = "ARCHIVED"


class Monitor(Base):
    """HTTP(S) monitor (FR-MON-002). URL and custom headers are encrypted (ADR-015);
    ``display_url`` never contains the query string."""

    __tablename__ = "monitor"
    __table_args__ = (
        UniqueConstraint("organization_id", "id"),
        ForeignKeyConstraint(
            ["organization_id", "project_id"],
            ["project.organization_id", "project.id"],
            ondelete="RESTRICT",
        ),
        CheckConstraint("kind = 'HTTP'", name="kind_http_phase1"),
        CheckConstraint("method IN ('GET', 'HEAD')", name="method_valid"),
        CheckConstraint("interval_seconds IN (60, 120, 300)", name="interval_allowed"),
        CheckConstraint("timeout_ms BETWEEN 3000 AND 15000", name="timeout_range"),
        CheckConstraint("retry_attempts BETWEEN 0 AND 2", name="retry_range"),
        CheckConstraint("header_count BETWEEN 0 AND 5", name="header_count_range"),
        CheckConstraint(
            "(header_count = 0) = (header_ciphertext IS NULL)", name="headers_consistent"
        ),
        CheckConstraint("validation_json IS NULL OR method = 'GET'", name="validation_needs_get"),
        CheckConstraint("failure_threshold BETWEEN 1 AND 10", name="failure_threshold_range"),
        CheckConstraint("recovery_threshold BETWEEN 1 AND 10", name="recovery_threshold_range"),
        CheckConstraint(
            "latency_threshold_ms IS NULL OR latency_threshold_ms BETWEEN 1 AND 15000",
            name="latency_threshold_range",
        ),
        CheckConstraint("tls_warn_days BETWEEN 1 AND 90", name="tls_warn_days_range"),
        CheckConstraint(
            "lifecycle IN ('DRAFT', 'ACTIVE', 'PAUSED', 'ARCHIVED')", name="lifecycle_valid"
        ),
        CheckConstraint(
            "paused_reason IS NULL OR paused_reason IN ('USER', 'POLICY_BLOCKED')",
            name="paused_reason_valid",
        ),
        Index("ix_monitor_organization_id_lifecycle", "organization_id", "lifecycle"),
    )

    id: Mapped[uuid.UUID] = mapped_column(primary_key=True, default=new_id)
    organization_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("organization.id", ondelete="RESTRICT")
    )
    project_id: Mapped[uuid.UUID]
    kind: Mapped[str] = mapped_column(Text, default="HTTP")
    name: Mapped[str] = mapped_column(Text)
    url_ciphertext: Mapped[str] = mapped_column(Text)
    url_key_id: Mapped[str] = mapped_column(Text)
    hostname: Mapped[str] = mapped_column(Text)
    display_url: Mapped[str] = mapped_column(Text)
    method: Mapped[str] = mapped_column(Text)
    interval_seconds: Mapped[int] = mapped_column(Integer)
    timeout_ms: Mapped[int] = mapped_column(Integer)
    retry_attempts: Mapped[int] = mapped_column(Integer)
    expected_status_json: Mapped[list[list[int]]] = mapped_column(JSONB)
    validation_json: Mapped[dict[str, Any] | None]
    header_ciphertext: Mapped[str | None] = mapped_column(Text)
    header_key_id: Mapped[str | None] = mapped_column(Text)
    header_count: Mapped[int] = mapped_column(Integer, default=0)
    latency_threshold_ms: Mapped[int | None] = mapped_column(Integer)
    failure_threshold: Mapped[int] = mapped_column(Integer)
    recovery_threshold: Mapped[int] = mapped_column(Integer)
    tls_warn_days: Mapped[int] = mapped_column(Integer)
    tags_json: Mapped[list[str]] = mapped_column(JSONB, default=list)
    lifecycle: Mapped[str] = mapped_column(Text)
    paused_reason: Mapped[str | None] = mapped_column(Text)
    attention_reason: Mapped[str | None] = mapped_column(Text)
    created_by: Mapped[uuid.UUID] = mapped_column(ForeignKey("app_user.id", ondelete="RESTRICT"))
    created_at: Mapped[datetime] = mapped_column(default=clock.now_default)
    updated_at: Mapped[datetime] = mapped_column(
        default=clock.now_default, onupdate=clock.now_default
    )
    version: Mapped[int] = mapped_column(Integer, default=1)
