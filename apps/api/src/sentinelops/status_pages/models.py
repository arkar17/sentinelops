"""Public status pages (03_DATABASE_DESIGN.md §2.6, ADR-016).

Pages are unpublished by default. The public endpoint reads only ``status_page_snapshot``,
whose payload is built from an allowlist of public fields.
"""

import uuid
from datetime import datetime
from typing import Any

from sqlalchemy import (
    Boolean,
    CheckConstraint,
    ForeignKey,
    ForeignKeyConstraint,
    Integer,
    Text,
    UniqueConstraint,
)
from sqlalchemy.orm import Mapped, mapped_column

from sentinelops import clock
from sentinelops.db.base import Base, new_id

SLUG_PATTERN = "^[a-z0-9][a-z0-9-]{1,38}[a-z0-9]$"


class StatusPage(Base):
    __tablename__ = "status_page"
    __table_args__ = (
        UniqueConstraint("organization_id", "id"),
        UniqueConstraint("public_slug"),
        CheckConstraint(f"public_slug ~ '{SLUG_PATTERN}'", name="slug_format"),
    )

    id: Mapped[uuid.UUID] = mapped_column(primary_key=True, default=new_id)
    organization_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("organization.id", ondelete="RESTRICT")
    )
    public_slug: Mapped[str] = mapped_column(Text)
    title: Mapped[str] = mapped_column(Text)
    enabled: Mapped[bool] = mapped_column(Boolean, default=False)
    created_by: Mapped[uuid.UUID] = mapped_column(ForeignKey("app_user.id", ondelete="RESTRICT"))
    created_at: Mapped[datetime] = mapped_column(default=clock.now_default)
    updated_at: Mapped[datetime] = mapped_column(
        default=clock.now_default, onupdate=clock.now_default
    )
    version: Mapped[int] = mapped_column(Integer, default=1)


class StatusPageMonitor(Base):
    __tablename__ = "status_page_monitor"
    __table_args__ = (
        ForeignKeyConstraint(
            ["organization_id", "status_page_id"],
            ["status_page.organization_id", "status_page.id"],
            ondelete="RESTRICT",
        ),
        ForeignKeyConstraint(
            ["organization_id", "monitor_id"],
            ["monitor.organization_id", "monitor.id"],
            ondelete="RESTRICT",
        ),
        CheckConstraint("sort_order BETWEEN 0 AND 1000", name="sort_order_range"),
    )

    status_page_id: Mapped[uuid.UUID] = mapped_column(primary_key=True)
    monitor_id: Mapped[uuid.UUID] = mapped_column(primary_key=True)
    organization_id: Mapped[uuid.UUID]
    public_display_name: Mapped[str] = mapped_column(Text)
    sort_order: Mapped[int] = mapped_column(Integer, default=0)


class StatusPageSnapshot(Base):
    __tablename__ = "status_page_snapshot"
    __table_args__ = (
        ForeignKeyConstraint(
            ["organization_id", "status_page_id"],
            ["status_page.organization_id", "status_page.id"],
            ondelete="RESTRICT",
        ),
    )

    status_page_id: Mapped[uuid.UUID] = mapped_column(primary_key=True)
    organization_id: Mapped[uuid.UUID]
    generated_at: Mapped[datetime]
    safe_payload_json: Mapped[dict[str, Any]]
