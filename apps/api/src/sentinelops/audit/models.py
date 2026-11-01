"""Append-only audit log (03_DATABASE_DESIGN.md §2.6). The app role has INSERT/SELECT only."""

import uuid
from datetime import datetime
from typing import Any

from sqlalchemy import CheckConstraint, ForeignKey, Index, Text
from sqlalchemy.orm import Mapped, mapped_column

from sentinelops import clock
from sentinelops.db.base import Base, new_id


class AuditEvent(Base):
    __tablename__ = "audit_event"
    __table_args__ = (
        CheckConstraint("scope IN ('PLATFORM', 'ORGANIZATION')", name="scope_valid"),
        CheckConstraint("actor_kind IN ('USER', 'SYSTEM', 'CLI')", name="actor_kind_valid"),
        CheckConstraint("actor_plane IN ('PLATFORM', 'ORG', 'NONE')", name="actor_plane_valid"),
        CheckConstraint(
            "scope <> 'ORGANIZATION' OR organization_id IS NOT NULL",
            name="organization_scope_has_org",
        ),
        Index("ix_audit_event_organization_id_at", "organization_id", "at"),
        Index("ix_audit_event_scope_at", "scope", "at"),
    )

    id: Mapped[uuid.UUID] = mapped_column(primary_key=True, default=new_id)
    scope: Mapped[str] = mapped_column(Text)
    organization_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("organization.id", ondelete="RESTRICT")
    )
    actor_kind: Mapped[str] = mapped_column(Text)
    actor_user_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("app_user.id", ondelete="RESTRICT")
    )
    actor_plane: Mapped[str] = mapped_column(Text)
    action: Mapped[str] = mapped_column(Text)
    entity_kind: Mapped[str | None] = mapped_column(Text)
    entity_id: Mapped[uuid.UUID | None]
    safe_diff_json: Mapped[dict[str, Any]] = mapped_column(default=dict)
    request_id: Mapped[str | None] = mapped_column(Text)
    at: Mapped[datetime] = mapped_column(default=clock.now_default)
