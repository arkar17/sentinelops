"""Platform API models. Metadata only: no hashes, tokens or organization secrets."""

import uuid
from datetime import date, datetime
from typing import Any

from pydantic import BaseModel, Field

from sentinelops.identity.passwords import MAX_PASSWORD_LENGTH


class InviteAdminRequest(BaseModel):
    email: str = Field(min_length=3, max_length=254)


class AcceptInvitationRequest(BaseModel):
    token: str = Field(min_length=16, max_length=128)
    password: str | None = Field(default=None, min_length=1, max_length=MAX_PASSWORD_LENGTH)


class AdminOut(BaseModel):
    user_id: uuid.UUID
    email: str
    user_status: str
    status: str
    granted_at: datetime
    granted_by_email: str | None
    deactivated_at: datetime | None


class InvitationOut(BaseModel):
    id: uuid.UUID
    email: str
    invited_by_email: str
    created_at: datetime
    expires_at: datetime


class AdminListOut(BaseModel):
    admins: list[AdminOut]
    invitations: list[InvitationOut]


class SettingsValues(BaseModel):
    default_max_monitors: int = Field(ge=1, le=10000)
    min_interval_seconds: int = Field(ge=60, le=300)
    max_timeout_ms: int = Field(ge=3000, le=15000)
    max_retry_attempts: int = Field(ge=0, le=2)
    max_custom_headers: int = Field(ge=0, le=5)
    validation_max_bytes: int = Field(ge=1024, le=1048576)
    check_now_per_monitor_seconds: int = Field(ge=10, le=3600)
    check_now_per_org_hour: int = Field(ge=0, le=1000)
    default_max_status_pages: int = Field(ge=0, le=100)
    default_max_channels: int = Field(ge=0, le=100)


class SettingsOut(SettingsValues):
    version: int
    updated_at: datetime


class SettingsUpdate(SettingsValues):
    version: int


class AuditOut(BaseModel):
    id: uuid.UUID
    at: datetime
    action: str
    actor_kind: str
    actor_email: str | None
    entity_kind: str | None
    entity_id: uuid.UUID | None
    details: dict[str, Any]
    request_id: str | None


class OrgUsageOut(BaseModel):
    """Aggregate usage against limits; metadata and counts only (FR-PLT-006)."""

    organization_id: uuid.UUID
    slug: str
    name: str
    status: str
    active_members: int
    monitors_live: int
    monitors_active: int
    max_monitors: int
    status_pages: int
    max_status_pages: int
    channels: int
    max_channels: int
    open_incidents_critical: int
    open_incidents_warning: int


class DailyUsageOut(BaseModel):
    day: date
    checks: int
    failed_checks: int
    blocked_checks: int
    inconclusive_checks: int
    incidents_opened: int
    notifications_sent: int
    notification_failures: int


class QueueHealthOut(BaseModel):
    checks_per_minute: float
    checks_last_24h: int
    due_backlog: int
    claim_lag_seconds: float | None
    checks_in_flight: int
    outbox_pending: int
    outbox_leased: int
    outbox_lag_seconds: float | None
    outbox_failed_24h: int


class WorkerOut(BaseModel):
    worker_id: str
    kind: str
    last_seen_at: datetime
    in_flight: int
    alive: bool


class DashboardOut(BaseModel):
    organizations_by_status: dict[str, int]
    active_admins: int
    pending_invitations: int
    recent_audit: list[AuditOut]
    organizations_created_30d: int
    monitors_total: int
    monitors_active: int
    open_incidents_by_severity: dict[str, int]
    queue: QueueHealthOut
    workers: list[WorkerOut]
    usage_daily: list[DailyUsageOut]
    organizations: list[OrgUsageOut]
