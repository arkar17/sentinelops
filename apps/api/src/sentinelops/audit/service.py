"""Audit writer. Callers pass only safe, non-secret fields in ``details``."""

import uuid
from typing import Any

from sqlalchemy.ext.asyncio import AsyncSession

from sentinelops import clock
from sentinelops.audit.models import AuditEvent
from sentinelops.log_config import request_id_var


class AuditAction:
    LOGIN_SUCCEEDED = "auth.login_succeeded"
    LOGIN_FAILED = "auth.login_failed"
    LOGIN_THROTTLED = "auth.login_throttled"
    LOGOUT = "auth.logout"
    ACCOUNT_ACTIVATED = "auth.account_activated"
    PASSWORD_RESET_REQUESTED = "auth.password_reset_requested"  # noqa: S105  # identifier, not a credential
    PASSWORD_RESET_COMPLETED = "auth.password_reset_completed"  # noqa: S105  # identifier, not a credential
    PASSWORD_CHANGED = "auth.password_changed"  # noqa: S105  # identifier, not a credential
    SESSIONS_REVOKED = "auth.sessions_revoked"
    MFA_ENROLLMENT_STARTED = "auth.mfa_enrollment_started"
    MFA_ENABLED = "auth.mfa_enabled"
    MFA_VERIFIED = "auth.mfa_verified"
    MFA_FAILED = "auth.mfa_failed"
    MFA_REAUTH_FAILED = "auth.mfa_reauthentication_failed"
    MFA_RECOVERY_CODES_REPLACED = "auth.mfa_recovery_codes_replaced"
    MFA_DISABLED = "auth.mfa_disabled"
    MFA_RESET_BY_OPERATOR = "platform.mfa_reset_by_operator"
    BOOTSTRAP = "platform.bootstrap_system_admin"
    RECOVERY = "platform.recover_system_admin"
    ADMIN_INVITED = "platform.admin_invited"
    ADMIN_INVITATION_REVOKED = "platform.admin_invitation_revoked"
    ADMIN_INVITATION_ACCEPTED = "platform.admin_invitation_accepted"
    ADMIN_DEACTIVATED = "platform.admin_deactivated"
    SETTINGS_UPDATED = "platform.settings_updated"
    ORG_CREATED = "platform.org_created"
    ORG_UPDATED = "platform.org_updated"
    ORG_SUSPENDED = "platform.org_suspended"
    ORG_ACTIVATED = "platform.org_activated"
    ORG_LIMITS_UPDATED = "platform.org_limits_updated"
    ORG_OWNER_INVITED = "platform.org_owner_invited"
    ORG_PROFILE_UPDATED = "org.profile_updated"
    MEMBER_INVITED = "org.member_invited"
    MEMBER_INVITATION_REVOKED = "org.member_invitation_revoked"
    MEMBER_JOINED = "org.member_joined"
    MEMBER_ROLE_CHANGED = "org.member_role_changed"
    MEMBER_STATUS_CHANGED = "org.member_status_changed"
    MEMBER_REMOVED = "org.member_removed"
    MEMBER_LEFT = "org.member_left"
    PROJECT_CREATED = "org.project_created"
    PROJECT_UPDATED = "org.project_updated"
    PROJECT_ARCHIVED = "org.project_archived"
    PROJECT_UNARCHIVED = "org.project_unarchived"
    DOMAIN_ADDED = "org.domain_added"
    DOMAIN_CHALLENGE_REGENERATED = "org.domain_challenge_regenerated"
    DOMAIN_VERIFIED = "org.domain_verified"
    DOMAIN_REVOKED = "org.domain_revoked"
    DOMAIN_EXCEPTION_REQUESTED = "org.domain_exception_requested"
    DOMAIN_EXCEPTION_APPROVED = "platform.domain_exception_approved"
    DOMAIN_EXCEPTION_REJECTED = "platform.domain_exception_rejected"
    MONITOR_CREATED = "org.monitor_created"
    MONITOR_UPDATED = "org.monitor_updated"
    MONITOR_HEADERS_CHANGED = "org.monitor_headers_changed"
    MONITOR_PAUSED = "org.monitor_paused"
    MONITOR_RESUMED = "org.monitor_resumed"
    MONITOR_ARCHIVED = "org.monitor_archived"
    MONITOR_UNARCHIVED = "org.monitor_unarchived"
    MONITOR_CHECK_REQUESTED = "org.monitor_check_requested"
    MONITOR_AUTO_PAUSED = "system.monitor_auto_paused"
    INCIDENT_OPENED = "system.incident_opened"
    INCIDENT_AUTO_RESOLVED = "system.incident_resolved"
    INCIDENT_UNASSIGNED_INACTIVE = "system.incident_unassigned"
    INCIDENT_ACKNOWLEDGED = "org.incident_acknowledged"
    INCIDENT_ASSIGNED = "org.incident_assigned"
    INCIDENT_COMMENTED = "org.incident_commented"
    INCIDENT_RESOLVED = "org.incident_resolved"
    CHANNEL_CREATED = "org.notification_channel_created"
    CHANNEL_UPDATED = "org.notification_channel_updated"
    CHANNEL_TESTED = "org.notification_channel_tested"
    ROUTE_CREATED = "org.notification_route_created"
    ROUTE_UPDATED = "org.notification_route_updated"
    ROUTE_DELETED = "org.notification_route_deleted"
    STATUS_PAGE_CREATED = "org.status_page_created"
    STATUS_PAGE_UPDATED = "org.status_page_updated"
    STATUS_PAGE_PUBLISHED = "org.status_page_published"
    STATUS_PAGE_UNPUBLISHED = "org.status_page_unpublished"


def record(
    db: AsyncSession,
    action: str,
    *,
    actor_kind: str = "USER",
    actor_user_id: uuid.UUID | None = None,
    actor_plane: str = "NONE",
    entity_kind: str | None = None,
    entity_id: uuid.UUID | None = None,
    details: dict[str, Any] | None = None,
    organization_id: uuid.UUID | None = None,
    scope: str = "PLATFORM",
) -> None:
    """Platform actions affecting an organization pass organization_id with scope PLATFORM, so
    they also appear in that organization's audit log (FR-PLT-007)."""
    db.add(
        AuditEvent(
            scope=scope,
            organization_id=organization_id,
            actor_kind=actor_kind,
            actor_user_id=actor_user_id,
            actor_plane=actor_plane,
            action=action,
            entity_kind=entity_kind,
            entity_id=entity_id,
            safe_diff_json=details or {},
            request_id=request_id_var.get(),
            at=clock.now(),
        )
    )
