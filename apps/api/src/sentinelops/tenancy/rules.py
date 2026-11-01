"""Role-assignment rules (PERMISSION_MATRIX.md §4), as pure functions."""

from sentinelops.tenancy.models import OrgRole

ADMIN_MANAGEABLE = frozenset({OrgRole.MEMBER, OrgRole.VIEWER})


def can_manage(actor_role: str, target_role: str, new_role: str | None = None) -> bool:
    """Whether actor_role may act on a membership/invitation holding target_role (→ new_role)."""
    if actor_role == OrgRole.OWNER:
        return True
    if actor_role == OrgRole.ADMIN:
        return target_role in ADMIN_MANAGEABLE and (
            new_role is None or new_role in ADMIN_MANAGEABLE
        )
    return False


def can_invite(actor_role: str, role: str) -> bool:
    return can_manage(actor_role, role)
