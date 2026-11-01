"""Platform-plane authorization: an ACTIVE platform_admin row, independent of any membership."""

from sentinelops.db.session import DbSession
from sentinelops.errors import AppError
from sentinelops.identity.dependencies import CurrentPrincipal, Principal
from sentinelops.platform.service import is_active_platform_admin

# PERMISSION_MATRIX.md §2: actions a SYSTEM_ADMIN may perform. Anything else is denied.
PLATFORM_ACTIONS = frozenset(
    {
        "PLT.dashboard.view",
        "PLT.org.list",
        "PLT.org.view",
        "PLT.org.create",
        "PLT.org.update",
        "PLT.org.suspend",
        "PLT.org.activate",
        "PLT.org.limits",
        "PLT.org.owner_invite",
        "PLT.admin.list",
        "PLT.admin.invite",
        "PLT.admin.deactivate",
        "PLT.settings.view",
        "PLT.settings.update",
        "PLT.domain_exception.decide",  # used from G3
        "PLT.audit.view",
    }
)


class PlatformPermission:
    """FastAPI dependency declaring the route's platform action ID and requiring SYSTEM_ADMIN."""

    def __init__(self, action: str) -> None:
        if action not in PLATFORM_ACTIONS:
            raise ValueError(f"{action} is not a permitted platform action")
        self.action = action

    async def __call__(self, principal: CurrentPrincipal, db: DbSession) -> Principal:
        if not await is_active_platform_admin(db, principal.user_id):
            raise AppError(403, "FORBIDDEN", "Platform administrator access required")
        return principal
