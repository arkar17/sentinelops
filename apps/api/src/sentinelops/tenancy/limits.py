"""Effective organization limits = per-organization override, else platform default (FR-PLT-008)."""

import uuid
from dataclasses import dataclass

from sqlalchemy.ext.asyncio import AsyncSession

from sentinelops.errors import AppError
from sentinelops.platform.models import PlatformSettings
from sentinelops.tenancy.models import OrganizationLimit

LIMIT_FIELDS = ("max_monitors", "min_interval_seconds", "max_status_pages", "max_channels")


@dataclass(frozen=True)
class EffectiveLimits:
    max_monitors: int
    min_interval_seconds: int
    max_status_pages: int
    max_channels: int


async def effective_limits(db: AsyncSession, organization_id: uuid.UUID) -> EffectiveLimits:
    platform = await db.get(PlatformSettings, 1)
    if platform is None:
        raise AppError(500, "SETTINGS_MISSING", "Platform settings are not initialized")
    override = await db.get(OrganizationLimit, organization_id)

    def pick(value: int | None, default: int) -> int:
        return default if value is None else value

    return EffectiveLimits(
        max_monitors=pick(override and override.max_monitors, platform.default_max_monitors),
        min_interval_seconds=pick(
            override and override.min_interval_seconds, platform.min_interval_seconds
        ),
        max_status_pages=pick(
            override and override.max_status_pages, platform.default_max_status_pages
        ),
        max_channels=pick(override and override.max_channels, platform.default_max_channels),
    )
