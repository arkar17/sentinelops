"""Migration verification: the migrated schema matches the ORM metadata exactly."""

import pytest
from alembic.autogenerate import compare_metadata
from alembic.migration import MigrationContext
from sqlalchemy import text
from sqlalchemy.engine import Connection
from sqlalchemy.ext.asyncio import AsyncEngine

from sentinelops.db.models import Base

pytestmark = pytest.mark.integration


async def test_migrated_schema_matches_models(owner_engine: AsyncEngine) -> None:
    def diff(connection: Connection) -> list[object]:
        context = MigrationContext.configure(connection, opts={"compare_type": True})
        return list(compare_metadata(context, Base.metadata))

    async with owner_engine.connect() as conn:
        assert await conn.run_sync(diff) == []


async def test_platform_settings_seeded_with_baseline_defaults(owner_engine: AsyncEngine) -> None:
    async with owner_engine.connect() as conn:
        row = (await conn.execute(text("SELECT * FROM platform_settings"))).mappings().one()
    assert row["default_max_monitors"] == 20
    assert row["max_custom_headers"] == 5
    assert row["min_interval_seconds"] == 60


async def test_no_accounts_created_by_migration(owner_engine: AsyncEngine) -> None:
    async with owner_engine.connect() as conn:
        assert await conn.scalar(text("SELECT count(*) FROM app_user")) == 0
