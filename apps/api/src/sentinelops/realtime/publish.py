"""Publish a dashboard event in the caller's transaction (``pg_notify`` is delivered on commit,
and dropped on rollback). Payloads carry IDs, states and result codes only: no names, URLs,
hosts, headers, notes or secrets. This module depends on nothing else in the domain."""

import json
import uuid
from typing import Any

from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

CHANNEL = "sentinelops_events"


def _jsonable(value: Any) -> Any:
    return str(value) if isinstance(value, uuid.UUID) else value


async def publish(
    db: AsyncSession, organization_id: uuid.UUID, event: str, **data: str | int | uuid.UUID | None
) -> None:
    payload = json.dumps(
        {
            "org": str(organization_id),
            "event": event,
            "data": {k: _jsonable(v) for k, v in data.items()},
        },
        separators=(",", ":"),
    )
    await db.execute(select(func.pg_notify(CHANNEL, payload)))
