"""GET /api/orgs/{org_id}/events: the organization's dashboard event stream (FR-UI-005).

Authorization (RPT.dashboard, ACTIVE membership, ACTIVE organization) is checked at connect and
re-validated every ``revalidate_seconds`` (at most 30 s) together with the login session; on
failure the stream sends ``revoked`` and closes. Streams also close after ``max_seconds`` with
``reconnect``. Clients reconnect and refetch their snapshot; events between connections are not
replayed.
"""

import asyncio
import json
from collections.abc import AsyncIterator
from dataclasses import dataclass
from typing import Annotated

from fastapi import APIRouter, Depends, Request
from fastapi.responses import StreamingResponse
from sqlalchemy import select

from sentinelops import clock
from sentinelops.identity.models import AppUser, UserSession, UserStatus
from sentinelops.realtime.hub import Event, EventHub, Subscription
from sentinelops.tenancy.context import OrgContext, OrgPermission, load_membership
from sentinelops.tenancy.models import OrgStatus

router = APIRouter(prefix="/api/orgs/{org_id}", tags=["realtime"])


@dataclass(frozen=True)
class SseSettings:
    heartbeat_seconds: float = 15.0
    revalidate_seconds: float = 15.0
    max_seconds: float = 300.0
    retry_ms: int = 5000


def _frame(event: Event) -> str:
    return f"event: {event.name}\ndata: {json.dumps(event.data, separators=(',', ':'))}\n\n"


async def still_authorized(request: Request, ctx: OrgContext) -> bool:
    async with request.app.state.sessionmaker() as db:
        found = await load_membership(db, ctx.organization_id, ctx.user_id)
        if found is None or found[0].status != OrgStatus.ACTIVE:
            return False
        session = await db.scalar(
            select(UserSession)
            .join(AppUser, AppUser.id == UserSession.user_id)
            .where(
                UserSession.id == ctx.principal.session_id,
                UserSession.revoked_at.is_(None),
                UserSession.expires_at > clock.now(),
                AppUser.status == UserStatus.ACTIVE,
            )
        )
        return session is not None


async def stream(
    request: Request,
    ctx: OrgContext,
    hub: EventHub,
    subscription: Subscription,
    settings: SseSettings,
) -> AsyncIterator[str]:
    loop = asyncio.get_running_loop()
    deadline = loop.time() + settings.max_seconds
    next_check = loop.time() + settings.revalidate_seconds
    try:
        yield f"retry: {settings.retry_ms}\n\n"
        yield _frame(Event("ready", {"organization_id": str(ctx.organization_id)}))
        while True:
            now = loop.time()
            if now >= deadline:
                yield _frame(Event("reconnect", {}))
                return
            if now >= next_check:
                if not await still_authorized(request, ctx):
                    yield _frame(Event("revoked", {}))
                    return
                next_check = now + settings.revalidate_seconds
            if await request.is_disconnected():
                return
            wait = max(0.0, min(settings.heartbeat_seconds, next_check - now, deadline - now))
            try:
                event = await asyncio.wait_for(subscription.queue.get(), timeout=wait)
            except TimeoutError:
                yield ": keepalive\n\n"
                continue
            yield _frame(event)
    finally:
        hub.unsubscribe(subscription)


@router.get("/events")
async def events(
    request: Request, ctx: Annotated[OrgContext, Depends(OrgPermission("RPT.dashboard"))]
) -> StreamingResponse:
    hub: EventHub = request.app.state.event_hub
    settings: SseSettings = request.app.state.sse_settings
    subscription = await hub.subscribe(ctx.organization_id)
    return StreamingResponse(
        stream(request, ctx, hub, subscription, settings),
        media_type="text/event-stream",
        headers={"Cache-Control": "no-store", "X-Accel-Buffering": "no"},
    )
