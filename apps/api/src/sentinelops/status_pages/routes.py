"""Status page management (/api/orgs/{org_id}/status-pages, STP.*) and the anonymous public
endpoint (/api/status/{slug}, PUB.status_page) that serves only stored sanitized snapshots."""

import time
import uuid
from collections import defaultdict, deque
from datetime import datetime
from typing import Annotated, Any

from fastapi import APIRouter, Depends, Request, Response, status
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field

from sentinelops.db.session import DbSession
from sentinelops.errors import AppError, error_response
from sentinelops.identity.dependencies import client_ip
from sentinelops.status_pages import service
from sentinelops.tenancy.context import OrgContext, OrgPermission

router = APIRouter(prefix="/api/orgs/{org_id}/status-pages", tags=["status-pages"])
public_router = APIRouter(prefix="/api/status", tags=["public"])

PUBLIC_REQUESTS_PER_MINUTE = 120
PUBLIC_CACHE_SECONDS = 30


def Ctx(action: str) -> Any:  # noqa: N802  # reads like a type in signatures
    return Depends(OrgPermission(action))


class PageMonitorIn(BaseModel):
    monitor_id: uuid.UUID
    public_display_name: str = Field(min_length=1, max_length=80)


class PageIn(BaseModel):
    title: str = Field(min_length=1, max_length=80)
    public_slug: str = Field(min_length=3, max_length=40)
    monitors: list[PageMonitorIn] = Field(default_factory=list[PageMonitorIn], max_length=50)


class PageUpdate(BaseModel):
    version: int
    title: str | None = Field(default=None, min_length=1, max_length=80)
    public_slug: str | None = Field(default=None, min_length=3, max_length=40)
    monitors: list[PageMonitorIn] | None = Field(default=None, max_length=50)


class PageMonitorOut(BaseModel):
    monitor_id: uuid.UUID
    monitor_name: str
    public_display_name: str
    sort_order: int


class PageOut(BaseModel):
    id: uuid.UUID
    title: str
    public_slug: str
    published: bool
    monitors: list[PageMonitorOut]
    created_at: datetime
    version: int


def _inputs(items: list[PageMonitorIn]) -> list[service.PageMonitorInput]:
    return [service.PageMonitorInput(m.monitor_id, m.public_display_name) for m in items]


def _out(view: service.PageView) -> PageOut:
    p = view.page
    return PageOut(
        id=p.id,
        title=p.title,
        public_slug=p.public_slug,
        published=p.enabled,
        monitors=[
            PageMonitorOut(
                monitor_id=s.monitor_id,
                monitor_name=name,
                public_display_name=s.public_display_name,
                sort_order=s.sort_order,
            )
            for s, name in view.monitors
        ],
        created_at=p.created_at,
        version=p.version,
    )


@router.get("", response_model=list[PageOut])
async def list_pages(db: DbSession, ctx: Annotated[OrgContext, Ctx("STP.view")]) -> list[PageOut]:
    return [_out(v) for v in await service.list_pages(db, ctx)]


@router.post("", response_model=PageOut, status_code=status.HTTP_201_CREATED)
async def create_page(
    body: PageIn, db: DbSession, ctx: Annotated[OrgContext, Ctx("STP.manage")]
) -> PageOut:
    page = await service.create_page(
        db, ctx, title=body.title, slug=body.public_slug, monitors=_inputs(body.monitors)
    )
    return _out(await service.get_page(db, ctx, page.id))


@router.get("/{page_id}", response_model=PageOut)
async def get_page(
    page_id: uuid.UUID, db: DbSession, ctx: Annotated[OrgContext, Ctx("STP.view")]
) -> PageOut:
    return _out(await service.get_page(db, ctx, page_id))


@router.patch("/{page_id}", response_model=PageOut)
async def update_page(
    page_id: uuid.UUID,
    body: PageUpdate,
    db: DbSession,
    ctx: Annotated[OrgContext, Ctx("STP.manage")],
) -> PageOut:
    await service.update_page(
        db,
        ctx,
        page_id,
        version=body.version,
        title=body.title,
        slug=body.public_slug,
        monitors=_inputs(body.monitors) if body.monitors is not None else None,
    )
    return _out(await service.get_page(db, ctx, page_id))


@router.post("/{page_id}/publish", response_model=PageOut)
async def publish_page(
    page_id: uuid.UUID, db: DbSession, ctx: Annotated[OrgContext, Ctx("STP.publish")]
) -> PageOut:
    await service.set_published(db, ctx, page_id, published=True)
    return _out(await service.get_page(db, ctx, page_id))


@router.post("/{page_id}/unpublish", response_model=PageOut)
async def unpublish_page(
    page_id: uuid.UUID, db: DbSession, ctx: Annotated[OrgContext, Ctx("STP.publish")]
) -> PageOut:
    await service.set_published(db, ctx, page_id, published=False)
    return _out(await service.get_page(db, ctx, page_id))


@router.get("/{page_id}/preview")
async def preview_page(
    page_id: uuid.UUID, db: DbSession, ctx: Annotated[OrgContext, Ctx("STP.view")]
) -> dict[str, Any]:
    return await service.preview(db, ctx, page_id)


class PublicRateLimiter:
    """Per-client sliding window for the anonymous endpoint (per API process)."""

    def __init__(self, limit: int = PUBLIC_REQUESTS_PER_MINUTE, window: float = 60.0) -> None:
        self.limit, self.window = limit, window
        self._hits: dict[str, deque[float]] = defaultdict(deque)

    def allow(self, key: str) -> bool:
        now = time.monotonic()
        hits = self._hits[key]
        while hits and now - hits[0] > self.window:
            hits.popleft()
        if len(hits) >= self.limit:
            return False
        hits.append(now)
        if len(self._hits) > 10_000:  # bound memory: drop idle clients
            for idle in [k for k, v in self._hits.items() if not v]:
                del self._hits[idle]
        return True


def _limiter(request: Request) -> PublicRateLimiter:
    limiter: PublicRateLimiter = request.app.state.public_rate_limiter
    return limiter


@public_router.get("/{slug}", response_model=None)
async def public_status(
    slug: str,
    request: Request,
    db: DbSession,
    limiter: Annotated[PublicRateLimiter, Depends(_limiter)],
) -> Response:
    if not limiter.allow(client_ip(request)):
        raise AppError(429, "RATE_LIMITED", "Too many requests; try again shortly")
    payload = await service.public_snapshot(db, slug)
    if payload is None:  # unknown, unpublished, or organization suspended: indistinguishable
        missing = error_response(request, 404, "NOT_FOUND", "Status page not found")
        missing.headers["Cache-Control"] = "no-store"
        return missing
    return JSONResponse(
        payload,
        headers={
            "Cache-Control": f"public, max-age={PUBLIC_CACHE_SECONDS}",
            "X-Content-Type-Options": "nosniff",
        },
    )
