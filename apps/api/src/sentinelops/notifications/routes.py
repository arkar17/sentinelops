"""Notification routes under /api/orgs/{org_id}. Each route declares one permission action.

Channel responses never include credentials: Telegram channels report only that credentials are
set. Delivery history returns result codes only.
"""

import uuid
from datetime import datetime
from typing import Annotated, Any, Literal

from fastapi import APIRouter, Depends, Query, Request, status
from pydantic import BaseModel, Field

from sentinelops.db.session import DbSession
from sentinelops.notifications import service
from sentinelops.notifications.models import NotificationRoute
from sentinelops.secrets.cipher import SecretBox
from sentinelops.tenancy.context import OrgContext, OrgPermission

router = APIRouter(prefix="/api/orgs/{org_id}", tags=["notifications"])

EventName = Literal[
    "INCIDENT_OPENED",
    "TLS_EXPIRY_WARNING",
    "INCIDENT_ACKNOWLEDGED",
    "INCIDENT_RESOLVED",
    "MONITOR_AUTO_PAUSED",
]


def Ctx(action: str) -> Any:  # noqa: N802  # reads like a type in signatures
    return Depends(OrgPermission(action))


def _box(request: Request) -> SecretBox:
    box: SecretBox = request.app.state.secret_box
    return box


Box = Annotated[SecretBox, Depends(_box)]


class TelegramIn(BaseModel):
    bot_token: str = Field(min_length=1, max_length=100)
    chat_id: str = Field(min_length=1, max_length=40)

    def to_input(self) -> service.TelegramInput:
        return service.TelegramInput(self.bot_token, self.chat_id)


class ChannelIn(BaseModel):
    type: Literal["TELEGRAM", "EMAIL"]
    label: str = Field(min_length=1, max_length=80)
    telegram: TelegramIn | None = None
    recipient_user_ids: list[uuid.UUID] = Field(default_factory=list[uuid.UUID], max_length=50)
    route_all_events: bool = True


class ChannelUpdate(BaseModel):
    version: int
    label: str | None = Field(default=None, min_length=1, max_length=80)
    enabled: bool | None = None
    telegram: TelegramIn | None = None
    recipient_user_ids: list[uuid.UUID] | None = Field(default=None, max_length=50)


class RecipientOut(BaseModel):
    user_id: uuid.UUID
    email: str


class ChannelOut(BaseModel):
    id: uuid.UUID
    type: str
    label: str
    enabled: bool
    credentials_set: bool
    recipients: list[RecipientOut]
    created_at: datetime
    version: int


class RouteIn(BaseModel):
    channel_id: uuid.UUID
    project_id: uuid.UUID | None = None
    monitor_id: uuid.UUID | None = None
    event_types: list[EventName] = Field(min_length=1, max_length=5)


class RouteUpdate(BaseModel):
    version: int
    event_types: list[EventName] | None = Field(default=None, min_length=1, max_length=5)
    enabled: bool | None = None


class RouteOut(BaseModel):
    id: uuid.UUID
    channel_id: uuid.UUID
    project_id: uuid.UUID | None
    monitor_id: uuid.UUID | None
    event_types: list[str]
    enabled: bool
    version: int


class AttemptOut(BaseModel):
    attempt: int
    result_code: str
    attempted_at: datetime


class DeliveryOut(BaseModel):
    id: uuid.UUID
    channel_id: uuid.UUID
    event_type: str
    incident_id: uuid.UUID | None
    monitor_id: uuid.UUID | None
    state: str
    cancel_reason: str | None
    attempts: int
    last_result_code: str | None
    created_at: datetime
    next_attempt_at: datetime
    sent_at: datetime | None
    history: list[AttemptOut]


def _channel(view: service.ChannelView) -> ChannelOut:
    c = view.channel
    return ChannelOut(
        id=c.id,
        type=c.type,
        label=c.label,
        enabled=c.enabled,
        credentials_set=c.config_ciphertext is not None,
        recipients=[RecipientOut(user_id=u, email=e) for u, e in view.recipients],
        created_at=c.created_at,
        version=c.version,
    )


def _route(route: NotificationRoute) -> RouteOut:
    return RouteOut(
        id=route.id,
        channel_id=route.channel_id,
        project_id=route.project_id,
        monitor_id=route.monitor_id,
        event_types=route.event_types_json,
        enabled=route.enabled,
        version=route.version,
    )


@router.get("/notification-channels", response_model=list[ChannelOut])
async def list_channels(
    db: DbSession, ctx: Annotated[OrgContext, Ctx("NTF.view")]
) -> list[ChannelOut]:
    return [_channel(v) for v in await service.list_channels(db, ctx)]


@router.post(
    "/notification-channels", response_model=ChannelOut, status_code=status.HTTP_201_CREATED
)
async def create_channel(
    body: ChannelIn,
    db: DbSession,
    box: Box,
    ctx: Annotated[OrgContext, Ctx("NTF.channel.manage")],
) -> ChannelOut:
    channel = await service.create_channel(
        db,
        ctx,
        box,
        type=body.type,
        label=body.label,
        telegram=body.telegram.to_input() if body.telegram else None,
        recipient_ids=body.recipient_user_ids,
        route_all_events=body.route_all_events,
    )
    return _channel(await service.get_channel(db, ctx, channel.id))


@router.patch("/notification-channels/{channel_id}", response_model=ChannelOut)
async def update_channel(
    channel_id: uuid.UUID,
    body: ChannelUpdate,
    db: DbSession,
    box: Box,
    ctx: Annotated[OrgContext, Ctx("NTF.channel.manage")],
) -> ChannelOut:
    await service.update_channel(
        db,
        ctx,
        box,
        channel_id,
        version=body.version,
        label=body.label,
        enabled=body.enabled,
        telegram=body.telegram.to_input() if body.telegram else None,
        recipient_ids=body.recipient_user_ids,
    )
    return _channel(await service.get_channel(db, ctx, channel_id))


@router.post("/notification-channels/{channel_id}/test", status_code=status.HTTP_202_ACCEPTED)
async def test_channel(
    channel_id: uuid.UUID, db: DbSession, ctx: Annotated[OrgContext, Ctx("NTF.channel.test")]
) -> dict[str, str]:
    await service.request_test(db, ctx, channel_id)
    return {"status": "queued"}


@router.get("/notification-routes", response_model=list[RouteOut])
async def list_routes(db: DbSession, ctx: Annotated[OrgContext, Ctx("NTF.view")]) -> list[RouteOut]:
    return [_route(r) for r in await service.list_routes(db, ctx)]


@router.post("/notification-routes", response_model=RouteOut, status_code=status.HTTP_201_CREATED)
async def create_route(
    body: RouteIn, db: DbSession, ctx: Annotated[OrgContext, Ctx("NTF.route.manage")]
) -> RouteOut:
    route = await service.create_route(
        db,
        ctx,
        channel_id=body.channel_id,
        project_id=body.project_id,
        monitor_id=body.monitor_id,
        event_types=list(body.event_types),
    )
    return _route(route)


@router.patch("/notification-routes/{route_id}", response_model=RouteOut)
async def update_route(
    route_id: uuid.UUID,
    body: RouteUpdate,
    db: DbSession,
    ctx: Annotated[OrgContext, Ctx("NTF.route.manage")],
) -> RouteOut:
    route = await service.update_route(
        db,
        ctx,
        route_id,
        version=body.version,
        event_types=list(body.event_types) if body.event_types else None,
        enabled=body.enabled,
    )
    return _route(route)


@router.delete("/notification-routes/{route_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_route(
    route_id: uuid.UUID, db: DbSession, ctx: Annotated[OrgContext, Ctx("NTF.route.manage")]
) -> None:
    await service.delete_route(db, ctx, route_id)


@router.get("/notification-deliveries", response_model=list[DeliveryOut])
async def list_deliveries(
    db: DbSession,
    ctx: Annotated[OrgContext, Ctx("NTF.delivery.view")],
    channel_id: uuid.UUID | None = None,
    limit: Annotated[int, Query(ge=1, le=200)] = 50,
) -> list[DeliveryOut]:
    views = await service.list_deliveries(db, ctx, channel_id=channel_id, limit=limit)
    return [
        DeliveryOut(
            id=v.item.id,
            channel_id=v.item.channel_id,
            event_type=v.item.event_type,
            incident_id=v.item.incident_id,
            monitor_id=v.item.monitor_id,
            state=v.item.state,
            cancel_reason=v.item.cancel_reason,
            attempts=v.item.attempts,
            last_result_code=v.item.last_result_code,
            created_at=v.item.created_at,
            next_attempt_at=v.item.next_attempt_at,
            sent_at=v.item.sent_at,
            history=[
                AttemptOut(
                    attempt=a.attempt, result_code=a.result_code, attempted_at=a.attempted_at
                )
                for a in v.attempts
            ],
        )
        for v in views
    ]
