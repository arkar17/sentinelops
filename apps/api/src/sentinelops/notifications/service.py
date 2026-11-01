"""Channel, route and delivery-history management (FR-NTF-001..005, PERMISSION_MATRIX NTF.*).

Telegram credentials (organization bot token + chat ID, ADR-014) are validated, sealed with
SecretBox bound to (organization, channel, "config") and never returned, logged or audited:
responses only say whether they are set. Email channels deliver through the platform relay to
recipients who are ACTIVE members of the organization (OD-08); organizations never supply SMTP
hosts or URLs. Channel tests are queued for the notifier, so the API makes no outbound calls.
"""

import json
import re
import uuid
from dataclasses import dataclass
from datetime import timedelta
from typing import Any

from sqlalchemy import delete, func, select
from sqlalchemy.ext.asyncio import AsyncSession

from sentinelops import clock
from sentinelops.audit.service import AuditAction, record
from sentinelops.catalog.models import Monitor, Project
from sentinelops.db.base import new_id
from sentinelops.errors import AppError
from sentinelops.identity.models import AppUser
from sentinelops.notifications.dispatcher import channel_binding
from sentinelops.notifications.models import (
    ChannelType,
    NotificationChannel,
    NotificationChannelRecipient,
    NotificationDelivery,
    NotificationOutbox,
    NotificationRoute,
    NotifyEvent,
)
from sentinelops.notifications.outbox import CHANNEL_DISABLED_REASON, cancel_pending, enqueue_test
from sentinelops.secrets.cipher import SecretBox
from sentinelops.tenancy.context import OrgContext
from sentinelops.tenancy.limits import effective_limits
from sentinelops.tenancy.locks import lock_organization
from sentinelops.tenancy.models import MemberStatus, OrganizationMember

BOT_TOKEN = re.compile(r"^\d{5,15}:[A-Za-z0-9_-]{30,64}$")
CHAT_ID = re.compile(r"^(-?\d{1,20}|@[A-Za-z][A-Za-z0-9_]{4,31})$")
MAX_RECIPIENTS = 50
TEST_INTERVAL = timedelta(seconds=60)


def _error(code: str, message: str, status: int = 422) -> AppError:
    return AppError(status, code, message)


def _not_found(kind: str = "Channel") -> AppError:
    return AppError(404, "NOT_FOUND", f"{kind} not found")


def clean_label(value: str) -> str:
    label = " ".join(value.split())
    if not 1 <= len(label) <= 80:
        raise _error("INVALID_LABEL", "The label must be 1-80 characters")
    return label


@dataclass(frozen=True)
class TelegramInput:
    bot_token: str
    chat_id: str


def validate_telegram(data: TelegramInput) -> TelegramInput:
    """Format checks only; values never appear in error messages."""
    token, chat = data.bot_token.strip(), data.chat_id.strip()
    if not BOT_TOKEN.fullmatch(token):
        raise _error("INVALID_BOT_TOKEN", "The bot token format is not valid")
    if not CHAT_ID.fullmatch(chat):
        raise _error("INVALID_CHAT_ID", "Use a numeric chat ID or an @channel username")
    return TelegramInput(token, chat)


def _seal(box: SecretBox, channel: NotificationChannel, data: TelegramInput) -> None:
    sealed = box.seal(
        json.dumps({"bot_token": data.bot_token, "chat_id": data.chat_id}),
        channel_binding(channel),
    )
    channel.config_ciphertext, channel.config_key_id = sealed.ciphertext, sealed.key_id


def _audit(
    db: AsyncSession, ctx: OrgContext, action: str, kind: str, entity: uuid.UUID, **details: Any
) -> None:
    record(
        db,
        action,
        scope="ORGANIZATION",
        organization_id=ctx.organization_id,
        actor_user_id=ctx.user_id,
        actor_plane="ORG",
        entity_kind=kind,
        entity_id=entity,
        details=details or None,
    )


# --- channels ---------------------------------------------------------------------------------


@dataclass(frozen=True)
class ChannelView:
    channel: NotificationChannel
    recipients: list[tuple[uuid.UUID, str]]


async def _recipient_rows(
    db: AsyncSession, ctx: OrgContext, channel_ids: list[uuid.UUID]
) -> dict[uuid.UUID, list[tuple[uuid.UUID, str]]]:
    rows = await db.execute(
        select(NotificationChannelRecipient.channel_id, AppUser.id, AppUser.email)
        .join(AppUser, AppUser.id == NotificationChannelRecipient.user_id)
        .where(
            NotificationChannelRecipient.organization_id == ctx.organization_id,
            NotificationChannelRecipient.channel_id.in_(channel_ids),
        )
        .order_by(AppUser.email)
    )
    found: dict[uuid.UUID, list[tuple[uuid.UUID, str]]] = {}
    for channel_id, user_id, email in rows:
        found.setdefault(channel_id, []).append((user_id, email))
    return found


async def list_channels(db: AsyncSession, ctx: OrgContext) -> list[ChannelView]:
    channels = list(
        await db.scalars(
            select(NotificationChannel)
            .where(NotificationChannel.organization_id == ctx.organization_id)
            .order_by(func.lower(NotificationChannel.label), NotificationChannel.id)
        )
    )
    recipients = await _recipient_rows(db, ctx, [c.id for c in channels])
    return [ChannelView(c, recipients.get(c.id, [])) for c in channels]


async def get_channel(db: AsyncSession, ctx: OrgContext, channel_id: uuid.UUID) -> ChannelView:
    channel = await db.scalar(
        select(NotificationChannel).where(
            NotificationChannel.organization_id == ctx.organization_id,
            NotificationChannel.id == channel_id,
        )
    )
    if channel is None:
        raise _not_found()
    return ChannelView(channel, (await _recipient_rows(db, ctx, [channel.id])).get(channel.id, []))


async def _lock_channel(
    db: AsyncSession, ctx: OrgContext, channel_id: uuid.UUID
) -> NotificationChannel:
    channel = await db.scalar(
        select(NotificationChannel)
        .where(
            NotificationChannel.organization_id == ctx.organization_id,
            NotificationChannel.id == channel_id,
        )
        .with_for_update()
    )
    if channel is None:
        raise _not_found()
    return channel


async def _set_recipients(
    db: AsyncSession, ctx: OrgContext, channel: NotificationChannel, user_ids: list[uuid.UUID]
) -> None:
    unique = list(dict.fromkeys(user_ids))
    if not 1 <= len(unique) <= MAX_RECIPIENTS:
        raise _error("INVALID_RECIPIENTS", f"Choose 1-{MAX_RECIPIENTS} members")
    active = set(
        await db.scalars(
            select(OrganizationMember.user_id)
            .where(
                OrganizationMember.organization_id == ctx.organization_id,
                OrganizationMember.user_id.in_(unique),
                OrganizationMember.status == MemberStatus.ACTIVE,
            )
            .with_for_update(read=True)
        )
    )
    if active != set(unique):
        raise _error(
            "RECIPIENT_NOT_MEMBER", "Recipients must be active members of this organization"
        )
    await db.execute(
        delete(NotificationChannelRecipient).where(
            NotificationChannelRecipient.organization_id == ctx.organization_id,
            NotificationChannelRecipient.channel_id == channel.id,
        )
    )
    for user_id in unique:
        db.add(
            NotificationChannelRecipient(
                organization_id=ctx.organization_id, channel_id=channel.id, user_id=user_id
            )
        )


async def create_channel(
    db: AsyncSession,
    ctx: OrgContext,
    box: SecretBox,
    *,
    type: str,  # API field name
    label: str,
    telegram: TelegramInput | None,
    recipient_ids: list[uuid.UUID],
    route_all_events: bool,
) -> NotificationChannel:
    clean = clean_label(label)
    if type == ChannelType.TELEGRAM and telegram is None:
        raise _error("TELEGRAM_CONFIG_REQUIRED", "Enter the bot token and chat ID")
    if type == ChannelType.EMAIL and telegram is not None:
        raise _error("INVALID_CONFIG", "Email channels take recipients, not credentials")
    config = validate_telegram(telegram) if telegram else None
    if await lock_organization(db, ctx.organization_id) is None:
        raise AppError(404, "NOT_FOUND", "Organization not found")
    limit = (await effective_limits(db, ctx.organization_id)).max_channels
    count = await db.scalar(
        select(func.count())
        .select_from(NotificationChannel)
        .where(NotificationChannel.organization_id == ctx.organization_id)
    )
    if int(count or 0) >= limit:
        raise _error("LIMIT_EXCEEDED", f"This organization may have at most {limit} channels", 409)
    now = clock.now()
    channel = NotificationChannel(
        id=new_id(),
        organization_id=ctx.organization_id,
        type=type,
        label=clean,
        enabled=True,
        created_by=ctx.user_id,
        created_at=now,
        updated_at=now,
        version=1,
    )
    if config:
        _seal(box, channel, config)
    db.add(channel)
    await db.flush()
    if type == ChannelType.EMAIL:
        await _set_recipients(db, ctx, channel, recipient_ids)
    if route_all_events:
        db.add(
            NotificationRoute(
                organization_id=ctx.organization_id,
                channel_id=channel.id,
                event_types_json=list(NotifyEvent.ROUTABLE),
                enabled=True,
                created_at=now,
            )
        )
    _audit(
        db,
        ctx,
        AuditAction.CHANNEL_CREATED,
        "notification_channel",
        channel.id,
        type=type,
        credentials_set=config is not None,
        recipients=len(recipient_ids) if type == ChannelType.EMAIL else 0,
    )
    await db.commit()
    return channel


async def update_channel(
    db: AsyncSession,
    ctx: OrgContext,
    box: SecretBox,
    channel_id: uuid.UUID,
    *,
    version: int,
    label: str | None,
    enabled: bool | None,
    telegram: TelegramInput | None,
    recipient_ids: list[uuid.UUID] | None,
) -> None:
    channel = await _lock_channel(db, ctx, channel_id)
    if channel.version != version:
        raise _error("VERSION_CONFLICT", "The channel changed; reload and try again", 409)
    changed: list[str] = []
    if label is not None and clean_label(label) != channel.label:
        channel.label = clean_label(label)
        changed.append("label")
    if telegram is not None:
        if channel.type != ChannelType.TELEGRAM:
            raise _error("INVALID_CONFIG", "Email channels take recipients, not credentials")
        _seal(box, channel, validate_telegram(telegram))
        changed.append("credentials")
    if recipient_ids is not None:
        if channel.type != ChannelType.EMAIL:
            raise _error("INVALID_CONFIG", "Only email channels have recipients")
        await _set_recipients(db, ctx, channel, recipient_ids)
        changed.append("recipients")
    cancelled = 0
    if enabled is not None and enabled != channel.enabled:
        channel.enabled = enabled
        changed.append("enabled" if enabled else "disabled")
        if not enabled:
            cancelled = await cancel_pending(
                db, ctx.organization_id, CHANNEL_DISABLED_REASON, channel_id=channel.id
            )
    if not changed:
        return
    channel.version += 1
    _audit(
        db,
        ctx,
        AuditAction.CHANNEL_UPDATED,
        "notification_channel",
        channel.id,
        changed=changed,
        cancelled_notifications=cancelled,
    )
    await db.commit()


async def request_test(db: AsyncSession, ctx: OrgContext, channel_id: uuid.UUID) -> None:
    channel = await _lock_channel(db, ctx, channel_id)
    if not channel.enabled:
        raise _error("CHANNEL_DISABLED", "Enable the channel before testing it", 409)
    recent = await db.scalar(
        select(func.count())
        .select_from(NotificationOutbox)
        .where(
            NotificationOutbox.organization_id == ctx.organization_id,
            NotificationOutbox.channel_id == channel.id,
            NotificationOutbox.event_type == NotifyEvent.CHANNEL_TEST,
            NotificationOutbox.created_at > clock.now() - TEST_INTERVAL,
        )
    )
    if recent:
        raise _error("TEST_RATE_LIMITED", "Wait a minute before sending another test", 429)
    await enqueue_test(db, channel)
    _audit(db, ctx, AuditAction.CHANNEL_TESTED, "notification_channel", channel.id)
    await db.commit()


# --- routes -----------------------------------------------------------------------------------


def _event_types(values: list[str]) -> list[str]:
    unique = list(dict.fromkeys(values))
    if not unique or any(v not in NotifyEvent.ROUTABLE for v in unique):
        raise _error("INVALID_EVENT_TYPES", "Choose one or more supported events")
    return unique


async def list_routes(db: AsyncSession, ctx: OrgContext) -> list[NotificationRoute]:
    return list(
        await db.scalars(
            select(NotificationRoute)
            .where(NotificationRoute.organization_id == ctx.organization_id)
            .order_by(NotificationRoute.created_at, NotificationRoute.id)
        )
    )


async def create_route(
    db: AsyncSession,
    ctx: OrgContext,
    *,
    channel_id: uuid.UUID,
    project_id: uuid.UUID | None,
    monitor_id: uuid.UUID | None,
    event_types: list[str],
) -> NotificationRoute:
    if project_id and monitor_id:
        raise _error("INVALID_SCOPE", "Scope a route to a project or a monitor, not both")
    await _lock_channel(db, ctx, channel_id)
    if project_id and not await db.scalar(
        select(Project.id).where(
            Project.organization_id == ctx.organization_id, Project.id == project_id
        )
    ):
        raise _not_found("Project")
    if monitor_id and not await db.scalar(
        select(Monitor.id).where(
            Monitor.organization_id == ctx.organization_id, Monitor.id == monitor_id
        )
    ):
        raise _not_found("Monitor")
    route = NotificationRoute(
        id=new_id(),
        organization_id=ctx.organization_id,
        channel_id=channel_id,
        project_id=project_id,
        monitor_id=monitor_id,
        event_types_json=_event_types(event_types),
        enabled=True,
        created_at=clock.now(),
        version=1,
    )
    db.add(route)
    _audit(
        db,
        ctx,
        AuditAction.ROUTE_CREATED,
        "notification_route",
        route.id,
        channel_id=str(channel_id),
    )
    await db.commit()
    return route


async def _lock_route(db: AsyncSession, ctx: OrgContext, route_id: uuid.UUID) -> NotificationRoute:
    route = await db.scalar(
        select(NotificationRoute)
        .where(
            NotificationRoute.organization_id == ctx.organization_id,
            NotificationRoute.id == route_id,
        )
        .with_for_update()
    )
    if route is None:
        raise _not_found("Route")
    return route


async def update_route(
    db: AsyncSession,
    ctx: OrgContext,
    route_id: uuid.UUID,
    *,
    version: int,
    event_types: list[str] | None,
    enabled: bool | None,
) -> NotificationRoute:
    route = await _lock_route(db, ctx, route_id)
    if route.version != version:
        raise _error("VERSION_CONFLICT", "The route changed; reload and try again", 409)
    if event_types is not None:
        route.event_types_json = _event_types(event_types)
    if enabled is not None:
        route.enabled = enabled
    route.version += 1
    _audit(db, ctx, AuditAction.ROUTE_UPDATED, "notification_route", route.id)
    await db.commit()
    return route


async def delete_route(db: AsyncSession, ctx: OrgContext, route_id: uuid.UUID) -> None:
    route = await _lock_route(db, ctx, route_id)
    await db.delete(route)
    _audit(db, ctx, AuditAction.ROUTE_DELETED, "notification_route", route_id)
    await db.commit()


# --- delivery history -------------------------------------------------------------------------


@dataclass(frozen=True)
class DeliveryView:
    item: NotificationOutbox
    attempts: list[NotificationDelivery]


async def list_deliveries(
    db: AsyncSession, ctx: OrgContext, *, channel_id: uuid.UUID | None, limit: int
) -> list[DeliveryView]:
    stmt = select(NotificationOutbox).where(
        NotificationOutbox.organization_id == ctx.organization_id
    )
    if channel_id is not None:
        stmt = stmt.where(NotificationOutbox.channel_id == channel_id)
    items = list(
        await db.scalars(
            stmt.order_by(NotificationOutbox.created_at.desc(), NotificationOutbox.id.desc()).limit(
                limit
            )
        )
    )
    attempts: dict[uuid.UUID, list[NotificationDelivery]] = {}
    if items:
        rows = await db.scalars(
            select(NotificationDelivery)
            .where(
                NotificationDelivery.organization_id == ctx.organization_id,
                NotificationDelivery.outbox_id.in_([i.id for i in items]),
            )
            .order_by(NotificationDelivery.attempted_at, NotificationDelivery.id)
        )
        for row in rows:
            attempts.setdefault(row.outbox_id, []).append(row)
    return [DeliveryView(i, attempts.get(i.id, [])) for i in items]
