"""Notifier: leases outbox rows and delivers them at least once (FR-NTF-003/005, Architecture §10).

1. Claim due rows with ``FOR UPDATE SKIP LOCKED``; each lease gets a token and counts an attempt.
   Expired leases (crashed notifier) are reclaimed; a row that used all 8 attempts fails.
2. Prepare under the row lock: re-validate (organization ACTIVE, channel enabled in the same
   organization, recipients still ACTIVE members), drop superseded items (an opened/acknowledged
   notice for an incident that is already resolved, or an auto-pause notice for a monitor that
   was resumed), apply the per-channel rate limit, render the message. Commit before any I/O.
3. Send with a timeout, outside any transaction.
4. Record one delivery row per attempt (per email recipient), then SENT, retry with bounded
   exponential backoff (temporary failures), or FAILED (permanent failures, attempts exhausted),
   but only while still holding the lease token.

Delivery is at-least-once: a crash between a provider accepting a message and step 4 resends it
after the lease expires. Messages carry an incident reference so duplicates are recognizable.
Email recipients already sent are skipped on retry.
"""

import asyncio
import contextlib
import json
import logging
import random
import uuid
from dataclasses import dataclass, field, replace
from datetime import datetime, timedelta
from typing import cast

from sqlalchemy import func, select
from sqlalchemy.dialects.postgresql import insert
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from sentinelops import __version__, clock
from sentinelops.catalog.eligibility import POLICY_BLOCKED
from sentinelops.catalog.models import Monitor, MonitorLifecycle, Project
from sentinelops.config import Settings
from sentinelops.db.base import new_id
from sentinelops.identity.models import AppUser, UserStatus
from sentinelops.incidents.models import EventType, Incident, IncidentEvent, IncidentStatus
from sentinelops.mail import MailDeliveryError, Mailer, OutgoingEmail
from sentinelops.notifications.messages import Message, MessageContext, render
from sentinelops.notifications.models import (
    ChannelType,
    NotificationChannel,
    NotificationChannelRecipient,
    NotificationDelivery,
    NotificationOutbox,
    NotifyEvent,
    OutboxState,
)
from sentinelops.notifications.outbox import CHANNEL_DISABLED_REASON, ORG_SUSPENDED_REASON
from sentinelops.notifications.telegram import SendResult, TelegramClient
from sentinelops.realtime.publish import publish
from sentinelops.scheduler.models import WorkerHeartbeat
from sentinelops.secrets.cipher import SecretBinding, SecretBox, SecretDecryptError
from sentinelops.tenancy.models import (
    MemberStatus,
    Organization,
    OrganizationMember,
    OrgRole,
    OrgStatus,
)

logger = logging.getLogger("sentinelops.notifier")

MAX_ATTEMPTS = 8  # FR-NTF-003
LEASE_SECONDS = 300
BACKOFF_BASE_SECONDS = 30
BACKOFF_CAP_SECONDS = 3600
CHANNEL_SENDS_PER_MINUTE = 20  # per channel, across notifiers (IC-19)
RATE_LIMIT_DEFER_SECONDS = 15
HEARTBEAT_EVERY = timedelta(seconds=30)
SUPERSEDED = "SUPERSEDED"
NO_RECIPIENTS = "NO_RECIPIENTS"
SENDING = "SENDING"
_INCIDENT_NOTICES = frozenset(
    {
        NotifyEvent.INCIDENT_OPENED,
        NotifyEvent.TLS_EXPIRY_WARNING,
        NotifyEvent.INCIDENT_ACKNOWLEDGED,
        NotifyEvent.INCIDENT_RESOLVED,
    }
)


def backoff_seconds(attempt: int) -> float:
    base = min(BACKOFF_BASE_SECONDS * 2 ** (attempt - 1), BACKOFF_CAP_SECONDS)
    return base * random.uniform(1.0, 1.2)  # noqa: S311  # jitter, not security


def _int(value: object) -> int | None:
    return value if isinstance(value, int) and not isinstance(value, bool) else None


def _text(value: object) -> str | None:
    return value if isinstance(value, str) else None


def channel_binding(channel: NotificationChannel) -> SecretBinding:
    return SecretBinding(channel.organization_id, "notification_channel", channel.id, "config")


@dataclass(frozen=True)
class Lease:
    outbox_id: uuid.UUID
    organization_id: uuid.UUID
    token: uuid.UUID
    attempt: int


@dataclass(frozen=True)
class Recipient:
    user_id: uuid.UUID
    email: str


@dataclass(frozen=True)
class Plan:
    channel_type: str
    message: Message
    recipients: list[Recipient]
    bot_token: str | None = None
    chat_id: str | None = None


@dataclass(frozen=True)
class Outcome:
    code: str
    ok: bool
    retryable: bool
    retry_after: int | None = None
    provider_ref: str | None = None
    recipient_user_id: uuid.UUID | None = None


@dataclass
class Dispatcher:
    sessionmaker: async_sessionmaker[AsyncSession]
    box: SecretBox
    telegram: TelegramClient
    mailer: Mailer
    settings: Settings
    worker_id: str = field(default_factory=lambda: f"notifier-{uuid.uuid4().hex[:12]}")
    batch: int = 20
    idle_seconds: float = 2.0
    _last_heartbeat: datetime | None = None

    # --- 1. claim -----------------------------------------------------------------------------

    async def claim(self) -> list[Lease]:
        now = clock.now()
        async with self.sessionmaker() as db:
            rows = list(
                await db.scalars(
                    select(NotificationOutbox)
                    .where(
                        (
                            (NotificationOutbox.state == OutboxState.PENDING)
                            & (NotificationOutbox.next_attempt_at <= now)
                        )
                        | (
                            (NotificationOutbox.state == OutboxState.LEASED)
                            & (NotificationOutbox.lease_until < now)
                        )
                    )
                    .order_by(NotificationOutbox.next_attempt_at)
                    .limit(self.batch)
                    .with_for_update(skip_locked=True)
                )
            )
            leases: list[Lease] = []
            for row in rows:
                if row.attempts >= MAX_ATTEMPTS:
                    self._finish(row, OutboxState.FAILED, row.last_result_code or "LEASE_EXPIRED")
                    continue
                row.state = OutboxState.LEASED
                row.attempts += 1
                row.lease_until = now + timedelta(seconds=LEASE_SECONDS)
                token = new_id()
                row.lease_token = token
                leases.append(Lease(row.id, row.organization_id, token, row.attempts))
            await db.commit()
        return leases

    @staticmethod
    def _finish(row: NotificationOutbox, state: str, code: str | None = None) -> None:
        row.state = state
        row.lease_until = None
        row.lease_token = None
        if code is not None:
            row.last_result_code = code

    @staticmethod
    def _cancel(row: NotificationOutbox, reason: str) -> None:
        Dispatcher._finish(row, OutboxState.CANCELLED, reason)
        row.cancel_reason = reason

    # --- 2. prepare ---------------------------------------------------------------------------

    async def _locked(self, db: AsyncSession, lease: Lease) -> NotificationOutbox | None:
        return await db.scalar(
            select(NotificationOutbox)
            .where(
                NotificationOutbox.organization_id == lease.organization_id,
                NotificationOutbox.id == lease.outbox_id,
                NotificationOutbox.state == OutboxState.LEASED,
                NotificationOutbox.lease_token == lease.token,
            )
            .with_for_update()
        )

    async def _recipients(
        self, db: AsyncSession, row: NotificationOutbox, admins_only: bool
    ) -> tuple[list[Recipient], int]:
        """ACTIVE member recipients not yet sent for this item, and how many were already sent."""
        sent = set(
            await db.scalars(
                select(NotificationDelivery.recipient_user_id).where(
                    NotificationDelivery.organization_id == row.organization_id,
                    NotificationDelivery.outbox_id == row.id,
                    NotificationDelivery.result_code == "SENT",
                )
            )
        )
        stmt = (
            select(AppUser.id, AppUser.email)
            .join(
                NotificationChannelRecipient,
                NotificationChannelRecipient.user_id == AppUser.id,
            )
            .join(
                OrganizationMember,
                (OrganizationMember.organization_id == NotificationChannelRecipient.organization_id)
                & (OrganizationMember.user_id == NotificationChannelRecipient.user_id),
            )
            .where(
                NotificationChannelRecipient.organization_id == row.organization_id,
                NotificationChannelRecipient.channel_id == row.channel_id,
                OrganizationMember.status == MemberStatus.ACTIVE,
                AppUser.status == UserStatus.ACTIVE,
            )
            .order_by(AppUser.email)
        )
        if admins_only:  # FR-MON-012: auto-pause notices go to owners and admins
            stmt = stmt.where(OrganizationMember.role.in_([OrgRole.OWNER, OrgRole.ADMIN]))
        rows = list(await db.execute(stmt))
        return [Recipient(uid, email) for uid, email in rows if uid not in sent], len(sent)

    async def _context(
        self, db: AsyncSession, row: NotificationOutbox, org: Organization, label: str
    ) -> MessageContext | None:
        base = f"{self.settings.public_base_url}/o/{org.slug}"
        if row.event_type == NotifyEvent.CHANNEL_TEST:
            return MessageContext(
                row.event_type, org.name, f"{base}/notifications", channel_label=label
            )
        monitor_row = (
            await db.execute(
                select(Monitor, Project.name)
                .join(
                    Project,
                    (Project.organization_id == Monitor.organization_id)
                    & (Project.id == Monitor.project_id),
                )
                .where(Monitor.organization_id == org.id, Monitor.id == row.monitor_id)
            )
        ).one_or_none()
        if monitor_row is None:
            return None
        monitor, project_name = monitor_row
        base_context = MessageContext(
            row.event_type,
            organization_name=org.name,
            link=f"{base}/monitors/{monitor.id}",
            project_name=project_name,
            monitor_name=monitor.name,
            hostname=monitor.hostname,
        )
        if row.event_type == NotifyEvent.MONITOR_AUTO_PAUSED:
            if (
                monitor.lifecycle != MonitorLifecycle.PAUSED
                or monitor.paused_reason != POLICY_BLOCKED
            ):
                return None  # resumed or changed since: obsolete
            return base_context
        incident = await db.scalar(
            select(Incident).where(
                Incident.organization_id == org.id, Incident.id == row.incident_id
            )
        )
        if incident is None:
            return None
        if (
            row.event_type != NotifyEvent.INCIDENT_RESOLVED
            and incident.status == IncidentStatus.RESOLVED
        ):
            return None  # an outage/ack notice must not arrive after the incident ended
        opened = await db.scalar(
            select(IncidentEvent.details_sanitized_json).where(
                IncidentEvent.organization_id == org.id,
                IncidentEvent.incident_id == incident.id,
                IncidentEvent.event_type == EventType.OPENED,
            )
        )
        details: dict[str, object] = opened or {}
        raw_evidence = details.get("evidence")
        evidence = cast(dict[str, object], raw_evidence) if isinstance(raw_evidence, dict) else {}
        return replace(
            base_context,
            link=f"{base}/incidents/{incident.id}",
            incident_type=incident.type,
            severity=incident.severity,
            opened_at=incident.opened_at,
            resolved_at=incident.resolved_at,
            resolution=incident.resolution,
            failure_category=_text(evidence.get("failure_category")),
            http_status=_int(evidence.get("http_status")),
            tls_days_remaining=_int(details.get("days_remaining")),
            tls_threshold_days=_int(details.get("threshold_days")),
        )

    async def _rate_limited(self, db: AsyncSession, row: NotificationOutbox, now: datetime) -> bool:
        """Sends in the last minute plus sends in flight, counted in one statement (one snapshot,
        so a send finishing concurrently is counted exactly once). The caller holds the channel
        row lock, so concurrent notifiers see each other's in-flight sends."""
        recent = (
            select(func.count(func.distinct(NotificationDelivery.outbox_id)))
            .join(
                NotificationOutbox,
                (NotificationOutbox.organization_id == NotificationDelivery.organization_id)
                & (NotificationOutbox.id == NotificationDelivery.outbox_id),
            )
            .where(
                NotificationOutbox.organization_id == row.organization_id,
                NotificationOutbox.channel_id == row.channel_id,
                NotificationDelivery.attempted_at > now - timedelta(seconds=60),
            )
            .scalar_subquery()
        )
        in_flight = (
            select(func.count())
            .select_from(NotificationOutbox)
            .where(
                NotificationOutbox.organization_id == row.organization_id,
                NotificationOutbox.channel_id == row.channel_id,
                NotificationOutbox.state == OutboxState.LEASED,
                NotificationOutbox.last_result_code == SENDING,
                NotificationOutbox.lease_until > now,
                NotificationOutbox.id != row.id,
            )
            .scalar_subquery()
        )
        total = await db.scalar(select(recent + in_flight))
        return int(total or 0) >= CHANNEL_SENDS_PER_MINUTE

    async def _prepare(self, lease: Lease, now: datetime) -> Plan | str:
        async with self.sessionmaker() as db:
            row = await self._locked(db, lease)
            if row is None:
                return "lost"
            org = await db.get(Organization, row.organization_id)
            channel = await db.scalar(
                select(NotificationChannel)
                .where(
                    NotificationChannel.organization_id == row.organization_id,
                    NotificationChannel.id == row.channel_id,
                )
                .with_for_update()  # serializes rate-limit accounting per channel
            )
            reason: str | None = None
            context: MessageContext | None = None
            if org is None or org.status != OrgStatus.ACTIVE:
                reason = ORG_SUSPENDED_REASON
            elif channel is None or not channel.enabled:
                reason = CHANNEL_DISABLED_REASON
            else:
                context = await self._context(db, row, org, channel.label)
                if context is None:
                    reason = SUPERSEDED
            if reason is not None or context is None or channel is None:
                self._cancel(row, reason or SUPERSEDED)
                await db.commit()
                return "cancelled"
            if await self._rate_limited(db, row, now):
                row.attempts -= 1  # deferral is not a delivery attempt
                row.next_attempt_at = now + timedelta(seconds=RATE_LIMIT_DEFER_SECONDS)
                self._finish(row, OutboxState.PENDING, "RATE_LIMITED_LOCAL")
                await db.commit()
                return "deferred"
            message = render(context)
            row.last_result_code = SENDING  # counted as in flight by _rate_limited
            if channel.type == ChannelType.EMAIL:
                recipients, already_sent = await self._recipients(
                    db, row, admins_only=row.event_type == NotifyEvent.MONITOR_AUTO_PAUSED
                )
                if not recipients:
                    if already_sent:
                        self._finish(row, OutboxState.SENT, "SENT")
                        row.sent_at = now
                    else:
                        self._cancel(row, NO_RECIPIENTS)
                    await db.commit()
                    return "cancelled" if not already_sent else "sent"
                await db.commit()
                return Plan(ChannelType.EMAIL, message, recipients)
            try:
                assert channel.config_key_id and channel.config_ciphertext  # noqa: S101  # CHECK constraint
                config = json.loads(
                    self.box.open(
                        channel.config_key_id, channel.config_ciphertext, channel_binding(channel)
                    )
                )
            except SecretDecryptError:
                self._finish(row, OutboxState.FAILED, "CONFIG_UNREADABLE")
                await db.commit()
                return "failed"
            await db.commit()
            return Plan(
                ChannelType.TELEGRAM,
                message,
                [],
                bot_token=str(config["bot_token"]),
                chat_id=str(config["chat_id"]),
            )

    # --- 3. send ------------------------------------------------------------------------------

    async def _send(self, plan: Plan) -> list[Outcome]:
        if plan.channel_type == ChannelType.TELEGRAM:
            assert plan.bot_token is not None and plan.chat_id is not None  # noqa: S101
            result: SendResult = await self.telegram.send_message(
                plan.bot_token, plan.chat_id, plan.message.text
            )
            return [
                Outcome(
                    result.code,
                    result.ok,
                    result.retryable,
                    result.retry_after,
                    result.provider_ref,
                )
            ]
        outcomes: list[Outcome] = []
        for recipient in plan.recipients:
            try:
                await self.mailer.send(
                    OutgoingEmail(
                        to=recipient.email, subject=plan.message.subject, body=plan.message.text
                    )
                )
                outcomes.append(Outcome("SENT", True, False, recipient_user_id=recipient.user_id))
            except MailDeliveryError as exc:
                code = "MAIL_REJECTED" if exc.permanent else "MAIL_FAILED"
                outcomes.append(
                    Outcome(code, False, not exc.permanent, recipient_user_id=recipient.user_id)
                )
        return outcomes

    # --- 4. record ----------------------------------------------------------------------------

    async def _record(self, lease: Lease, outcomes: list[Outcome], now: datetime) -> str:
        async with self.sessionmaker() as db:
            for outcome in outcomes:
                await db.execute(
                    insert(NotificationDelivery).values(
                        id=new_id(),
                        organization_id=lease.organization_id,
                        outbox_id=lease.outbox_id,
                        attempt=lease.attempt,
                        recipient_user_id=outcome.recipient_user_id,
                        result_code=outcome.code,
                        provider_ref=outcome.provider_ref,
                        attempted_at=now,
                    )
                )
            row = await self._locked(db, lease)
            if row is None:  # lease expired and was reclaimed meanwhile; keep the history only
                await db.commit()
                return "lost"
            failures = [o for o in outcomes if not o.ok]
            if not failures:
                self._finish(row, OutboxState.SENT, "SENT")
                row.sent_at = now
                status = "sent"
            elif any(o.retryable for o in failures) and lease.attempt < MAX_ATTEMPTS:
                delay = backoff_seconds(lease.attempt)
                hinted = [o.retry_after for o in failures if o.retry_after]
                if hinted:
                    delay = max(delay, float(max(hinted)))
                self._finish(row, OutboxState.PENDING, failures[0].code)
                row.next_attempt_at = now + timedelta(seconds=delay)
                status = "retry"
            else:
                self._finish(row, OutboxState.FAILED, failures[0].code)
                status = "failed"
            await publish(
                db,
                row.organization_id,
                "notification.delivery",
                outbox_id=row.id,
                channel_id=row.channel_id,
                state=row.state,
                result_code=row.last_result_code,
            )
            await db.commit()
            return status

    async def deliver(self, lease: Lease) -> str:
        plan = await self._prepare(lease, clock.now())
        if isinstance(plan, str):
            return plan
        outcomes = await self._send(plan)
        status = await self._record(lease, outcomes, clock.now())
        logger.info(
            "notification %s outbox=%s org=%s attempt=%s codes=%s",
            status,
            lease.outbox_id,
            lease.organization_id,
            lease.attempt,
            ",".join(sorted({o.code for o in outcomes})),
        )
        return status

    # --- loop ---------------------------------------------------------------------------------

    async def run_once(self) -> list[str]:
        leases = await self.claim()
        results = await asyncio.gather(*(self._safe(lease) for lease in leases))
        return list(results)

    async def _safe(self, lease: Lease) -> str:
        try:
            return await self.deliver(lease)
        except Exception:
            logger.exception("notification crashed outbox=%s; lease will expire", lease.outbox_id)
            return "crashed"

    async def heartbeat(self) -> None:
        now = clock.now()
        if self._last_heartbeat is not None and now - self._last_heartbeat < HEARTBEAT_EVERY:
            return
        async with self.sessionmaker() as db:
            await db.execute(
                insert(WorkerHeartbeat)
                .values(
                    worker_id=self.worker_id,
                    kind="NOTIFIER",
                    last_seen_at=now,
                    in_flight=0,
                    version_label=__version__,
                )
                .on_conflict_do_update(index_elements=["worker_id"], set_={"last_seen_at": now})
            )
            await db.commit()
        self._last_heartbeat = now

    async def run_forever(self, stop: asyncio.Event) -> None:
        """A batch in progress always finishes (each send has a timeout); unclaimed work stays
        PENDING and unfinished leases expire for reclaim."""
        while not stop.is_set():
            await self.heartbeat()
            results = await self.run_once()
            if not results:
                with contextlib.suppress(TimeoutError):
                    await asyncio.wait_for(stop.wait(), timeout=self.idle_seconds)
