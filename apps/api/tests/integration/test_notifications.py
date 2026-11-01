"""G5 notifications: channels, routes, transactional outbox and the notifier (AC-005, AC-006,
AC-016, AC-022, AC-028, AC-029, AC-032, FR-NTF-*). Telegram and SMTP are fakes; nothing is sent.
"""

import asyncio
import json
import uuid
from collections import Counter
from datetime import timedelta
from typing import Any

import pytest
from sqlalchemy import func, select, text, update
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from sentinelops import clock
from sentinelops.audit.models import AuditEvent
from sentinelops.mail import MailDeliveryError
from sentinelops.notifications import dispatcher as dispatch_module
from sentinelops.notifications.models import (
    NotificationChannel,
    NotificationDelivery,
    NotificationOutbox,
)
from sentinelops.notifications.telegram import SendResult
from sentinelops.platform.organizations import activate_organization, suspend_organization
from sentinelops.tenancy.models import OrganizationLimit
from tests.integration.g5 import BOT_TOKEN, CHAT_ID, SECRET_QUERY, Tenant, tenant
from tests.integration.helpers import csrf

pytestmark = pytest.mark.integration
__all__ = ["tenant"]


@pytest.fixture
def t(tenant: Tenant) -> Tenant:
    return tenant


async def deliveries(t: Tenant) -> list[NotificationDelivery]:
    async with t.session() as s:
        return list(
            await s.scalars(
                select(NotificationDelivery)
                .where(NotificationDelivery.organization_id == t.org)
                .order_by(NotificationDelivery.attempted_at, NotificationDelivery.id)
            )
        )


# --- channels -----------------------------------------------------------------------------------


async def test_telegram_credentials_are_write_only_and_encrypted(t: Tenant) -> None:
    channel = await t.telegram_channel()
    assert channel["credentials_set"] is True and channel["recipients"] == []
    listed = await t.member.get(t.url("/notification-channels"))
    assert listed.status_code == 200
    payloads = [json.dumps(channel), listed.text, (await t.admin.get(t.url("/audit"))).text]
    async with t.session() as s:
        row = await s.get(NotificationChannel, uuid.UUID(channel["id"]))
        assert row is not None and row.config_ciphertext is not None
        payloads.append(row.config_ciphertext)
        payloads.append(json.dumps([a.safe_diff_json for a in await s.scalars(select(AuditEvent))]))
    for payload in payloads:
        assert BOT_TOKEN not in payload
        assert BOT_TOKEN.split(":")[1] not in payload
        assert CHAT_ID not in payload
    # Replacing credentials keeps them hidden; the response still only says they are set.
    updated = await t.patch(
        t.admin,
        f"/notification-channels/{channel['id']}",
        {"version": 1, "telegram": {"bot_token": "987654:" + "B" * 35, "chat_id": "@acme_ops"}},
    )
    assert updated.status_code == 200 and "B" * 35 not in updated.text


@pytest.mark.parametrize(
    ("telegram", "code"),
    [
        ({"bot_token": "not-a-token", "chat_id": CHAT_ID}, "INVALID_BOT_TOKEN"),
        ({"bot_token": BOT_TOKEN, "chat_id": "https://evil.example/x"}, "INVALID_CHAT_ID"),
    ],
)
async def test_invalid_telegram_config_is_rejected_without_echo(
    t: Tenant, telegram: dict[str, str], code: str
) -> None:
    body = {"type": "TELEGRAM", "label": "Bad", "telegram": telegram}
    response = await t.post(t.admin, "/notification-channels", body)
    assert response.status_code == 422
    assert response.json()["error"]["code"] == code
    assert telegram["bot_token"] not in response.text and "evil" not in response.text


async def test_email_recipients_must_be_active_members(t: Tenant) -> None:
    outsider = await t.post(
        t.admin,
        "/notification-channels",
        {"type": "EMAIL", "label": "Mail", "recipient_user_ids": [str(t.outsider_id)]},
    )
    assert outsider.json()["error"]["code"] == "RECIPIENT_NOT_MEMBER"
    empty = await t.post(
        t.admin,
        "/notification-channels",
        {"type": "EMAIL", "label": "Mail", "recipient_user_ids": []},
    )
    assert empty.json()["error"]["code"] == "INVALID_RECIPIENTS"
    smtp = await t.post(
        t.admin,
        "/notification-channels",
        {"type": "EMAIL", "label": "Mail", "smtp_host": "evil.example", "recipient_user_ids": []},
    )
    assert smtp.status_code == 422  # no tenant-supplied SMTP or webhook fields exist
    channel = await t.email_channel(t.admin_id, t.viewer_id)
    assert {r["email"] for r in channel["recipients"]} == {"admin@acme.test", "viewer@acme.test"}


async def test_channel_limit_is_enforced(t: Tenant) -> None:
    async with t.session() as s:
        s.add(OrganizationLimit(organization_id=t.org, max_channels=1))
        await s.commit()
    await t.telegram_channel()
    second = await t.post(
        t.admin,
        "/notification-channels",
        {"type": "EMAIL", "label": "x", "recipient_user_ids": [str(t.admin_id)]},
    )
    assert second.status_code == 409 and second.json()["error"]["code"] == "LIMIT_EXCEEDED"


async def test_channel_permissions_follow_the_matrix(t: Tenant) -> None:
    channel = await t.telegram_channel()
    cid = channel["id"]
    body = {"type": "EMAIL", "label": "x", "recipient_user_ids": [str(t.member_id)]}
    assert (await t.post(t.member, "/notification-channels", body)).status_code == 403
    assert (
        await t.patch(t.member, f"/notification-channels/{cid}", {"version": 1})
    ).status_code == 403
    assert (await t.post(t.member, f"/notification-channels/{cid}/test")).status_code == 403
    assert (await t.member.get(t.url("/notification-channels"))).status_code == 200
    assert (await t.member.get(t.url("/notification-deliveries"))).status_code == 200
    route = {"channel_id": cid, "event_types": ["INCIDENT_OPENED"]}
    assert (await t.post(t.member, "/notification-routes", route)).status_code == 403
    for path in ("/notification-channels", "/notification-routes", "/notification-deliveries"):
        assert (await t.viewer.get(t.url(path))).status_code == 403


async def test_test_message_is_queued_rate_limited_and_delivered(t: Tenant) -> None:
    channel = await t.telegram_channel()
    first = await t.post(t.admin, f"/notification-channels/{channel['id']}/test")
    assert first.status_code == 202
    again = await t.post(t.admin, f"/notification-channels/{channel['id']}/test")
    assert again.status_code == 429
    assert t.telegram.sent == []  # the API never sends; the notifier does
    assert await t.dispatcher().run_once() == ["sent"]
    [(token, chat, body)] = t.telegram.sent
    assert (token, chat) == (BOT_TOKEN, CHAT_ID)
    assert "test notification" in body and "On-call chat" in body


# --- delivery from incident events --------------------------------------------------------------


async def test_outage_and_recovery_send_exactly_one_message_each(t: Tenant) -> None:
    await t.telegram_channel()
    await t.check("FAIL", "FAIL", "FAIL")
    [opened] = await t.outbox()
    assert (opened.event_type, opened.state) == ("INCIDENT_OPENED", "PENDING")
    assert opened.dedupe_key == f"{opened.incident_id}:INCIDENT_OPENED:{opened.channel_id}"
    assert await t.dispatcher().run_once() == ["sent"]
    text_ = t.telegram.sent[0][2]
    for expected in (
        "[CRITICAL]",
        "Payments API",
        "Host: api.acme.example",
        "HTTP_STATUS_MISMATCH",
        "Organization: Acme",
        f"/o/acme/incidents/{opened.incident_id}",
    ):
        assert expected in text_
    await t.check("FAIL", "PASS", "PASS")
    assert await t.dispatcher().run_once() == ["sent"]
    assert "[RESOLVED]" in t.telegram.sent[1][2] and "(estimated)" in t.telegram.sent[1][2]
    assert await t.dispatcher().run_once() == []
    for _, _, body in t.telegram.sent:
        assert SECRET_QUERY not in body and "?key" not in body and "/health" not in body


async def test_tls_warning_and_acknowledgement_events(t: Tenant) -> None:
    await t.telegram_channel()
    await t.check("PASS", tls_days=5)
    [warning] = await t.outbox()
    assert warning.event_type == "TLS_EXPIRY_WARNING"
    assert await t.dispatcher().run_once() == ["sent"]
    assert "Certificate expires in 5 days" in t.telegram.sent[0][2]
    acked = await t.post(t.member, f"/incidents/{warning.incident_id}/acknowledge")
    assert acked.status_code == 200
    comment = await t.post(t.member, f"/incidents/{warning.incident_id}/comments", {"text": "x"})
    assert comment.status_code == 201
    kinds = [o.event_type for o in await t.outbox()]
    assert kinds == ["TLS_EXPIRY_WARNING", "INCIDENT_ACKNOWLEDGED"]  # notes do not notify


async def test_duplicate_processing_and_overlapping_routes_enqueue_once(t: Tenant) -> None:
    channel = await t.telegram_channel()  # organization-wide route for all events
    route = await t.post(
        t.admin,
        "/notification-routes",
        {
            "channel_id": channel["id"],
            "monitor_id": str(t.monitor),
            "event_types": ["INCIDENT_OPENED"],
        },
    )
    assert route.status_code == 201
    await t.check("FAIL", "FAIL")
    t.clock.advance(seconds=60)
    job = await t.claim(t.monitor)
    results = await asyncio.gather(*(t.finish(job, "FAIL") for _ in range(50)))
    assert Counter(results) == Counter({"recorded": 1, "stale": 49})
    assert len(await t.outbox()) == 1
    await t.dispatcher().run_once()
    await t.dispatcher().run_once()
    assert len(t.telegram.sent) == 1


async def test_routes_filter_by_scope_and_event(t: Tenant) -> None:
    channel = await t.telegram_channel(route_all_events=False)
    other_project = await t.post(t.admin, "/projects", {"name": "Other"})
    await t.post(
        t.admin,
        "/notification-routes",
        {
            "channel_id": channel["id"],
            "project_id": other_project.json()["id"],
            "event_types": ["INCIDENT_OPENED"],
        },
    )
    await t.post(
        t.admin,
        "/notification-routes",
        {
            "channel_id": channel["id"],
            "project_id": str(t.project),
            "event_types": ["INCIDENT_RESOLVED"],
        },
    )
    await t.check("FAIL", "FAIL", "FAIL")
    assert await t.outbox() == []  # opened events are routed only for the other project
    await t.check("PASS", "PASS")
    assert [o.event_type for o in await t.outbox()] == ["INCIDENT_RESOLVED"]
    both = await t.post(
        t.admin,
        "/notification-routes",
        {
            "channel_id": channel["id"],
            "project_id": str(t.project),
            "monitor_id": str(t.monitor),
            "event_types": ["INCIDENT_OPENED"],
        },
    )
    assert both.json()["error"]["code"] == "INVALID_SCOPE"


async def test_retries_with_backoff_without_blocking_probes(t: Tenant) -> None:
    await t.telegram_channel()
    t.telegram.script = [SendResult("TELEGRAM_UNAVAILABLE", retryable=True)] * 2
    await t.check("FAIL", "FAIL", "FAIL")
    assert await t.dispatcher().run_once() == ["retry"]
    [item] = await t.outbox()
    first_delay = (item.next_attempt_at - clock.now()).total_seconds()
    assert (item.state, item.attempts, item.last_result_code) == (
        "PENDING",
        1,
        "TELEGRAM_UNAVAILABLE",
    )
    assert 30 <= first_delay <= 36
    assert await t.dispatcher().run_once() == []  # not due yet
    await t.check("FAIL")  # probing continues while Telegram is down (AC-006)
    t.clock.advance(seconds=first_delay + 1)
    assert await t.dispatcher().run_once() == ["retry"]
    [item] = await t.outbox()
    assert 60 <= (item.next_attempt_at - clock.now()).total_seconds() <= 72
    t.clock.advance(seconds=80)
    assert await t.dispatcher().run_once() == ["sent"]
    assert [d.result_code for d in await deliveries(t)] == [
        "TELEGRAM_UNAVAILABLE",
        "TELEGRAM_UNAVAILABLE",
        "SENT",
    ]


async def test_rate_limited_by_telegram_honours_retry_after(t: Tenant) -> None:
    await t.telegram_channel()
    t.telegram.script = [SendResult("TELEGRAM_RATE_LIMITED", retryable=True, retry_after=600)]
    await t.check("FAIL", "FAIL", "FAIL")
    assert await t.dispatcher().run_once() == ["retry"]
    [item] = await t.outbox()
    assert (item.next_attempt_at - clock.now()).total_seconds() >= 600


async def test_permanent_failure_stops_immediately(t: Tenant) -> None:
    await t.telegram_channel()
    t.telegram.script = [SendResult("TELEGRAM_UNAUTHORIZED")]
    await t.check("FAIL", "FAIL", "FAIL")
    assert await t.dispatcher().run_once() == ["failed"]
    [item] = await t.outbox()
    assert (item.state, item.attempts) == ("FAILED", 1)


async def test_attempts_are_bounded_at_eight(t: Tenant) -> None:
    await t.telegram_channel()
    t.telegram.script = [SendResult("TELEGRAM_TIMEOUT", retryable=True)] * 20
    await t.check("FAIL", "FAIL", "FAIL")
    for _ in range(12):
        await t.dispatcher().run_once()
        t.clock.advance(hours=2)
    [item] = await t.outbox()
    assert (item.state, item.attempts) == ("FAILED", 8)
    assert len(t.telegram.sent) == 8


async def test_email_retries_only_failed_recipients(t: Tenant) -> None:
    await t.email_channel(t.admin_id, t.member_id)
    t.mailer.failures["member@acme.test"] = [MailDeliveryError()]
    await t.check("FAIL", "FAIL", "FAIL")
    assert await t.dispatcher().run_once() == ["retry"]
    t.clock.advance(minutes=5)
    assert await t.dispatcher().run_once() == ["sent"]
    assert sorted(m.to for m in t.mailer.sent) == ["admin@acme.test", "member@acme.test"]
    assert [d.result_code for d in await deliveries(t)] == ["SENT", "MAIL_FAILED", "SENT"]
    body = t.mailer.sent[0].body
    assert "Payments API" in body and SECRET_QUERY not in body


async def test_email_permanent_rejection_fails(t: Tenant) -> None:
    await t.email_channel(t.admin_id)
    t.mailer.failures["admin@acme.test"] = [MailDeliveryError(permanent=True)]
    await t.check("FAIL", "FAIL", "FAIL")
    assert await t.dispatcher().run_once() == ["failed"]
    [item] = await t.outbox()
    assert item.last_result_code == "MAIL_REJECTED"


async def test_obsolete_outage_notice_is_not_sent_after_recovery(t: Tenant) -> None:
    await t.telegram_channel()
    await t.check("FAIL", "FAIL", "FAIL", "PASS", "PASS")  # notifier was down meanwhile
    results = await t.dispatcher().run_once()
    assert sorted(results) == ["cancelled", "sent"]
    states = {o.event_type: (o.state, o.cancel_reason) for o in await t.outbox()}
    assert states == {
        "INCIDENT_OPENED": ("CANCELLED", "SUPERSEDED"),
        "INCIDENT_RESOLVED": ("SENT", None),
    }
    assert len(t.telegram.sent) == 1 and "[RESOLVED]" in t.telegram.sent[0][2]


async def test_auto_pause_notice_goes_to_owners_and_admins_only(t: Tenant) -> None:
    await t.email_channel(t.admin_id, t.member_id)
    await t.check("BLOCKED", "BLOCKED", "BLOCKED")
    [item] = await t.outbox()
    assert item.event_type == "MONITOR_AUTO_PAUSED"
    assert await t.dispatcher().run_once() == ["sent"]
    assert [m.to for m in t.mailer.sent] == ["admin@acme.test"]
    assert "paused by policy" in t.mailer.sent[0].subject


async def test_auto_pause_notice_is_dropped_once_resumed(t: Tenant) -> None:
    await t.telegram_channel()
    await t.check("BLOCKED", "BLOCKED", "BLOCKED")
    assert (await t.post(t.admin, f"/monitors/{t.monitor}/resume")).status_code == 200
    assert await t.dispatcher().run_once() == ["cancelled"]
    assert t.telegram.sent == []


# --- revocation and suspension ------------------------------------------------------------------


async def test_suspension_cancels_pending_and_leased_items(t: Tenant) -> None:
    await t.telegram_channel()
    await t.check("FAIL", "FAIL", "FAIL")
    async with t.session() as s:
        await suspend_organization(s, actor_id=t.admin_id, org_id=t.org, reason="billing review")
    [item] = await t.outbox()
    assert (item.state, item.cancel_reason) == ("CANCELLED", "ORG_SUSPENDED")
    assert await t.dispatcher().run_once() == []
    async with t.session() as s:
        await activate_organization(s, actor_id=t.admin_id, org_id=t.org)
    # An item leased just before suspension is re-validated before sending.
    await t.check("FAIL", "FAIL", "FAIL", "PASS", "PASS")
    notifier = t.dispatcher()
    leases = await notifier.claim()
    async with t.session() as s:
        await suspend_organization(s, actor_id=t.admin_id, org_id=t.org, reason="again")
    assert [await notifier.deliver(lease) for lease in leases] == ["cancelled"] * len(leases)
    assert t.telegram.sent == []


async def test_disabled_channel_cancels_pending_items(t: Tenant) -> None:
    channel = await t.telegram_channel()
    await t.check("FAIL", "FAIL", "FAIL")
    disabled = await t.patch(
        t.admin, f"/notification-channels/{channel['id']}", {"version": 1, "enabled": False}
    )
    assert disabled.json()["enabled"] is False
    [item] = await t.outbox()
    assert item.cancel_reason == "CHANNEL_DISABLED"
    await t.check("PASS", "PASS")
    assert await t.outbox(state="PENDING") == []  # disabled channels are not routed
    assert await t.dispatcher().run_once() == []


async def test_former_members_stop_receiving_email(t: Tenant) -> None:
    await t.email_channel(t.member_id)
    await t.check("FAIL", "FAIL", "FAIL")
    removed = await t.admin.delete(t.url(f"/members/{t.member_id}"), headers=csrf(t.admin))
    assert removed.status_code in (200, 204)
    assert await t.dispatcher().run_once() == ["cancelled"]
    [item] = await t.outbox()
    assert item.cancel_reason == "NO_RECIPIENTS"
    assert t.mailer.sent == []
    listed = (await t.admin.get(t.url("/notification-channels"))).json()
    assert listed[0]["recipients"] == []


# --- worker concurrency and crash recovery ------------------------------------------------------


async def _queue_tests(t: Tenant, channel_id: str, count: int) -> None:
    async with t.session() as s:
        for i in range(count):
            await s.execute(
                text(
                    "INSERT INTO notification_outbox (id, organization_id, channel_id, event_type, "
                    "dedupe_key, state, attempts, next_attempt_at, created_at) VALUES "
                    "(:id, :org, :ch, 'CHANNEL_TEST', :key, 'PENDING', 0, :now, :now)"
                ),
                {
                    "id": uuid.uuid4(),
                    "org": t.org,
                    "ch": channel_id,
                    "key": f"t{i}",
                    "now": clock.now(),
                },
            )
        await s.commit()


async def test_concurrent_notifiers_never_send_an_item_twice(t: Tenant) -> None:
    channel = await t.telegram_channel()
    await _queue_tests(t, channel["id"], 15)
    notifiers = [t.dispatcher(batch=4) for _ in range(4)]
    for _ in range(4):
        await asyncio.gather(*(n.run_once() for n in notifiers))
    assert len(t.telegram.sent) == 15
    assert {o.state for o in await t.outbox()} == {"SENT"}


async def test_per_channel_rate_limit_defers_without_using_attempts(t: Tenant) -> None:
    channel = await t.telegram_channel()
    await _queue_tests(t, channel["id"], 25)
    results = await t.dispatcher(batch=50).run_once()
    assert Counter(results) == Counter({"sent": 20, "deferred": 5})
    deferred = await t.outbox(state="PENDING")
    assert {(o.attempts, o.last_result_code) for o in deferred} == {(0, "RATE_LIMITED_LOCAL")}
    t.clock.advance(seconds=61)
    assert Counter(await t.dispatcher(batch=50).run_once()) == Counter({"sent": 5})


async def test_crashed_notifier_lease_expires_and_is_reclaimed(t: Tenant) -> None:
    await t.telegram_channel()
    await t.check("FAIL", "FAIL", "FAIL")
    [crashed] = await t.dispatcher().claim()  # notifier dies before sending
    assert await t.dispatcher().claim() == []  # still leased
    t.clock.advance(seconds=dispatch_module.LEASE_SECONDS + 1)
    rescuer = t.dispatcher()
    [rescued] = await rescuer.claim()
    assert rescued.attempt == 2 and rescued.token != crashed.token
    assert await t.dispatcher().deliver(crashed) == "lost"  # stale lease cannot send
    assert await rescuer.deliver(rescued) == "sent"
    assert len(t.telegram.sent) == 1


async def test_lost_lease_after_send_keeps_history_but_not_state(t: Tenant) -> None:
    await t.telegram_channel()
    await t.check("FAIL", "FAIL", "FAIL")
    slow = t.dispatcher()
    [lease] = await slow.claim()
    plan = await slow._prepare(lease, clock.now())
    assert not isinstance(plan, str)
    t.clock.advance(seconds=dispatch_module.LEASE_SECONDS + 1)
    [reclaimed] = await t.dispatcher().claim()
    outcomes = await slow._send(plan)
    assert await slow._record(lease, outcomes, clock.now()) == "lost"
    [item] = await t.outbox()
    assert (item.state, item.lease_token) == ("LEASED", reclaimed.token)


# --- isolation and hygiene ----------------------------------------------------------------------


async def test_other_organizations_cannot_see_or_use_channels(t: Tenant) -> None:
    channel = await t.telegram_channel()
    cid = channel["id"]
    assert (await t.outsider.get(t.url("/notification-channels"))).status_code == 404
    other = f"/api/orgs/{t.other_org}"
    assert (await t.outsider.get(f"{other}/notification-channels")).json() == []
    patch = await t.outsider.patch(
        f"{other}/notification-channels/{cid}",
        json={"version": 1, "enabled": False},
        headers=csrf(t.outsider),
    )
    assert patch.status_code == 404
    test = await t.outsider.post(
        f"{other}/notification-channels/{cid}/test", headers=csrf(t.outsider)
    )
    assert test.status_code == 404
    route = await t.outsider.post(
        f"{other}/notification-routes",
        json={"channel_id": cid, "event_types": ["INCIDENT_OPENED"]},
        headers=csrf(t.outsider),
    )
    assert route.status_code == 404
    history = await t.outsider.get(f"{other}/notification-deliveries?channel_id={cid}")
    assert history.json() == []


async def test_database_rejects_cross_organization_links(t: Tenant) -> None:
    channel = await t.telegram_channel()
    async with t.session() as s:
        with pytest.raises(IntegrityError):  # outbox -> channel of another organization
            await s.execute(
                text(
                    "INSERT INTO notification_outbox (id, organization_id, channel_id, event_type, "
                    "dedupe_key, state, attempts, next_attempt_at, created_at) VALUES "
                    "(:id, :org, :ch, 'CHANNEL_TEST', 'x', 'PENDING', 0, now(), now())"
                ),
                {"id": uuid.uuid4(), "org": t.other_org, "ch": channel["id"]},
            )
        await s.rollback()
        with pytest.raises(IntegrityError):  # recipient who is not a member
            await s.execute(
                text(
                    "INSERT INTO notification_channel_recipient (organization_id, channel_id, "
                    "user_id) VALUES (:org, :ch, :u)"
                ),
                {"org": t.org, "ch": channel["id"], "u": t.outsider_id},
            )
        await s.rollback()
        with pytest.raises(IntegrityError):  # route -> monitor of another organization
            await s.execute(
                text(
                    "INSERT INTO notification_route (id, organization_id, channel_id, monitor_id, "
                    "event_types_json, enabled, created_at, version) VALUES "
                    "(:id, :org, :ch, :m, '[\"INCIDENT_OPENED\"]', true, now(), 1)"
                ),
                {"id": uuid.uuid4(), "org": t.other_org, "ch": channel["id"], "m": t.monitor},
            )
        await s.rollback()
        with pytest.raises(Exception, match="permission denied"):
            await s.execute(text("UPDATE notification_delivery SET result_code = 'SENT'"))
        await s.rollback()


async def test_copied_ciphertext_cannot_be_used_by_another_channel(t: Tenant) -> None:
    first = await t.telegram_channel()
    second = await t.telegram_channel(label="Second")
    async with t.session() as s:
        source = await s.get(NotificationChannel, uuid.UUID(first["id"]))
        assert source is not None
        await s.execute(
            update(NotificationChannel)
            .where(NotificationChannel.id == uuid.UUID(second["id"]))
            .values(config_ciphertext=source.config_ciphertext)
        )
        await s.commit()
    tested = await t.post(t.admin, f"/notification-channels/{second['id']}/test")
    assert tested.status_code == 202
    assert await t.dispatcher().run_once() == ["failed"]
    assert (await t.outbox())[0].last_result_code == "CONFIG_UNREADABLE"
    assert t.telegram.sent == []


async def test_delivery_history_has_result_codes_only(t: Tenant, db: AsyncSession) -> None:
    await t.email_channel(t.admin_id)
    t.mailer.failures["admin@acme.test"] = [MailDeliveryError()]
    await t.check("FAIL", "FAIL", "FAIL")
    await t.dispatcher().run_once()
    history = await t.member.get(t.url("/notification-deliveries"))
    [item] = history.json()
    assert item["state"] == "PENDING" and item["history"][0]["result_code"] == "MAIL_FAILED"
    for secret in ("admin@acme.test", SECRET_QUERY, "Payments API", "subject"):
        assert secret not in history.text
    count = await db.scalar(select(func.count()).select_from(NotificationOutbox))
    assert count == 1


async def test_audit_records_channel_changes_without_secrets(t: Tenant) -> None:
    channel = await t.telegram_channel()
    await t.patch(
        t.admin, f"/notification-channels/{channel['id']}", {"version": 1, "label": "Ops"}
    )
    async with t.session() as s:
        rows = list(
            await s.scalars(
                select(AuditEvent).where(AuditEvent.entity_id == uuid.UUID(channel["id"]))
            )
        )
    actions = sorted(a.action for a in rows)
    assert actions == ["org.notification_channel_created", "org.notification_channel_updated"]
    dumped: Any = json.dumps([a.safe_diff_json for a in rows])
    assert BOT_TOKEN not in dumped and CHAT_ID not in dumped


async def test_backoff_is_bounded() -> None:
    for attempt in range(1, 9):
        delay = dispatch_module.backoff_seconds(attempt)
        assert 30 * 2 ** (attempt - 1) <= delay or delay >= 3600
        assert delay <= 3600 * 1.2
    assert timedelta(seconds=dispatch_module.backoff_seconds(8)) <= timedelta(hours=1.2)
