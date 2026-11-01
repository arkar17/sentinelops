"""Telegram client, message rendering and channel validation without a database or network."""

import logging
from datetime import UTC, datetime, timedelta

import httpx
import pytest

from sentinelops.errors import AppError
from sentinelops.notifications.messages import MessageContext, render
from sentinelops.notifications.models import NotifyEvent
from sentinelops.notifications.service import TelegramInput, validate_telegram
from sentinelops.notifications.telegram import HttpTelegramClient, classify

TOKEN = "123456789:AAFakeTokenForTestsOnly_abcdefghijkl"  # noqa: S105  # fictional
OPENED = datetime(2026, 10, 31, 10, 0, tzinfo=UTC)


def client(handler: httpx.MockTransport) -> HttpTelegramClient:
    return HttpTelegramClient(transport=handler)


async def test_sends_to_the_fixed_bot_api_host_as_plain_text() -> None:
    seen: list[httpx.Request] = []

    def handle(request: httpx.Request) -> httpx.Response:
        seen.append(request)
        return httpx.Response(200, json={"ok": True, "result": {"message_id": 77}})

    result = await client(httpx.MockTransport(handle)).send_message(TOKEN, "-100123", "hi <b>")
    assert (result.ok, result.code, result.provider_ref) == (True, "SENT", "77")
    [request] = seen
    assert request.url.host == "api.telegram.org" and request.url.scheme == "https"
    assert request.url.path == f"/bot{TOKEN}/sendMessage"
    body = request.read().decode()
    assert '"parse_mode"' not in body and '"chat_id":"-100123"' in body.replace(" ", "")


@pytest.mark.parametrize(
    ("status", "payload", "code", "retryable"),
    [
        (429, {"ok": False, "parameters": {"retry_after": 42}}, "TELEGRAM_RATE_LIMITED", True),
        (401, {"ok": False}, "TELEGRAM_UNAUTHORIZED", False),
        (404, None, "TELEGRAM_UNAUTHORIZED", False),
        (403, {"ok": False}, "TELEGRAM_FORBIDDEN", False),
        (400, {"ok": False}, "TELEGRAM_BAD_REQUEST", False),
        (502, None, "TELEGRAM_UNAVAILABLE", True),
        (200, {"ok": False}, "TELEGRAM_HTTP_200", False),
    ],
)
def test_classification(status: int, payload: object, code: str, retryable: bool) -> None:
    result = classify(status, payload)
    assert (result.code, result.retryable, result.ok) == (code, retryable, False)
    if status == 429:
        assert result.retry_after == 42


def test_retry_after_is_capped() -> None:
    assert classify(429, {"parameters": {"retry_after": 10**9}}).retry_after == 3600


@pytest.mark.parametrize(
    ("error", "code"),
    [
        (httpx.ConnectTimeout("t"), "TELEGRAM_TIMEOUT"),
        (httpx.ConnectError("refused"), "TELEGRAM_NETWORK_ERROR"),
    ],
)
async def test_network_failures_are_retryable_and_never_leak_the_token(
    error: Exception, code: str, caplog: pytest.LogCaptureFixture
) -> None:
    def handle(request: httpx.Request) -> httpx.Response:
        raise error

    caplog.set_level(logging.DEBUG)
    result = await client(httpx.MockTransport(handle)).send_message(TOKEN, "1", "x")
    assert (result.code, result.retryable) == (code, True)
    assert TOKEN not in caplog.text and TOKEN.split(":")[1] not in repr(result)


async def test_request_logging_never_contains_the_token(caplog: pytest.LogCaptureFixture) -> None:
    caplog.set_level(logging.INFO)
    transport = httpx.MockTransport(lambda r: httpx.Response(200, json={"ok": True, "result": {}}))
    await client(transport).send_message(TOKEN, "1", "x")
    assert TOKEN not in caplog.text


@pytest.mark.parametrize(
    "data",
    [
        TelegramInput("nope", "123"),
        TelegramInput("123:short", "123"),
        TelegramInput(TOKEN, "https://example.test/hook"),
        TelegramInput(TOKEN, "@a"),
        TelegramInput(TOKEN + "/../x", "123"),
    ],
)
def test_telegram_validation_rejects_without_echo(data: TelegramInput) -> None:
    with pytest.raises(AppError) as info:
        validate_telegram(data)
    assert data.bot_token not in info.value.message and data.chat_id not in info.value.message


def test_telegram_validation_accepts_ids_and_usernames() -> None:
    assert validate_telegram(TelegramInput(f" {TOKEN} ", "-1001234")).bot_token == TOKEN
    assert validate_telegram(TelegramInput(TOKEN, "@acme_ops")).chat_id == "@acme_ops"


def _context(event: str, **kw: object) -> MessageContext:
    base: dict[str, object] = {
        "organization_name": "Acme",
        "link": "http://localhost:5173/o/acme/incidents/abc",
        "project_name": "Main",
        "monitor_name": "Payments API",
        "hostname": "api.acme.example",
        "incident_type": "OUTAGE",
        "severity": "CRITICAL",
        "opened_at": OPENED,
    }
    base.update(kw)
    return MessageContext(event, **base)  # type: ignore[arg-type]


def test_outage_message_contains_only_sanitized_fields() -> None:
    message = render(
        _context(NotifyEvent.INCIDENT_OPENED, failure_category="CONNECT_TIMEOUT", http_status=None)
    )
    assert message.subject == "[CRITICAL] Outage: Payments API"
    for expected in (
        "Organization: Acme",
        "Project: Main",
        "Host: api.acme.example",
        "Problem: CONNECT_TIMEOUT",
        "Opened: 2026-10-31 10:00 UTC",
        "Incident: http://localhost:5173/o/acme/incidents/abc",
    ):
        assert expected in message.text


def test_recovery_message_labels_outage_duration_as_estimate() -> None:
    message = render(
        _context(
            NotifyEvent.INCIDENT_RESOLVED,
            resolved_at=OPENED + timedelta(minutes=7),
            resolution="AUTO",
        )
    )
    assert (
        "resolved automatically" in message.text and "Duration (estimated): 7 min" in message.text
    )


def test_tls_and_auto_pause_and_test_messages() -> None:
    tls = render(
        _context(
            NotifyEvent.TLS_EXPIRY_WARNING,
            incident_type="TLS_EXPIRY",
            severity="WARNING",
            tls_days_remaining=6,
            tls_threshold_days=14,
        )
    )
    assert "[WARNING] TLS certificate expiry" in tls.subject and "expires in 6 days" in tls.text
    paused = render(_context(NotifyEvent.MONITOR_AUTO_PAUSED))
    assert paused.subject == "Monitor paused by policy: Payments API"
    test = render(MessageContext(NotifyEvent.CHANNEL_TEST, "Acme", "x", channel_label="Ops"))
    assert "Ops" in test.text and "Acme" in test.text
