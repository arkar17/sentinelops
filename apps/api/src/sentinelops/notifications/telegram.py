"""Telegram Bot API client (ADR-014): the only destination is the fixed api.telegram.org host.

The bot token is part of the request path, so neither URLs nor exception messages are ever
logged or returned; failures map to result codes only. No proxies, no redirects, plain-text
messages (no parse mode, so names cannot inject markup).
"""

import logging
from dataclasses import dataclass
from typing import Protocol, cast

import httpx

TELEGRAM_API = "https://api.telegram.org"
TIMEOUT_SECONDS = 10.0
MAX_RETRY_AFTER_SECONDS = 3600

# httpx logs request URLs at INFO; the URL contains the bot token.
logging.getLogger("httpx").setLevel(logging.WARNING)


@dataclass(frozen=True)
class SendResult:
    code: str
    ok: bool = False
    retryable: bool = False
    retry_after: int | None = None
    provider_ref: str | None = None


class TelegramClient(Protocol):
    async def send_message(self, bot_token: str, chat_id: str, text: str) -> SendResult: ...


def _field(mapping: object, key: str) -> object:
    return cast(dict[str, object], mapping).get(key) if isinstance(mapping, dict) else None


def classify(status: int, payload: object) -> SendResult:
    if status == 200 and _field(payload, "ok") is True:
        message_id = _field(_field(payload, "result"), "message_id")
        return SendResult("SENT", ok=True, provider_ref=str(message_id) if message_id else None)
    if status == 429:
        raw = _field(_field(payload, "parameters"), "retry_after")
        retry_after = min(raw, MAX_RETRY_AFTER_SECONDS) if isinstance(raw, int) else None
        return SendResult("TELEGRAM_RATE_LIMITED", retryable=True, retry_after=retry_after)
    if status in (401, 404):
        return SendResult("TELEGRAM_UNAUTHORIZED")  # invalid or revoked bot token
    if status == 403:
        return SendResult("TELEGRAM_FORBIDDEN")  # bot blocked or removed from the chat
    if status == 400:
        return SendResult("TELEGRAM_BAD_REQUEST")  # e.g. chat not found
    if status >= 500:
        return SendResult("TELEGRAM_UNAVAILABLE", retryable=True)
    return SendResult(f"TELEGRAM_HTTP_{status}", retryable=False)


class HttpTelegramClient:
    def __init__(self, transport: httpx.AsyncBaseTransport | None = None) -> None:
        self._transport = transport

    async def send_message(self, bot_token: str, chat_id: str, text: str) -> SendResult:
        try:
            async with httpx.AsyncClient(
                base_url=TELEGRAM_API,
                timeout=TIMEOUT_SECONDS,
                trust_env=False,
                follow_redirects=False,
                transport=self._transport,
            ) as client:
                response = await client.post(
                    f"/bot{bot_token}/sendMessage",
                    json={"chat_id": chat_id, "text": text, "disable_web_page_preview": True},
                )
        except httpx.TimeoutException:
            return SendResult("TELEGRAM_TIMEOUT", retryable=True)
        except httpx.HTTPError:
            return SendResult("TELEGRAM_NETWORK_ERROR", retryable=True)
        try:
            payload: object = response.json()
        except ValueError:
            payload = None
        return classify(response.status_code, payload)
