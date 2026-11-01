"""In-process fan-out of LISTEN notifications to SSE subscribers, keyed by organization.

One dedicated asyncpg connection per API process LISTENs on the events channel. Each event is
delivered only to subscribers of the organization named in its payload. Subscriber queues are
bounded: on overflow, or when the listening connection drops and is re-established, subscribers
receive ``resync`` and refetch their snapshot (FR-UI-005: no guarantee of every event).
"""

import asyncio
import contextlib
import json
import logging
import uuid
from dataclasses import dataclass, field
from typing import Any, cast

import asyncpg  # pyright: ignore[reportMissingTypeStubs]

from sentinelops.realtime.publish import CHANNEL

logger = logging.getLogger("sentinelops.realtime")
QUEUE_SIZE = 256
RECONNECT_SECONDS = 2.0
_asyncpg = cast(Any, asyncpg)
_PG_ERROR: type[Exception] = _asyncpg.PostgresError


@dataclass(frozen=True)
class Event:
    name: str
    data: dict[str, Any]


RESYNC = Event("resync", {})


@dataclass(eq=False)
class Subscription:
    organization_id: uuid.UUID
    queue: asyncio.Queue[Event] = field(default_factory=lambda: asyncio.Queue(QUEUE_SIZE))

    def offer(self, event: Event) -> None:
        try:
            self.queue.put_nowait(event)
        except asyncio.QueueFull:
            while not self.queue.empty():  # drop the backlog; the client refetches instead
                self.queue.get_nowait()
            self.queue.put_nowait(RESYNC)


class EventHub:
    def __init__(self, dsn: str) -> None:
        self._dsn = dsn.replace("postgresql+asyncpg://", "postgresql://", 1)
        self._subscribers: dict[uuid.UUID, set[Subscription]] = {}
        self._connection: Any = None
        self._lock = asyncio.Lock()
        self._reconnect: asyncio.Task[None] | None = None
        self._closed = False

    async def subscribe(self, organization_id: uuid.UUID) -> Subscription:
        await self._ensure_listening()
        subscription = Subscription(organization_id)
        self._subscribers.setdefault(organization_id, set()).add(subscription)
        return subscription

    def unsubscribe(self, subscription: Subscription) -> None:
        subscribers = self._subscribers.get(subscription.organization_id)
        if subscribers is not None:
            subscribers.discard(subscription)
            if not subscribers:
                del self._subscribers[subscription.organization_id]

    def subscriber_count(self) -> int:
        return sum(len(s) for s in self._subscribers.values())

    async def _ensure_listening(self) -> None:
        async with self._lock:
            if self._connection is not None and not self._connection.is_closed():
                return
            connection: Any = await _asyncpg.connect(self._dsn)
            connection.add_termination_listener(self._on_terminated)
            await connection.add_listener(CHANNEL, self._on_notify)
            self._connection = connection

    def _on_notify(self, _conn: object, _pid: int, _channel: str, payload: str) -> None:
        try:
            message = json.loads(payload)
            organization_id = uuid.UUID(message["org"])
            event = Event(str(message["event"]), dict(message.get("data") or {}))
        except ValueError, KeyError, TypeError:
            logger.warning("ignored malformed realtime payload")
            return
        for subscription in list(self._subscribers.get(organization_id, ())):
            subscription.offer(event)

    def _broadcast(self, event: Event) -> None:
        for subscribers in list(self._subscribers.values()):
            for subscription in list(subscribers):
                subscription.offer(event)

    def _on_terminated(self, _conn: object) -> None:
        if self._closed:
            return
        logger.warning("realtime listener connection lost; reconnecting")
        self._connection = None
        if self._reconnect is None or self._reconnect.done():
            self._reconnect = asyncio.get_running_loop().create_task(self._reconnect_loop())

    async def _reconnect_loop(self) -> None:
        while not self._closed and self._subscribers:
            try:
                await self._ensure_listening()
            except OSError, asyncpg.PostgresError:
                await asyncio.sleep(RECONNECT_SECONDS)
                continue
            self._broadcast(RESYNC)  # events may have been missed while disconnected
            return

    async def close(self) -> None:
        self._closed = True
        if self._reconnect is not None:
            self._reconnect.cancel()
            with contextlib.suppress(asyncio.CancelledError):
                await self._reconnect
        if self._connection is not None and not self._connection.is_closed():
            await self._connection.close()
        self._connection = None
