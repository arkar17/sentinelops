"""Worker loop: claim within capacity, run checks concurrently, sleep until work is due.

No busy polling: the loop waits until the earliest due time (capped by worker_idle_seconds, which
bounds check-now latency) or until a running check frees a slot. On shutdown it stops claiming,
waits up to the grace period for running checks and lets unfinished leases expire for reclaim.
"""

import asyncio
import contextlib
import logging
import uuid
from collections import Counter
from dataclasses import dataclass, field
from datetime import datetime, timedelta

from sqlalchemy import func, select
from sqlalchemy.dialects.postgresql import insert
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from sentinelops import __version__, clock
from sentinelops.catalog.domains import TxtLookup, renew_and_expire
from sentinelops.config import Settings
from sentinelops.incidents.engine import mark_stale
from sentinelops.measurements.rollups import apply_retention, rollup_recent
from sentinelops.scheduler.models import WorkerHeartbeat
from sentinelops.scheduler.runner import JobRunner
from sentinelops.scheduler.service import Capacity, ClaimedJob, claim_jobs, earliest_due
from sentinelops.status_pages.service import refresh_published

logger = logging.getLogger("sentinelops.worker")

DOMAIN_MAINTENANCE_LOCK = 0x534E5444  # advisory lock id for domain renewal
DOMAIN_MAINTENANCE_EVERY = timedelta(minutes=10)
STALENESS_LOCK = 0x534E5453  # advisory lock id for staleness and status snapshots
STALENESS_EVERY = timedelta(seconds=60)
ROLLUP_LOCK = 0x534E5452  # advisory lock id for rollups and retention
ROLLUP_EVERY = timedelta(minutes=5)
HEARTBEAT_EVERY = timedelta(seconds=30)
MIN_WAIT_SECONDS = 0.05


@dataclass
class Worker:
    sessionmaker: async_sessionmaker[AsyncSession]
    runner: JobRunner
    settings: Settings
    txt_lookup: TxtLookup
    worker_id: str = field(default_factory=lambda: f"worker-{uuid.uuid4().hex[:12]}")
    _tasks: set[asyncio.Task[str]] = field(default_factory=set[asyncio.Task[str]])
    _by_org: Counter[uuid.UUID] = field(default_factory=Counter[uuid.UUID])
    _by_host: Counter[str] = field(default_factory=Counter[str])
    _slot_freed: asyncio.Event = field(default_factory=asyncio.Event)
    _last_heartbeat: datetime | None = None
    _last_domain_maintenance: datetime | None = None
    _last_staleness: datetime | None = None
    _last_rollup: datetime | None = None

    @property
    def in_flight(self) -> int:
        return len(self._tasks)

    async def claim_and_start(self) -> list[ClaimedJob]:
        capacity = Capacity(
            slots=self.settings.worker_concurrency - len(self._tasks),
            org_cap=self.settings.worker_org_concurrency,
            host_cap=self.settings.worker_host_concurrency,
            by_org=self._by_org,
            by_host=self._by_host,
        )
        if capacity.slots <= 0:
            return []
        async with self.sessionmaker() as db:
            jobs = await claim_jobs(
                db,
                worker_id=self.worker_id,
                capacity=capacity,
                now=clock.now(),
                batch=min(self.settings.worker_batch_size, capacity.slots * 3),
            )
        for job in jobs:
            task = asyncio.create_task(self._run(job), name=f"check-{job.monitor_id}")
            self._tasks.add(task)
        return jobs

    async def _run(self, job: ClaimedJob) -> str:
        try:
            return await self.runner.run(job)
        except Exception:
            logger.exception(
                "check crashed monitor=%s; lease will expire for reclaim", job.monitor_id
            )
            return "crashed"
        finally:
            self._by_org[job.organization_id] -= 1
            self._by_host[job.hostname] -= 1
            current = asyncio.current_task()
            if current is not None:
                self._tasks.discard(current)  # pyright: ignore[reportArgumentType]
            self._slot_freed.set()

    async def drain(self, timeout: float | None = None) -> None:  # noqa: ASYNC109
        if self._tasks:
            await asyncio.wait(set(self._tasks), timeout=timeout)

    async def _seconds_until_due(self) -> float:
        async with self.sessionmaker() as db:
            due = await earliest_due(db)
        idle = self.settings.worker_idle_seconds
        if due is None:
            return idle
        return min(max((due - clock.now()).total_seconds(), MIN_WAIT_SECONDS), idle)

    async def maintenance(self) -> None:
        now = clock.now()
        if self._last_heartbeat is None or now - self._last_heartbeat >= HEARTBEAT_EVERY:
            async with self.sessionmaker() as db:
                await db.execute(
                    insert(WorkerHeartbeat)
                    .values(
                        worker_id=self.worker_id,
                        kind="WORKER",
                        last_seen_at=now,
                        in_flight=len(self._tasks),
                        version_label=__version__,
                    )
                    .on_conflict_do_update(
                        index_elements=["worker_id"],
                        set_={"last_seen_at": now, "in_flight": len(self._tasks)},
                    )
                )
                await db.commit()
            self._last_heartbeat = now
        if (
            self._last_domain_maintenance is None
            or now - self._last_domain_maintenance >= DOMAIN_MAINTENANCE_EVERY
        ):
            self._last_domain_maintenance = now
            async with self.sessionmaker() as db:
                locked = await db.scalar(
                    select(func.pg_try_advisory_xact_lock(DOMAIN_MAINTENANCE_LOCK))
                )
                if locked:
                    renewed, expired = await renew_and_expire(db, self.txt_lookup)
                    if renewed or expired:
                        logger.info("domains renewed=%s expired=%s", renewed, expired)
                else:
                    await db.rollback()
        if self._last_staleness is None or now - self._last_staleness >= STALENESS_EVERY:
            self._last_staleness = now
            async with self.sessionmaker() as db:
                if await db.scalar(select(func.pg_try_advisory_xact_lock(STALENESS_LOCK))):
                    stale = await mark_stale(db, now)
                    pages = await refresh_published(db, now)  # status page snapshots
                    await db.commit()
                    if stale:
                        logger.info("health marked stale monitors=%s", stale)
                    if pages:
                        logger.debug("status page snapshots refreshed pages=%s", pages)
                else:
                    await db.rollback()
        if self._last_rollup is None or now - self._last_rollup >= ROLLUP_EVERY:
            self._last_rollup = now
            await self.rollups(now)

    async def rollups(self, now: datetime) -> None:
        """Hourly rollups and retention, one worker at a time (advisory lock)."""
        async with self.sessionmaker() as db:
            if not await db.scalar(select(func.pg_try_advisory_xact_lock(ROLLUP_LOCK))):
                await db.rollback()
                return
            rolled = await rollup_recent(db, now)
            deleted = await apply_retention(db, now)
            await db.commit()
            if deleted:
                logger.info(
                    "retention deleted raw measurements=%s rollups_updated=%s", deleted, rolled
                )

    async def run_forever(self, stop: asyncio.Event) -> None:
        logger.info(
            "worker %s started (concurrency=%s)", self.worker_id, self.settings.worker_concurrency
        )
        while not stop.is_set():
            try:
                await self.claim_and_start()
                await self.maintenance()
                wait = await self._seconds_until_due()
            except Exception:
                logger.exception("worker iteration failed; backing off")
                wait = self.settings.worker_idle_seconds
            self._slot_freed.clear()
            stop_wait = asyncio.create_task(stop.wait())
            slot_wait = asyncio.create_task(self._slot_freed.wait())
            await asyncio.wait(
                {stop_wait, slot_wait}, timeout=wait, return_when=asyncio.FIRST_COMPLETED
            )
            for pending in (stop_wait, slot_wait):
                pending.cancel()
                with contextlib.suppress(asyncio.CancelledError):
                    await pending
        logger.info(
            "worker %s stopping; waiting for %s running checks", self.worker_id, len(self._tasks)
        )
        await self.drain(self.settings.worker_shutdown_grace_seconds)
        for task in list(self._tasks):
            task.cancel()
        logger.info("worker %s stopped", self.worker_id)
