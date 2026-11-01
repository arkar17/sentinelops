"""Executes one claimed job: load config, decrypt, probe, complete. Logs never contain URLs,
headers or response data, only identifiers and the result classification."""

import logging
from dataclasses import dataclass

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from sentinelops import clock
from sentinelops.catalog.models import Monitor
from sentinelops.catalog.monitors import decrypt_headers, decrypt_url
from sentinelops.platform.models import PlatformSettings
from sentinelops.probes.http.engine import (
    CheckOutcome,
    Failure,
    ProbeEnvironment,
    ProbeRequest,
    Result,
    run_check,
)
from sentinelops.scheduler.service import ClaimedJob, complete_job
from sentinelops.secrets.cipher import SecretBox, SecretDecryptError

logger = logging.getLogger("sentinelops.worker")


@dataclass
class JobRunner:
    sessionmaker: async_sessionmaker[AsyncSession]
    box: SecretBox
    environment: ProbeEnvironment

    async def _build_request(self, job: ClaimedJob) -> ProbeRequest | None:
        async with self.sessionmaker() as db:
            monitor = await db.scalar(
                select(Monitor).where(
                    Monitor.organization_id == job.organization_id, Monitor.id == job.monitor_id
                )
            )
            platform = await db.get(PlatformSettings, 1)
            if monitor is None or platform is None:
                return None
            url = decrypt_url(self.box, monitor)
            return ProbeRequest(
                url=url,
                hostname=monitor.hostname,
                port=443 if url.startswith("https://") else 80,
                method=monitor.method,
                timeout_ms=monitor.timeout_ms,
                retry_attempts=monitor.retry_attempts,
                expected_status=[(low, high) for low, high in monitor.expected_status_json],
                latency_threshold_ms=monitor.latency_threshold_ms,
                validation=monitor.validation_json,
                validation_max_bytes=platform.validation_max_bytes,
                headers=decrypt_headers(self.box, monitor),
            )

    async def run(self, job: ClaimedJob) -> str:
        observed_at = clock.now()
        try:
            request = await self._build_request(job)
        except SecretDecryptError:
            request = None
        if request is None:
            outcome = CheckOutcome(Result.INCONCLUSIVE, Failure.INTERNAL_ERROR)
        else:
            outcome = await run_check(request, self.environment)
        async with self.sessionmaker() as db:
            status = await complete_job(db, job, outcome, observed_at=observed_at, now=clock.now())
        logger.info(
            "check %s monitor=%s org=%s trigger=%s result=%s category=%s",
            status,
            job.monitor_id,
            job.organization_id,
            job.trigger,
            outcome.result,
            outcome.failure_category,
        )
        return status
