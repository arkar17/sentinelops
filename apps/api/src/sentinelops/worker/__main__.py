"""Entrypoint: python -m sentinelops.worker

Claims due monitors, runs hardened probes and records measurements (G3). Stops gracefully on
SIGTERM/SIGINT: no new claims, running checks get a grace period, leases of the rest expire.
"""

import asyncio
import logging
import signal

from sentinelops.catalog.domains import dns_txt_lookup
from sentinelops.config import get_settings
from sentinelops.db.engine import create_engine
from sentinelops.db.session import create_sessionmaker
from sentinelops.log_config import configure_logging
from sentinelops.probes.http.engine import ProbeEnvironment
from sentinelops.scheduler.loop import Worker
from sentinelops.scheduler.runner import JobRunner
from sentinelops.secrets.cipher import SecretBox

logger = logging.getLogger("sentinelops.worker")


async def _main() -> None:
    settings = get_settings()
    engine = create_engine(settings)
    sessionmaker = create_sessionmaker(engine)
    environment = ProbeEnvironment(allow_loopback=settings.probe_policy == "dev-fixtures")
    worker = Worker(
        sessionmaker=sessionmaker,
        runner=JobRunner(sessionmaker, SecretBox.from_settings(settings), environment),
        settings=settings,
        txt_lookup=dns_txt_lookup,
    )
    stop = asyncio.Event()
    loop = asyncio.get_running_loop()
    for sig in (signal.SIGTERM, signal.SIGINT):
        loop.add_signal_handler(sig, stop.set)
    try:
        await worker.run_forever(stop)
    finally:
        await engine.dispose()


def main() -> int:
    configure_logging(get_settings().log_level)
    asyncio.run(_main())
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
