"""Entrypoint: python -m sentinelops.notifier

Delivers notification outbox items (G5): email through the platform SMTP relay, Telegram through
the fixed Bot API host. Stops gracefully on SIGTERM/SIGINT: the batch in progress finishes (every
send has a timeout) and unfinished leases expire for reclaim.
"""

import asyncio
import logging
import signal

from sentinelops.config import get_settings
from sentinelops.db.engine import create_engine
from sentinelops.db.session import create_sessionmaker
from sentinelops.log_config import configure_logging
from sentinelops.mail import SmtpMailer
from sentinelops.notifications.dispatcher import Dispatcher
from sentinelops.notifications.telegram import HttpTelegramClient
from sentinelops.secrets.cipher import SecretBox

logger = logging.getLogger("sentinelops.notifier")


async def _main() -> None:
    settings = get_settings()
    engine = create_engine(settings)
    dispatcher = Dispatcher(
        sessionmaker=create_sessionmaker(engine),
        box=SecretBox.from_settings(settings),
        telegram=HttpTelegramClient(),
        mailer=SmtpMailer(settings),
        settings=settings,
    )
    stop = asyncio.Event()
    loop = asyncio.get_running_loop()
    for sig in (signal.SIGTERM, signal.SIGINT):
        loop.add_signal_handler(sig, stop.set)
    try:
        await dispatcher.run_forever(stop)
    finally:
        await engine.dispose()


def main() -> int:
    configure_logging(get_settings().log_level)
    asyncio.run(_main())
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
