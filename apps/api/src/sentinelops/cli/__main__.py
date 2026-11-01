"""Entrypoint: sentinelops (or python -m sentinelops.cli).

Commands:
  bootstrap-system-admin --email ADDRESS            create the first SYSTEM_ADMIN (once)
  bootstrap-system-admin --email ADDRESS --recover  re-issue activation for a SYSTEM_ADMIN
  reset-admin-mfa --email ADDRESS                   remove a SYSTEM_ADMIN's MFA (lost device)
  seed-demo --confirm                               fictional demo data (empty *_demo DB only)

The activation URL is written only to this terminal's stdout, never to logs (FR-PLT-001).
Every command requires shell access to the deployment and is audited.
"""

import argparse
import asyncio
import sys
from collections.abc import Sequence

from sentinelops import __version__
from sentinelops.cli.demo import DemoAccounts, seed_demo
from sentinelops.config import get_settings
from sentinelops.db.engine import create_engine
from sentinelops.db.session import create_sessionmaker
from sentinelops.errors import AppError
from sentinelops.identity.mfa_service import operator_reset
from sentinelops.identity.passwords import PasswordService
from sentinelops.log_config import configure_logging
from sentinelops.platform.service import (
    BootstrapRefusedError,
    bootstrap_system_admin,
    recover_system_admin,
)
from sentinelops.secrets.cipher import SecretBox


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="sentinelops", description="SentinelOps operator CLI")
    parser.add_argument("--version", action="version", version=f"sentinelops {__version__}")
    commands = parser.add_subparsers(title="commands", dest="command")
    bootstrap = commands.add_parser(
        "bootstrap-system-admin",
        help="create the first SYSTEM_ADMIN (refuses if one exists)",
    )
    bootstrap.add_argument("--email", required=True, help="the platform owner's email address")
    bootstrap.add_argument(
        "--recover",
        action="store_true",
        help="reset an existing SYSTEM_ADMIN and issue a new activation link",
    )
    reset = commands.add_parser(
        "reset-admin-mfa",
        help="remove a SYSTEM_ADMIN's MFA and revoke their sessions (lost authenticator)",
    )
    reset.add_argument("--email", required=True, help="the administrator's email address")
    demo = commands.add_parser(
        "seed-demo",
        help="write fictional demo data to an empty database named *_demo (prints passwords once)",
    )
    demo.add_argument(
        "--confirm", action="store_true", help="required: confirm this database is for demos"
    )
    return parser


async def _run_seed_demo() -> DemoAccounts:
    settings = get_settings()
    engine = create_engine(settings)
    try:
        async with create_sessionmaker(engine)() as db:
            return await seed_demo(
                db, settings, PasswordService(settings), SecretBox.from_settings(settings)
            )
    finally:
        await engine.dispose()


async def _run_reset_mfa(email: str) -> None:
    settings = get_settings()
    engine = create_engine(settings)
    try:
        async with create_sessionmaker(engine)() as db:
            await operator_reset(db, email=email)
    finally:
        await engine.dispose()


async def _run_bootstrap(email: str, recover: bool) -> str:
    settings = get_settings()
    engine = create_engine(settings)
    try:
        async with create_sessionmaker(engine)() as db:
            if recover:
                return await recover_system_admin(db, settings, email=email)
            return await bootstrap_system_admin(db, settings, email=email)
    finally:
        await engine.dispose()


def main(argv: Sequence[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    if args.command is None:
        parser.print_help()
        return 0
    configure_logging(get_settings().log_level)
    if args.command == "seed-demo":
        if not args.confirm:
            sys.stderr.write("Refused: pass --confirm to write fictional demo data.\n")
            return 1
        try:
            accounts = asyncio.run(_run_seed_demo())
        except AppError as exc:
            sys.stderr.write(f"Refused: {exc.message}\n")
            return 1
        sys.stdout.write("Fictional demo data created. Passwords are shown only here:\n\n")
        for email, role, password in accounts.credentials:
            sys.stdout.write(f"  {role:<12} {email:<34} {password}\n")
        sys.stdout.write("\nPublic status page: /status/northwind-status\n")
        return 0
    if args.command == "reset-admin-mfa":
        try:
            asyncio.run(_run_reset_mfa(args.email))
        except AppError as exc:
            sys.stderr.write(f"Refused: {exc.message}\n")
            return 1
        sys.stdout.write(
            "MFA removed and all sessions revoked. The administrator must sign in again"
            " and, where MFA is required, enrol a new authenticator.\n"
        )
        return 0
    try:
        url = asyncio.run(_run_bootstrap(args.email, args.recover))
    except BootstrapRefusedError as exc:
        sys.stderr.write(f"Refused: {exc}\n")
        return 1
    sys.stdout.write(
        "SYSTEM_ADMIN account is pending activation.\n"
        "Open this single-use link within 30 minutes to set the password:\n\n"
        f"  {url}\n\n"
        "This link is shown only here. Do not share or store it.\n"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
