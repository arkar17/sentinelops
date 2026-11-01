"""FastAPI application factory."""

from collections.abc import AsyncGenerator
from contextlib import asynccontextmanager

from fastapi import FastAPI

from sentinelops import __version__
from sentinelops.api.health import router as health_router
from sentinelops.api.me import router as me_router
from sentinelops.api.middleware import RequestIdMiddleware
from sentinelops.api.origin import OriginCheckMiddleware
from sentinelops.catalog.domain_routes import router as domain_router
from sentinelops.catalog.domains import TxtLookup, dns_txt_lookup
from sentinelops.catalog.monitor_routes import router as monitor_router
from sentinelops.catalog.routes import router as project_router
from sentinelops.config import Settings, get_settings
from sentinelops.db.engine import create_engine
from sentinelops.db.session import create_sessionmaker
from sentinelops.errors import register_error_handlers
from sentinelops.identity.mfa import MfaCipher
from sentinelops.identity.mfa_routes import router as mfa_router
from sentinelops.identity.passwords import PasswordService
from sentinelops.identity.routes import router as auth_router
from sentinelops.incidents.routes import router as incident_router
from sentinelops.log_config import configure_logging
from sentinelops.mail import Mailer, SmtpMailer
from sentinelops.measurements.routes import router as report_router
from sentinelops.notifications.routes import router as notification_router
from sentinelops.platform.domain_routes import router as platform_domain_router
from sentinelops.platform.org_routes import router as platform_org_router
from sentinelops.platform.routes import public_router as platform_public_router
from sentinelops.platform.routes import router as platform_router
from sentinelops.realtime.hub import EventHub
from sentinelops.realtime.routes import SseSettings
from sentinelops.realtime.routes import router as realtime_router
from sentinelops.secrets.cipher import SecretBox
from sentinelops.status_pages.routes import PublicRateLimiter
from sentinelops.status_pages.routes import public_router as status_public_router
from sentinelops.status_pages.routes import router as status_page_router
from sentinelops.tenancy.routes import invitation_router as org_invitation_router
from sentinelops.tenancy.routes import router as org_router
from sentinelops.tenancy.routes import self_router


def create_app(
    settings: Settings | None = None,
    *,
    mailer: Mailer | None = None,
    txt_lookup: TxtLookup | None = None,
) -> FastAPI:
    settings = settings or get_settings()
    configure_logging(settings.log_level)

    @asynccontextmanager
    async def lifespan(app: FastAPI) -> AsyncGenerator[None]:
        app.state.db_engine = create_engine(settings)
        app.state.sessionmaker = create_sessionmaker(app.state.db_engine)
        try:
            yield
        finally:
            await app.state.event_hub.close()
            await app.state.db_engine.dispose()

    docs_enabled = not settings.is_production
    app = FastAPI(
        title="SentinelOps API",
        version=__version__,
        lifespan=lifespan,
        docs_url="/api/docs" if docs_enabled else None,
        redoc_url=None,
        openapi_url="/api/openapi.json" if docs_enabled else None,
    )
    app.state.settings = settings
    app.state.passwords = PasswordService(settings)
    app.state.mailer = mailer or SmtpMailer(settings)
    app.state.secret_box = SecretBox.from_settings(settings)
    app.state.mfa_cipher = MfaCipher.from_settings(settings)
    app.state.txt_lookup = txt_lookup or dns_txt_lookup
    app.state.public_rate_limiter = PublicRateLimiter()
    app.state.event_hub = EventHub(settings.database_url.get_secret_value())
    app.state.sse_settings = SseSettings()
    # Added last = outermost: request IDs exist before the origin check can reject.
    app.add_middleware(OriginCheckMiddleware, allowed_origins=settings.allowed_origins)
    app.add_middleware(RequestIdMiddleware)
    register_error_handlers(app)
    app.include_router(health_router)
    app.include_router(auth_router)
    app.include_router(mfa_router)
    app.include_router(me_router)
    app.include_router(platform_public_router)
    app.include_router(platform_router)
    app.include_router(platform_org_router)
    app.include_router(self_router)
    app.include_router(org_invitation_router)
    app.include_router(org_router)
    app.include_router(project_router)
    app.include_router(domain_router)
    app.include_router(monitor_router)
    app.include_router(incident_router)
    app.include_router(notification_router)
    app.include_router(report_router)
    app.include_router(realtime_router)
    app.include_router(status_page_router)
    app.include_router(status_public_router)
    app.include_router(platform_domain_router)
    return app
