"""Liveness and readiness endpoints (architecture §12)."""

import asyncio
import logging
from collections.abc import Awaitable, Callable
from typing import Annotated, Literal

from fastapi import APIRouter, Depends, Request
from pydantic import BaseModel

from sentinelops.db.engine import ping
from sentinelops.errors import AppError, ErrorResponse

logger = logging.getLogger(__name__)

router = APIRouter(tags=["health"])

DatabaseCheck = Callable[[], Awaitable[None]]


class LivenessResponse(BaseModel):
    status: Literal["ok"] = "ok"


class ReadinessResponse(BaseModel):
    status: Literal["ready"] = "ready"
    checks: dict[str, Literal["ok"]]


def get_database_check(request: Request) -> DatabaseCheck:
    engine = request.app.state.db_engine

    async def check() -> None:
        await ping(engine)

    return check


@router.get("/healthz", response_model=LivenessResponse)
async def healthz() -> LivenessResponse:
    """Process is up. Never touches dependencies."""
    return LivenessResponse()


@router.get(
    "/readyz",
    response_model=ReadinessResponse,
    responses={503: {"model": ErrorResponse}},
)
async def readyz(
    request: Request,
    check_database: Annotated[DatabaseCheck, Depends(get_database_check)],
) -> ReadinessResponse:
    """Process can serve traffic: the database answers within the readiness timeout."""
    timeout = request.app.state.settings.readiness_timeout_seconds
    try:
        async with asyncio.timeout(timeout):
            await check_database()
    except Exception as exc:
        # Log the type only: driver messages can include connection details.
        logger.warning("Readiness check failed: database (%s)", type(exc).__name__)
        raise AppError(503, "NOT_READY", "Service dependencies are not ready") from exc
    return ReadinessResponse(checks={"database": "ok"})
