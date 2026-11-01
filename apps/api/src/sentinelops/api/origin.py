"""Origin validation for state-changing API requests (CSRF defense in depth, incl. login CSRF).

POST/PUT/PATCH/DELETE under /api must carry an Origin (or, failing that, Referer) whose origin is
in settings.allowed_origins. Requests with neither header are rejected.
"""

from urllib.parse import urlsplit

from starlette.requests import Request
from starlette.types import ASGIApp, Receive, Scope, Send

from sentinelops.errors import error_response
from sentinelops.identity.dependencies import UNSAFE_METHODS


def _origin_of(url: str) -> str | None:
    parts = urlsplit(url)
    if not parts.scheme or not parts.netloc:
        return None
    return f"{parts.scheme}://{parts.netloc}".lower()


class OriginCheckMiddleware:
    def __init__(self, app: ASGIApp, allowed_origins: list[str]) -> None:
        self.app = app
        self.allowed = {origin.rstrip("/").lower() for origin in allowed_origins}

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if (
            scope["type"] != "http"
            or scope["method"] not in UNSAFE_METHODS
            or not scope["path"].startswith("/api/")
        ):
            await self.app(scope, receive, send)
            return
        request = Request(scope)
        origin = request.headers.get("origin")
        candidate = origin.lower() if origin and origin != "null" else None
        if candidate is None and (referer := request.headers.get("referer")):
            candidate = _origin_of(referer)
        if candidate in self.allowed:
            await self.app(scope, receive, send)
            return
        response = error_response(request, 403, "ORIGIN_REJECTED", "Request origin is not allowed")
        await response(scope, receive, send)
