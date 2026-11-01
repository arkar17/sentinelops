"""HTTPX transport whose sockets connect only to a pre-validated IP address.

httpcore asks the network backend to connect to the URL's hostname; ``PinnedBackend`` refuses any
hostname other than the expected one and dials the validated IP instead. No DNS lookup happens
at connect time, so validation and connection cannot diverge (DNS rebinding). TLS still uses the
original hostname for SNI and certificate verification, and the Host header is unchanged.
There is deliberately no proxy support.
"""

import ssl
from collections.abc import AsyncIterator, Iterable
from typing import Any, cast

import httpcore
import httpx


class PinnedHostMismatchError(Exception):
    """httpcore asked to connect to a host other than the validated one (never expected)."""


class PinnedBackend(httpcore.AsyncNetworkBackend):
    def __init__(
        self, hostname: str, ip: str, inner: httpcore.AsyncNetworkBackend | None = None
    ) -> None:
        self._hostname = hostname
        self._ip = ip
        self._inner: httpcore.AsyncNetworkBackend = inner or cast(
            httpcore.AsyncNetworkBackend, httpcore.AnyIOBackend()
        )

    async def connect_tcp(
        self,
        host: str,
        port: int,
        timeout: float | None = None,  # noqa: ASYNC109  # httpcore backend signature
        local_address: str | None = None,
        socket_options: Iterable[httpcore.SOCKET_OPTION] | None = None,
    ) -> httpcore.AsyncNetworkStream:
        if host.lower().rstrip(".") != self._hostname:
            raise PinnedHostMismatchError
        return await self._inner.connect_tcp(self._ip, port, timeout=timeout)

    async def connect_unix_socket(
        self,
        path: str,
        timeout: float | None = None,  # noqa: ASYNC109  # httpcore backend signature
        socket_options: Iterable[httpcore.SOCKET_OPTION] | None = None,
    ) -> httpcore.AsyncNetworkStream:
        raise PinnedHostMismatchError

    async def sleep(self, seconds: float) -> None:
        await self._inner.sleep(seconds)


class _ResponseStream(httpx.AsyncByteStream):
    def __init__(self, stream: Iterable[bytes] | AsyncIterator[bytes] | object) -> None:
        self._stream = stream

    async def __aiter__(self) -> AsyncIterator[bytes]:
        async for chunk in self._stream:  # type: ignore[attr-defined]
            yield chunk

    async def aclose(self) -> None:
        close = getattr(self._stream, "aclose", None)
        if close is not None:
            await close()


class PinnedTransport(httpx.AsyncBaseTransport):
    """One-shot transport for a single probe attempt (no connection reuse across checks)."""

    def __init__(
        self,
        hostname: str,
        ip: str,
        ssl_context: ssl.SSLContext,
        inner_backend: httpcore.AsyncNetworkBackend | None = None,
    ) -> None:
        self._pool = httpcore.AsyncConnectionPool(
            ssl_context=ssl_context,
            max_connections=1,
            http1=True,
            http2=False,
            retries=0,
            network_backend=PinnedBackend(hostname, ip, inner_backend),
        )

    async def handle_async_request(self, request: httpx.Request) -> httpx.Response:
        if not isinstance(request.stream, httpx.AsyncByteStream):
            raise TypeError("PinnedTransport requires an async request stream")
        core_request = httpcore.Request(
            method=request.method,
            url=httpcore.URL(
                scheme=request.url.raw_scheme,
                host=request.url.raw_host,
                port=request.url.port,
                target=request.url.raw_path,
            ),
            headers=request.headers.raw,
            content=request.stream,
            extensions=request.extensions,
        )
        response = await self._pool.handle_async_request(core_request)
        extensions: dict[str, Any] = dict(response.extensions)  # pyright: ignore[reportUnknownMemberType, reportUnknownArgumentType]
        return httpx.Response(
            status_code=response.status,
            headers=response.headers,
            stream=_ResponseStream(response.stream),
            extensions=extensions,
        )

    async def aclose(self) -> None:
        await self._pool.aclose()
