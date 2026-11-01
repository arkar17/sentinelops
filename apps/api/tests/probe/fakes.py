"""In-memory network fakes: no sockets, no DNS, no real hosts."""

import asyncio
import socket
import ssl
from collections.abc import Iterable, Sequence
from dataclasses import dataclass, field
from typing import Any

import httpcore


@dataclass
class FakeServer:
    """Canned HTTP/1.1 response plus a record of every connection and request."""

    response: bytes = b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok"
    connect_delay: float = 0.0
    response_delay: float = 0.0
    connect_error: BaseException | None = None
    connections: list[tuple[str, int]] = field(default_factory=list[tuple[str, int]])
    requests: list[bytes] = field(default_factory=list[bytes])
    tls_server_names: list[str | None] = field(default_factory=list[str | None])


class FakeStream(httpcore.AsyncNetworkStream):
    def __init__(self, server: FakeServer) -> None:
        self._server = server
        self._buffer = b""
        self._sent = False

    async def read(self, max_bytes: int, timeout: float | None = None) -> bytes:  # noqa: ASYNC109
        if not self._sent:
            await asyncio.sleep(self._server.response_delay)
            self._buffer = self._server.response
            self._sent = True
        chunk, self._buffer = self._buffer[:max_bytes], self._buffer[max_bytes:]
        return chunk

    async def write(self, buffer: bytes, timeout: float | None = None) -> None:  # noqa: ASYNC109
        self._server.requests.append(buffer)

    async def aclose(self) -> None:
        return None

    async def start_tls(
        self,
        ssl_context: ssl.SSLContext,
        server_hostname: str | None = None,
        timeout: float | None = None,  # noqa: ASYNC109
    ) -> httpcore.AsyncNetworkStream:
        self._server.tls_server_names.append(server_hostname)
        return self

    def get_extra_info(self, info: str) -> Any:
        return None


class FakeBackend(httpcore.AsyncNetworkBackend):
    def __init__(self, server: FakeServer) -> None:
        self.server = server

    async def connect_tcp(
        self,
        host: str,
        port: int,
        timeout: float | None = None,  # noqa: ASYNC109
        local_address: str | None = None,
        socket_options: Iterable[httpcore.SOCKET_OPTION] | None = None,
    ) -> httpcore.AsyncNetworkStream:
        self.server.connections.append((host, port))
        if self.server.connect_error is not None:
            raise self.server.connect_error
        await asyncio.sleep(self.server.connect_delay)
        return FakeStream(self.server)

    async def sleep(self, seconds: float) -> None:
        await asyncio.sleep(seconds)


class FakeResolver:
    """Returns successive answer lists (to simulate DNS rebinding) or raises."""

    def __init__(self, *answers: Sequence[str] | BaseException) -> None:
        self._answers = list(answers)
        self.calls: list[str] = []

    async def __call__(self, hostname: str, port: int) -> Sequence[str]:
        self.calls.append(hostname)
        answer = self._answers[min(len(self.calls), len(self._answers)) - 1]
        if isinstance(answer, BaseException):
            raise answer
        return answer


def nxdomain() -> socket.gaierror:
    return socket.gaierror(socket.EAI_NONAME, "Name or service not known")


def dns_again() -> socket.gaierror:
    return socket.gaierror(socket.EAI_AGAIN, "Temporary failure in name resolution")
