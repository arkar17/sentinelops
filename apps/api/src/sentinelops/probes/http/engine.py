"""HTTP/HTTPS check execution (FR-MON-004/006/007/011/012/013).

Each attempt resolves the hostname, rejects the target if ANY answer is forbidden, then connects
through PinnedTransport to a validated address. Results carry only non-sensitive metadata: no
URL, headers, body or resolved IP ever leaves this module.
"""

import asyncio
import ipaddress
import json
import re
import socket
import ssl
import time
from collections.abc import Awaitable, Callable, Sequence
from dataclasses import dataclass, field, replace
from datetime import UTC, datetime
from typing import Any, cast

import certifi
import httpcore
import httpx

from sentinelops import __version__
from sentinelops.probe_policy.addresses import IPAddress, is_forbidden
from sentinelops.probes.http.transport import PinnedHostMismatchError, PinnedTransport


class Result:
    PASS = "PASS"  # noqa: S105  # result name, not a credential
    SLOW = "SLOW"
    FAIL = "FAIL"
    BLOCKED = "BLOCKED"
    INCONCLUSIVE = "INCONCLUSIVE"

    CONCLUSIVE = frozenset({PASS, SLOW, FAIL})


class Failure:
    DNS_FAILURE = "DNS_FAILURE"
    DNS_TIMEOUT = "DNS_TIMEOUT"
    CONNECT_TIMEOUT = "CONNECT_TIMEOUT"
    CONNECT_ERROR = "CONNECT_ERROR"
    TLS_ERROR = "TLS_ERROR"
    READ_TIMEOUT = "READ_TIMEOUT"
    TIMEOUT = "TIMEOUT"
    HTTP_STATUS_MISMATCH = "HTTP_STATUS_MISMATCH"
    VALIDATION_FAILED = "VALIDATION_FAILED"
    RESPONSE_TOO_LARGE = "RESPONSE_TOO_LARGE"
    POLICY_BLOCKED = "POLICY_BLOCKED"
    INTERNAL_ERROR = "INTERNAL_ERROR"

    # FR-MON-011: only transient network failures are retried.
    RETRYABLE = frozenset({DNS_TIMEOUT, CONNECT_TIMEOUT, CONNECT_ERROR, READ_TIMEOUT, TIMEOUT})


USER_AGENT = f"SentinelOps-Monitor/{__version__} (+https://sentinelops.invalid/bot)"
RETRY_DELAY_SECONDS = 1.0

Resolver = Callable[[str, int], Awaitable[Sequence[str]]]


async def system_resolver(hostname: str, port: int) -> Sequence[str]:
    """All A/AAAA answers from the system resolver."""
    infos = await asyncio.get_running_loop().getaddrinfo(
        hostname, port, type=socket.SOCK_STREAM, proto=socket.IPPROTO_TCP
    )
    return [str(info[4][0]) for info in infos]


def default_ssl_context() -> ssl.SSLContext:
    context = ssl.create_default_context(cafile=certifi.where())
    context.check_hostname = True
    context.verify_mode = ssl.CERT_REQUIRED
    return context


@dataclass(frozen=True)
class ProbeRequest:
    url: str
    hostname: str
    port: int
    method: str  # GET or HEAD
    timeout_ms: int
    retry_attempts: int
    expected_status: Sequence[tuple[int, int]]
    latency_threshold_ms: int | None = None
    validation: dict[str, Any] | None = None
    validation_max_bytes: int = 65536
    headers: Sequence[tuple[str, str]] = field(default_factory=tuple[tuple[str, str], ...])


@dataclass(frozen=True)
class CheckOutcome:
    result: str
    failure_category: str | None = None
    http_status: int | None = None
    elapsed_ms: int | None = None
    attempt_count: int = 1
    tls_not_after: datetime | None = None


@dataclass(frozen=True)
class ProbeEnvironment:
    resolver: Resolver = system_resolver
    ssl_context_factory: Callable[[], ssl.SSLContext] = default_ssl_context
    allow_loopback: bool = False  # dev-fixtures policy only
    inner_backend: httpcore.AsyncNetworkBackend | None = None  # tests inject fakes here
    retry_delay_seconds: float = RETRY_DELAY_SECONDS


# --- response validation (GET only; no regular expressions over bodies) ---

_PATH_TOKEN = re.compile(r"\.([A-Za-z0-9_-]+)|\[(\d{1,6})\]")


def parse_json_path(path: str) -> list[str | int]:
    rest = path.strip()
    rest = rest.removeprefix("$")
    if rest and not rest.startswith((".", "[")):
        rest = "." + rest
    tokens: list[str | int] = []
    position = 0
    while position < len(rest):
        match = _PATH_TOKEN.match(rest, position)
        if match is None:
            raise ValueError("Use a path like $.status or $.items[0].state")
        tokens.append(match.group(1) if match.group(1) is not None else int(match.group(2)))
        position = match.end()
    if not tokens or len(tokens) > 32:
        raise ValueError("The JSON path must have 1-32 segments")
    return tokens


def _json_lookup(document: object, tokens: list[str | int]) -> tuple[bool, object]:
    current: object = document
    for token in tokens:
        if isinstance(token, int) and isinstance(current, list):
            items = cast(list[object], current)
            if token >= len(items):
                return False, None
            current = items[token]
        elif isinstance(token, str) and isinstance(current, dict):
            mapping = cast(dict[str, object], current)
            if token not in mapping:
                return False, None
            current = mapping[token]
        else:
            return False, None
    return True, current


def evaluate_validation(rule: dict[str, Any], body: bytes, truncated: bool) -> str | None:
    """Return a failure category, or None when the rule passes."""
    if rule["type"] == "substring":
        return None if rule["value"].encode() in body else Failure.VALIDATION_FAILED
    if truncated:
        return Failure.RESPONSE_TOO_LARGE  # a JSON document must be complete to be judged
    try:
        document = json.loads(body)
    except ValueError:
        return Failure.VALIDATION_FAILED
    found, value = _json_lookup(document, parse_json_path(rule["path"]))
    return None if found and value == rule["equals"] else Failure.VALIDATION_FAILED


# --- execution -----------------------------------------------------------------------------------


def _status_expected(status: int, expected: Sequence[tuple[int, int]]) -> bool:
    return any(low <= status <= high for low, high in expected)


def _classify_transport_error(exc: Exception) -> str:
    if isinstance(exc, httpx.ConnectTimeout | httpcore.ConnectTimeout):
        return Failure.CONNECT_TIMEOUT
    if isinstance(exc, httpx.ReadTimeout | httpx.WriteTimeout | httpcore.ReadTimeout):
        return Failure.READ_TIMEOUT
    cause: BaseException | None = exc
    while cause is not None:
        if isinstance(cause, ssl.SSLError | ssl.CertificateError):
            return Failure.TLS_ERROR
        cause = cause.__cause__ or cause.__context__
    if "SSL" in type(exc).__name__ or "CERTIFICATE_VERIFY_FAILED" in str(exc):
        return Failure.TLS_ERROR
    return Failure.CONNECT_ERROR


def _tls_not_after(response: httpx.Response) -> datetime | None:
    stream = response.extensions.get("network_stream")
    if stream is None:
        return None
    ssl_object = stream.get_extra_info("ssl_object")
    if ssl_object is None:
        return None
    certificate = ssl_object.getpeercert()
    not_after = certificate.get("notAfter") if certificate else None
    if not isinstance(not_after, str):
        return None
    return datetime.fromtimestamp(ssl.cert_time_to_seconds(not_after), UTC)


async def _resolve_and_validate(
    request: ProbeRequest, env: ProbeEnvironment, deadline: float
) -> tuple[str | None, CheckOutcome | None]:
    try:
        async with asyncio.timeout(max(deadline - time.monotonic(), 0.001)):
            answers = await env.resolver(request.hostname, request.port)
    except TimeoutError:
        return None, CheckOutcome(Result.FAIL, Failure.DNS_TIMEOUT)
    except socket.gaierror as exc:
        transient = exc.errno in (socket.EAI_AGAIN,)
        return None, CheckOutcome(
            Result.FAIL, Failure.DNS_TIMEOUT if transient else Failure.DNS_FAILURE
        )
    addresses: list[IPAddress] = []
    for answer in answers:
        try:
            addresses.append(ipaddress.ip_address(answer.split("%", 1)[0]))
        except ValueError:
            return None, CheckOutcome(Result.BLOCKED, Failure.POLICY_BLOCKED)
    if not addresses:
        return None, CheckOutcome(Result.FAIL, Failure.DNS_FAILURE)
    if any(is_forbidden(ip, allow_loopback=env.allow_loopback) for ip in addresses):
        return None, CheckOutcome(Result.BLOCKED, Failure.POLICY_BLOCKED)
    return str(addresses[0]), None


async def _attempt(request: ProbeRequest, env: ProbeEnvironment) -> CheckOutcome:
    started = time.monotonic()
    deadline = started + request.timeout_ms / 1000
    ip, blocked = await _resolve_and_validate(request, env, deadline)
    if blocked is not None or ip is None:
        return blocked or CheckOutcome(Result.INCONCLUSIVE, Failure.INTERNAL_ERROR)

    remaining = max(deadline - time.monotonic(), 0.001)
    transport = PinnedTransport(request.hostname, ip, env.ssl_context_factory(), env.inner_backend)
    headers = [*request.headers, ("User-Agent", USER_AGENT), ("Accept-Encoding", "identity")]
    try:
        async with (
            asyncio.timeout(remaining),
            httpx.AsyncClient(
                transport=transport,
                trust_env=False,  # never honor HTTP(S)_PROXY / netrc
                follow_redirects=False,
                timeout=httpx.Timeout(remaining),
            ) as client,
            client.stream(request.method, request.url, headers=headers) as response,
        ):
            elapsed_ms = int((time.monotonic() - started) * 1000)
            tls_not_after = _tls_not_after(response)
            status = response.status_code
            base = CheckOutcome(
                Result.PASS,
                http_status=status,
                elapsed_ms=elapsed_ms,
                tls_not_after=tls_not_after,
            )
            if not _status_expected(status, request.expected_status):
                return replace(
                    base, result=Result.FAIL, failure_category=Failure.HTTP_STATUS_MISMATCH
                )
            if request.validation is not None and request.method == "GET":
                body = bytearray()
                truncated = False
                async for chunk in response.aiter_raw():
                    body.extend(chunk)
                    if len(body) > request.validation_max_bytes:
                        truncated = True
                        del body[request.validation_max_bytes :]
                        break
                failure = evaluate_validation(request.validation, bytes(body), truncated)
                if failure is not None:
                    return replace(base, result=Result.FAIL, failure_category=failure)
            if (
                request.latency_threshold_ms is not None
                and elapsed_ms > request.latency_threshold_ms
            ):
                return replace(base, result=Result.SLOW)
            return base
    except TimeoutError:
        return CheckOutcome(Result.FAIL, Failure.TIMEOUT, elapsed_ms=request.timeout_ms)
    except PinnedHostMismatchError:
        return CheckOutcome(Result.INCONCLUSIVE, Failure.INTERNAL_ERROR)
    except (
        httpx.TransportError,
        httpcore.NetworkError,
        httpcore.TimeoutException,
        ssl.SSLError,
        OSError,  # raw socket errors (e.g. network unreachable) are connection failures
    ) as exc:
        return CheckOutcome(Result.FAIL, _classify_transport_error(exc))
    finally:
        await transport.aclose()


async def run_check(request: ProbeRequest, env: ProbeEnvironment | None = None) -> CheckOutcome:
    """Run one check with FR-MON-011 retries; never raises for target-side problems."""
    env = env or ProbeEnvironment()
    total = request.retry_attempts + 1
    outcome = CheckOutcome(Result.INCONCLUSIVE, Failure.INTERNAL_ERROR)
    for attempt in range(1, total + 1):
        try:
            outcome = await _attempt(request, env)
        except Exception:  # probe-side fault: never attribute it to the target
            return CheckOutcome(Result.INCONCLUSIVE, Failure.INTERNAL_ERROR, attempt_count=attempt)
        outcome = replace(outcome, attempt_count=attempt)
        if outcome.failure_category not in Failure.RETRYABLE or attempt == total:
            return outcome
        await asyncio.sleep(env.retry_delay_seconds)
    return outcome


def lease_seconds(timeout_ms: int, retry_attempts: int) -> float:
    """Worst-case duration of one check plus margin (02_TECHNICAL_ARCHITECTURE.md §5)."""
    return timeout_ms / 1000 * (retry_attempts + 1) + retry_attempts * RETRY_DELAY_SECONDS + 10
