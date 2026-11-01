"""Probe engine against in-memory fakes: pinning, rebinding, redirects, proxies, results."""

import asyncio

import httpcore
import pytest

from sentinelops.probes.http.engine import (
    Failure,
    ProbeEnvironment,
    ProbeRequest,
    Result,
    evaluate_validation,
    parse_json_path,
    run_check,
)
from tests.probe.fakes import FakeBackend, FakeResolver, FakeServer, dns_again, nxdomain

PUBLIC = "93.184.216.34"
OK = (("200-299", (200, 299)),)


def request(**overrides: object) -> ProbeRequest:
    base: dict[str, object] = {
        "url": "https://api.example.com/health?key=s3cr3t",
        "hostname": "api.example.com",
        "port": 443,
        "method": "GET",
        "timeout_ms": 2000,
        "retry_attempts": 0,
        "expected_status": [(200, 299)],
    }
    base.update(overrides)
    return ProbeRequest(**base)  # type: ignore[arg-type]


def env(server: FakeServer, resolver: FakeResolver) -> ProbeEnvironment:
    return ProbeEnvironment(
        resolver=resolver, inner_backend=FakeBackend(server), retry_delay_seconds=0
    )


async def test_pass_connects_only_to_validated_ip_with_host_and_sni() -> None:
    server, resolver = FakeServer(), FakeResolver([PUBLIC])
    outcome = await run_check(request(), env(server, resolver))
    assert outcome.result == Result.PASS
    assert outcome.http_status == 200
    assert server.connections == [(PUBLIC, 443)]  # pinned IP dialed, never the hostname
    assert server.tls_server_names == ["api.example.com"]  # SNI keeps the hostname
    sent = server.requests[0].decode()
    assert sent.startswith("GET /health?key=s3cr3t HTTP/1.1\r\n")
    assert "Host: api.example.com\r\n" in sent
    assert "User-Agent: SentinelOps-Monitor/" in sent
    assert "Accept-Encoding: identity" in sent


@pytest.mark.parametrize(
    "answers",
    [
        ["10.0.0.5"],
        [PUBLIC, "10.0.0.5"],
        ["169.254.169.254"],
        ["::ffff:127.0.0.1"],
        ["fd00:ec2::254"],
    ],
)
async def test_forbidden_answers_block_before_connecting(answers: list[str]) -> None:
    server = FakeServer()
    outcome = await run_check(request(), env(server, FakeResolver(answers)))
    assert outcome.result == Result.BLOCKED
    assert outcome.failure_category == Failure.POLICY_BLOCKED
    assert server.connections == []


async def test_dns_rebinding_between_checks_is_blocked() -> None:
    server, resolver = FakeServer(), FakeResolver([PUBLIC], ["127.0.0.1"])
    first = await run_check(request(), env(server, resolver))
    second = await run_check(request(), env(server, resolver))
    assert (first.result, second.result) == (Result.PASS, Result.BLOCKED)
    assert server.connections == [(PUBLIC, 443)]


async def test_every_retry_re_resolves_and_revalidates() -> None:
    server = FakeServer(connect_error=httpcore.ConnectError("refused"))
    resolver = FakeResolver([PUBLIC], [PUBLIC], ["10.0.0.1"])
    outcome = await run_check(request(retry_attempts=2), env(server, resolver))
    assert len(resolver.calls) == 3
    assert outcome.result == Result.BLOCKED  # rebinding on the last retry is still caught
    assert outcome.attempt_count == 3
    assert server.connections == [(PUBLIC, 443), (PUBLIC, 443)]


async def test_redirects_are_never_followed() -> None:
    server = FakeServer(
        response=b"HTTP/1.1 302 Found\r\nLocation: http://169.254.169.254/latest/\r\n"
        b"Content-Length: 0\r\n\r\n"
    )
    outcome = await run_check(request(), env(server, FakeResolver([PUBLIC])))
    assert outcome.result == Result.FAIL
    assert outcome.failure_category == Failure.HTTP_STATUS_MISMATCH
    assert outcome.http_status == 302
    assert len(server.connections) == 1
    accepted = await run_check(
        request(expected_status=[(300, 399)]), env(server, FakeResolver([PUBLIC]))
    )
    assert accepted.result == Result.PASS


async def test_proxy_environment_is_ignored(monkeypatch: pytest.MonkeyPatch) -> None:
    for name in ("HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "http_proxy", "https_proxy"):
        monkeypatch.setenv(name, "http://10.9.9.9:3128")
    server = FakeServer()
    outcome = await run_check(request(), env(server, FakeResolver([PUBLIC])))
    assert outcome.result == Result.PASS
    assert server.connections == [(PUBLIC, 443)]


async def test_status_mismatch_and_slow() -> None:
    bad = FakeServer(response=b"HTTP/1.1 503 Service Unavailable\r\nContent-Length: 0\r\n\r\n")
    outcome = await run_check(request(), env(bad, FakeResolver([PUBLIC])))
    assert (outcome.result, outcome.failure_category, outcome.http_status) == (
        Result.FAIL,
        Failure.HTTP_STATUS_MISMATCH,
        503,
    )
    slow = FakeServer(response_delay=0.05)
    outcome = await run_check(request(latency_threshold_ms=10), env(slow, FakeResolver([PUBLIC])))
    assert outcome.result == Result.SLOW
    assert outcome.elapsed_ms is not None and outcome.elapsed_ms >= 50


async def test_timeouts_are_retried_then_fail() -> None:
    server = FakeServer(connect_delay=1.0)
    outcome = await run_check(
        request(timeout_ms=100, retry_attempts=1), env(server, FakeResolver([PUBLIC]))
    )
    assert outcome.result == Result.FAIL
    assert outcome.failure_category in (Failure.TIMEOUT, Failure.CONNECT_TIMEOUT)
    assert outcome.attempt_count == 2


async def test_response_delay_beyond_timeout_fails() -> None:
    server = FakeServer(response_delay=1.0)
    outcome = await run_check(request(timeout_ms=100), env(server, FakeResolver([PUBLIC])))
    assert outcome.result == Result.FAIL
    assert outcome.failure_category in (Failure.TIMEOUT, Failure.READ_TIMEOUT)


async def test_dns_failures() -> None:
    server = FakeServer()
    missing = await run_check(request(retry_attempts=2), env(server, FakeResolver(nxdomain())))
    assert (missing.result, missing.failure_category, missing.attempt_count) == (
        Result.FAIL,
        Failure.DNS_FAILURE,
        1,
    )
    flaky = await run_check(
        request(retry_attempts=1), env(server, FakeResolver(dns_again(), [PUBLIC]))
    )
    assert flaky.result == Result.PASS
    assert flaky.attempt_count == 2
    empty = await run_check(request(), env(server, FakeResolver([])))
    assert empty.failure_category == Failure.DNS_FAILURE


async def test_slow_dns_counts_against_the_deadline() -> None:
    async def hang(hostname: str, port: int) -> list[str]:
        await asyncio.sleep(5)
        return [PUBLIC]

    outcome = await run_check(
        request(timeout_ms=100),
        ProbeEnvironment(resolver=hang, inner_backend=FakeBackend(FakeServer())),
    )
    assert outcome.failure_category == Failure.DNS_TIMEOUT


async def test_probe_side_fault_is_inconclusive() -> None:
    server = FakeServer(connect_error=RuntimeError("worker bug"))
    outcome = await run_check(request(), env(server, FakeResolver([PUBLIC])))
    assert (outcome.result, outcome.failure_category) == (
        Result.INCONCLUSIVE,
        Failure.INTERNAL_ERROR,
    )


async def test_custom_headers_are_sent_but_never_returned() -> None:
    server = FakeServer()
    outcome = await run_check(
        request(headers=[("Authorization", "Bearer top-secret")]),
        env(server, FakeResolver([PUBLIC])),
    )
    assert "Authorization: Bearer top-secret" in server.requests[0].decode()
    assert "top-secret" not in repr(outcome)
    assert "s3cr3t" not in repr(outcome)


async def test_validation_body_rules() -> None:
    body = b'{"status": "ok", "items": [{"state": "green"}]}'
    server = FakeServer(
        response=b"HTTP/1.1 200 OK\r\nContent-Length: %d\r\n\r\n%s" % (len(body), body)
    )
    for rule, expected in [
        ({"type": "substring", "value": '"ok"'}, Result.PASS),
        ({"type": "substring", "value": "degraded"}, Result.FAIL),
        ({"type": "json_path", "path": "$.items[0].state", "equals": "green"}, Result.PASS),
        ({"type": "json_path", "path": "$.status", "equals": "down"}, Result.FAIL),
        ({"type": "json_path", "path": "$.missing", "equals": None}, Result.FAIL),
    ]:
        outcome = await run_check(request(validation=rule), env(server, FakeResolver([PUBLIC])))
        assert outcome.result == expected, rule
    head = await run_check(
        request(method="HEAD", validation={"type": "substring", "value": "x"}),
        env(server, FakeResolver([PUBLIC])),
    )
    assert head.result == Result.PASS


def test_validation_reads_at_most_the_cap() -> None:
    assert (
        evaluate_validation({"type": "substring", "value": "ok"}, b"ok" + b"x" * 10, True) is None
    )
    rule = {"type": "json_path", "path": "$.a", "equals": 1}
    assert evaluate_validation(rule, b'{"a": 1', True) == Failure.RESPONSE_TOO_LARGE


async def test_large_body_truncated_at_cap() -> None:
    body = b"x" * 5000 + b"needle"
    server = FakeServer(
        response=b"HTTP/1.1 200 OK\r\nContent-Length: %d\r\n\r\n%s" % (len(body), body)
    )
    outcome = await run_check(
        request(validation={"type": "substring", "value": "needle"}, validation_max_bytes=1024),
        env(server, FakeResolver([PUBLIC])),
    )
    assert outcome.failure_category == Failure.VALIDATION_FAILED


@pytest.mark.parametrize(
    "path", ["", "$", "status;drop", "$..x", "$.a[b]", "$." + ".".join("a" * 33)]
)
def test_invalid_json_paths(path: str) -> None:
    with pytest.raises(ValueError):
        parse_json_path(path)


async def test_raw_socket_errors_are_connect_errors() -> None:
    server = FakeServer(connect_error=OSError("Network is unreachable"))
    outcome = await run_check(request(retry_attempts=1), env(server, FakeResolver([PUBLIC])))
    assert (outcome.result, outcome.failure_category, outcome.attempt_count) == (
        Result.FAIL,
        Failure.CONNECT_ERROR,
        2,
    )
