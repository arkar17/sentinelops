"""Real TLS over loopback (dev-fixtures policy only): pinned IP keeps SNI and hostname checks."""

import asyncio
import datetime
import ssl
from collections.abc import AsyncIterator
from pathlib import Path

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

from sentinelops.probes.http.engine import (
    Failure,
    ProbeEnvironment,
    ProbeRequest,
    Result,
    run_check,
)
from tests.probe.fakes import FakeResolver

NOW = datetime.datetime.now(datetime.UTC)


def _ca() -> tuple[x509.Certificate, ec.EllipticCurvePrivateKey]:
    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "SentinelOps test CA")])
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(NOW - datetime.timedelta(days=1))
        .not_valid_after(NOW + datetime.timedelta(days=30))
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .add_extension(
            x509.KeyUsage(True, False, False, False, False, True, True, False, False), critical=True
        )
        .add_extension(x509.SubjectKeyIdentifier.from_public_key(key.public_key()), critical=False)
        .sign(key, hashes.SHA256())
    )
    return cert, key


def _leaf(
    ca: x509.Certificate, ca_key: ec.EllipticCurvePrivateKey, name: str, days: int
) -> tuple[x509.Certificate, ec.EllipticCurvePrivateKey]:
    key = ec.generate_private_key(ec.SECP256R1())
    cert = (
        x509.CertificateBuilder()
        .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, name)]))
        .issuer_name(ca.subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(NOW - datetime.timedelta(days=1))
        .not_valid_after(NOW + datetime.timedelta(days=days))
        .add_extension(x509.SubjectAlternativeName([x509.DNSName(name)]), critical=False)
        .add_extension(
            x509.AuthorityKeyIdentifier.from_issuer_public_key(ca_key.public_key()), critical=False
        )
        .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]), critical=False)
        .sign(ca_key, hashes.SHA256())
    )
    return cert, key


async def _serve(
    tmp: Path, cert: x509.Certificate, key: ec.EllipticCurvePrivateKey
) -> asyncio.Server:
    cert_path, key_path = tmp / "cert.pem", tmp / "key.pem"
    cert_path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    key_path.write_bytes(
        key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
    )
    context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
    context.load_cert_chain(cert_path, key_path)

    async def handle(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        try:
            await reader.readuntil(b"\r\n\r\n")
            writer.write(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
            await writer.drain()
        except ConnectionError, asyncio.IncompleteReadError, ssl.SSLError:
            pass
        finally:
            writer.close()

    return await asyncio.start_server(handle, "127.0.0.1", 0, ssl=context)


@pytest.fixture
async def ca_env() -> AsyncIterator[tuple[x509.Certificate, ec.EllipticCurvePrivateKey]]:
    yield _ca()


async def _check(tmp: Path, cert_name: str, days: int = 30) -> tuple[str, str | None, object]:
    ca, ca_key = _ca()
    cert, key = _leaf(ca, ca_key, cert_name, days)
    server = await _serve(tmp, cert, key)
    port = server.sockets[0].getsockname()[1]
    ca_pem = ca.public_bytes(serialization.Encoding.PEM).decode()

    def trust_test_ca() -> ssl.SSLContext:
        context = ssl.create_default_context(cadata=ca_pem)
        return context

    environment = ProbeEnvironment(
        resolver=FakeResolver(["127.0.0.1"]), ssl_context_factory=trust_test_ca, allow_loopback=True
    )
    request = ProbeRequest(
        url=f"https://good.example.com:{port}/",
        hostname="good.example.com",
        port=port,
        method="GET",
        timeout_ms=3000,
        retry_attempts=0,
        expected_status=[(200, 299)],
    )
    try:
        outcome = await run_check(request, environment)
    finally:
        server.close()
        await server.wait_closed()
    return outcome.result, outcome.failure_category, outcome.tls_not_after


async def test_valid_certificate_passes_and_expiry_is_captured(tmp_path: Path) -> None:
    result, category, not_after = await _check(tmp_path, "good.example.com", days=20)
    assert (result, category) == (Result.PASS, None)
    assert isinstance(not_after, datetime.datetime)
    assert 19 <= (not_after - NOW).days <= 20


async def test_certificate_for_another_name_fails_tls(tmp_path: Path) -> None:
    result, category, _ = await _check(tmp_path, "evil.example.net")
    assert (result, category) == (Result.FAIL, Failure.TLS_ERROR)


async def test_strict_policy_blocks_the_same_loopback_target(tmp_path: Path) -> None:
    request = ProbeRequest(
        url="https://good.example.com/",
        hostname="good.example.com",
        port=443,
        method="GET",
        timeout_ms=1000,
        retry_attempts=0,
        expected_status=[(200, 299)],
    )
    outcome = await run_check(request, ProbeEnvironment(resolver=FakeResolver(["127.0.0.1"])))
    assert outcome.result == Result.BLOCKED
