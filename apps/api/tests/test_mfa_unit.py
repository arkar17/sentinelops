"""TOTP (RFC 6238 vectors), replay windows, sealing and recovery codes; trusted-proxy client IPs."""

import base64
import os
import uuid
from datetime import UTC, datetime
from types import SimpleNamespace
from typing import Any

import pytest
from cryptography.exceptions import InvalidTag
from pydantic import SecretStr

from sentinelops.config import Settings
from sentinelops.identity import mfa
from sentinelops.identity.dependencies import client_ip

RFC_SECRET = base64.b32encode(b"12345678901234567890").decode()


@pytest.mark.parametrize(
    ("timestamp", "expected"),
    [(59, "287082"), (1111111109, "081804"), (1234567890, "005924"), (2000000000, "279037")],
)
def test_rfc6238_sha1_vectors(timestamp: int, expected: str) -> None:
    now = datetime.fromtimestamp(timestamp, UTC)
    assert mfa.code_at(RFC_SECRET, mfa.step_of(now)) == expected


def test_codes_match_within_drift_and_never_replay() -> None:
    now = datetime.fromtimestamp(1_700_000_000, UTC)
    step = mfa.step_of(now)
    current = mfa.code_at(RFC_SECRET, step)
    assert mfa.matching_step(RFC_SECRET, current, now, None) == step
    assert mfa.matching_step(RFC_SECRET, mfa.code_at(RFC_SECRET, step - 1), now, None) == step - 1
    assert mfa.matching_step(RFC_SECRET, mfa.code_at(RFC_SECRET, step - 2), now, None) is None
    assert mfa.matching_step(RFC_SECRET, current, now, step) is None  # already used
    for bad in ("", "12345", "abcdef", "1234567"):
        assert mfa.matching_step(RFC_SECRET, bad, now, None) is None


def test_otpauth_uri_and_secret_shape() -> None:
    secret = mfa.new_secret()
    assert len(base64.b32decode(secret + "=" * (-len(secret) % 8))) == 20
    uri = mfa.otpauth_uri(secret, "root@platform.test")
    assert uri.startswith("otpauth://totp/SentinelOps%3Aroot%40platform.test?secret=")
    assert "period=30" in uri and "digits=6" in uri


def test_secret_sealing_is_bound_to_the_user() -> None:
    cipher = mfa.MfaCipher({"k": os.urandom(32)}, "k")
    alice, bob = uuid.uuid4(), uuid.uuid4()
    key_id, sealed = cipher.seal(alice, "JBSWY3DPEHPK3PXP")
    assert "JBSWY3DPEHPK3PXP" not in sealed
    assert cipher.open(alice, key_id, sealed) == "JBSWY3DPEHPK3PXP"
    with pytest.raises(InvalidTag):
        cipher.open(bob, key_id, sealed)


def test_recovery_codes_are_random_and_hashed_case_insensitively() -> None:
    codes = mfa.new_recovery_codes()
    assert len(set(codes)) == 10 and all(len(c) == 14 for c in codes)
    assert mfa.hash_recovery_code(codes[0]) == mfa.hash_recovery_code(
        codes[0].upper().replace("-", "")
    )
    assert codes[0] not in mfa.hash_recovery_code(codes[0])


def _request(
    peer: str, forwarded: list[str] | None = None, proxies: list[str] | None = None
) -> Any:
    settings = Settings(
        database_url=SecretStr("postgresql+asyncpg://u@h/db"), trusted_proxies=proxies or []
    )

    def getlist(_name: str) -> list[str]:
        return forwarded or []

    headers = SimpleNamespace(getlist=getlist)
    return SimpleNamespace(
        client=SimpleNamespace(host=peer),
        headers=headers,
        app=SimpleNamespace(state=SimpleNamespace(settings=settings)),
    )


@pytest.mark.parametrize(
    ("peer", "forwarded", "proxies", "expected"),
    [
        ("203.0.113.9", ["1.2.3.4"], [], "203.0.113.9"),  # no trusted proxies: header ignored
        ("203.0.113.9", ["1.2.3.4"], ["10.0.0.0/8"], "203.0.113.9"),  # untrusted peer spoofing
        ("10.0.0.5", ["198.51.100.7"], ["10.0.0.0/8"], "198.51.100.7"),
        ("10.0.0.5", ["6.6.6.6, 198.51.100.7, 10.0.0.9"], ["10.0.0.0/8"], "198.51.100.7"),
        ("10.0.0.5", ["6.6.6.6", "198.51.100.7"], ["10.0.0.0/8"], "198.51.100.7"),
        ("10.0.0.5", ["not-an-ip"], ["10.0.0.0/8"], "10.0.0.5"),
        ("10.0.0.5", [], ["10.0.0.0/8"], "10.0.0.5"),
        ("10.0.0.5", ["2001:db8::1"], ["10.0.0.0/8"], "2001:db8::1"),
    ],
)
def test_client_ip_honours_only_trusted_proxies(
    peer: str, forwarded: list[str], proxies: list[str], expected: str
) -> None:
    assert client_ip(_request(peer, forwarded, proxies)) == expected
