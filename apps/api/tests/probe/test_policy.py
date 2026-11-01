"""Destination and URL policy (FR-MON-004)."""

import ipaddress

import pytest

from sentinelops.probe_policy.addresses import is_forbidden
from sentinelops.probe_policy.urls import UrlPolicyError, hostname_covered, parse_target

FORBIDDEN = [
    "127.0.0.1", "127.255.255.254", "10.0.0.1", "172.16.5.4", "192.168.1.1",
    "169.254.169.254", "169.254.170.2", "100.64.0.1", "100.100.100.200", "0.0.0.0",
    "224.0.0.1", "239.255.255.250", "255.255.255.255", "192.0.2.1", "198.51.100.7",
    "203.0.113.9", "198.18.0.1", "240.0.0.1", "192.0.0.8",
    "::1", "::", "fe80::1", "fc00::1", "fd12:3456::1", "fd00:ec2::254", "ff02::1",
    "2001:db8::1", "::ffff:127.0.0.1", "::ffff:10.1.2.3", "::ffff:169.254.169.254",
    "64:ff9b::a9fe:a9fe", "64:ff9b::7f00:1", "2002:7f00:1::1", "2002:a9fe:a9fe::1",
    "2001:0:4136:e378:8000:63bf:3fff:fdd2", "::127.0.0.1", "::a9fe:a9fe",
]  # fmt: skip
ALLOWED = ["93.184.216.34", "1.1.1.1", "8.8.8.8", "2606:4700:4700::1111", "2a00:1450:4001::8a"]


@pytest.mark.parametrize("address", FORBIDDEN)
def test_forbidden_destinations(address: str) -> None:
    assert is_forbidden(ipaddress.ip_address(address))


@pytest.mark.parametrize("address", ALLOWED)
def test_public_destinations_allowed(address: str) -> None:
    assert not is_forbidden(ipaddress.ip_address(address))


def test_dev_fixture_policy_allows_only_loopback() -> None:
    assert not is_forbidden(ipaddress.ip_address("127.0.0.1"), allow_loopback=True)
    assert not is_forbidden(ipaddress.ip_address("::1"), allow_loopback=True)
    for address in ("169.254.169.254", "10.0.0.1", "fd00:ec2::254", "::ffff:169.254.169.254"):
        assert is_forbidden(ipaddress.ip_address(address), allow_loopback=True)


REJECTED_URLS = [
    "ftp://example.com/", "file:///etc/passwd", "javascript:alert(1)", "gopher://example.com",
    "http://127.0.0.1/", "http://[::1]/", "http://[::ffff:127.0.0.1]/", "http://2130706433/",
    "http://0x7f.0.0.1/", "http://0177.0.0.1/", "http://127.1/", "http://0x7f000001/",
    "http://169.254.169.254/latest/meta-data/", "http://user:pw@example.com/",
    "http://example.com@169.254.169.254/", "https://example.com:8443/", "http://example.com:443/",
    "https://example.com:80/", "http://example.com/#frag", "http://localhost/", "http://app.localhost/",
    "http://metadata.google.internal/", "http://printer.local/", "http://router.lan/",
    "http://x.home.arpa/", "http://1.0.0.127.in-addr.arpa/", "http://single/",
    "http://exa mple.com/",
    "http://example.com/\r\nHost: evil", "http://-bad-.example.com/", "http://example.123/",
    "https://" + "a" * 2050 + ".com/",
]  # fmt: skip


@pytest.mark.parametrize("url", REJECTED_URLS)
def test_rejected_urls(url: str) -> None:
    with pytest.raises(UrlPolicyError):
        parse_target(url)


def test_url_normalization_and_display() -> None:
    target = parse_target("HTTPS://API.Example.COM./v1/health?token=secret")
    assert target.hostname == "api.example.com"
    assert target.port == 443
    assert target.display_url == "https://api.example.com/v1/health"
    assert "token=secret" in target.url
    assert "secret" not in target.display_url
    assert parse_target("http://example.com").display_url == "http://example.com/"
    assert parse_target("https://bücher.example/").hostname == "xn--bcher-kva.example"


def test_domain_coverage() -> None:
    assert hostname_covered("example.com", "example.com")
    assert hostname_covered("api.eu.example.com", "example.com")
    assert not hostname_covered("evilexample.com", "example.com")
    assert not hostname_covered("example.com.evil.net", "example.com")
    assert not hostname_covered("example.com", "api.example.com")
