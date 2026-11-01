"""Static monitor URL validation (FR-MON-004 steps that need no DNS)."""

import ipaddress
import re
from dataclasses import dataclass
from urllib.parse import urlsplit

from sentinelops.errors import AppError

ALLOWED_PORTS = {"http": 80, "https": 443}
_LABEL = re.compile(r"^(?!-)[a-z0-9-]{1,63}(?<!-)$")
_NUMERIC_LABEL = re.compile(r"^(0x[0-9a-f]*|[0-9]+)$")
# Special-use names that can never be public monitoring targets.
_FORBIDDEN_SUFFIXES = (
    "localhost",
    "local",
    "internal",
    "intranet",
    "lan",
    "home.arpa",
    "arpa",
    "onion",
    "invalid",
)
MAX_URL_LENGTH = 2048


class UrlPolicyError(AppError):
    def __init__(self, message: str) -> None:
        super().__init__(422, "URL_NOT_ALLOWED", message)


@dataclass(frozen=True)
class ParsedTarget:
    scheme: str
    hostname: str  # normalized ASCII (IDNA), lowercase, no trailing dot
    port: int
    display_url: str  # scheme://host/path, never the query string
    url: str  # normalized full URL (stored encrypted)


def normalize_hostname(raw: str) -> str:
    host = raw.strip().rstrip(".").lower()
    if not host:
        raise UrlPolicyError("A hostname is required")
    try:
        ipaddress.ip_address(host.strip("[]"))
    except ValueError:
        pass
    else:
        raise UrlPolicyError("IP addresses are not allowed; use a verified hostname")
    try:
        ascii_host = host.encode("idna").decode("ascii")
    except UnicodeError as exc:
        raise UrlPolicyError("The hostname is not a valid internationalized domain name") from exc
    labels = ascii_host.split(".")
    if (
        len(ascii_host) > 253
        or len(labels) < 2
        or not all(_LABEL.fullmatch(label) for label in labels)
    ):
        raise UrlPolicyError("The hostname is not a valid public DNS name")
    if all(_NUMERIC_LABEL.fullmatch(label) for label in labels) or labels[-1].isdigit():
        raise UrlPolicyError("Numeric or encoded IP hostnames are not allowed")
    if any(ascii_host == s or ascii_host.endswith("." + s) for s in _FORBIDDEN_SUFFIXES):
        raise UrlPolicyError("Special-use and internal hostnames are not allowed")
    return ascii_host


def parse_target(url: str) -> ParsedTarget:
    candidate = url.strip()
    if len(candidate) > MAX_URL_LENGTH or any(ord(c) < 0x21 or ord(c) == 0x7F for c in candidate):
        raise UrlPolicyError("The URL is too long or contains control or space characters")
    parts = urlsplit(candidate)
    scheme = parts.scheme.lower()
    if scheme not in ALLOWED_PORTS:
        raise UrlPolicyError("Only http and https URLs are allowed")
    if parts.username is not None or parts.password is not None or "@" in parts.netloc:
        raise UrlPolicyError("Credentials in URLs are not allowed; use custom headers")
    if parts.fragment or "#" in candidate:
        raise UrlPolicyError("URL fragments are not allowed")
    try:
        port = parts.port
    except ValueError as exc:
        raise UrlPolicyError("The port is invalid") from exc
    if port is not None and port != ALLOWED_PORTS[scheme]:
        raise UrlPolicyError("Only port 80 (http) and 443 (https) are allowed")
    hostname = normalize_hostname(parts.hostname or "")
    path = parts.path or "/"
    query = f"?{parts.query}" if parts.query else ""
    return ParsedTarget(
        scheme=scheme,
        hostname=hostname,
        port=ALLOWED_PORTS[scheme],
        display_url=f"{scheme}://{hostname}{path}",
        url=f"{scheme}://{hostname}{path}{query}",
    )


def hostname_covered(hostname: str, fqdn: str) -> bool:
    """A verified domain covers itself and its subdomains (OD-05)."""
    return hostname == fqdn or hostname.endswith("." + fqdn)
