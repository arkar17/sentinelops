"""Destination IP classification (FR-MON-004, 02_TECHNICAL_ARCHITECTURE.md §7).

A destination is allowed only if it is globally routable unicast. IPv6 forms that embed IPv4
(mapped, compatible, 6to4, NAT64) are judged by the embedded address; Teredo is always refused.
"""

import ipaddress

IPAddress = ipaddress.IPv4Address | ipaddress.IPv6Address

# Explicit for readability; every one is also caught by the generic checks below.
METADATA_ADDRESSES = frozenset(
    {
        ipaddress.ip_address("169.254.169.254"),  # AWS, GCP, Azure, OpenStack
        ipaddress.ip_address("169.254.170.2"),  # AWS ECS task metadata
        ipaddress.ip_address("100.100.100.200"),  # Alibaba Cloud
        ipaddress.ip_address("fd00:ec2::254"),  # AWS IPv6 IMDS
    }
)
_NAT64 = (ipaddress.ip_network("64:ff9b::/96"), ipaddress.ip_network("64:ff9b:1::/48"))
_IPV4_COMPATIBLE = ipaddress.ip_network("::/96")
_LOOPBACK = (ipaddress.ip_network("127.0.0.0/8"), ipaddress.ip_network("::1/128"))


def _embedded_ipv4(ip: ipaddress.IPv6Address) -> ipaddress.IPv4Address | None:
    if ip.ipv4_mapped is not None:
        return ip.ipv4_mapped
    if ip.sixtofour is not None:
        return ip.sixtofour
    if any(ip in net for net in _NAT64) or (ip in _IPV4_COMPATIBLE and int(ip) > 1):
        return ipaddress.IPv4Address(int(ip) & 0xFFFFFFFF)
    return None


def is_loopback(ip: IPAddress) -> bool:
    return any(ip in net for net in _LOOPBACK) or (
        isinstance(ip, ipaddress.IPv6Address)
        and (embedded := _embedded_ipv4(ip)) is not None
        and embedded.is_loopback
    )


def is_forbidden(ip: IPAddress, *, allow_loopback: bool = False) -> bool:
    """True unless ``ip`` is a globally routable unicast address."""
    if allow_loopback and is_loopback(ip):
        return False
    if ip in METADATA_ADDRESSES:
        return True
    if isinstance(ip, ipaddress.IPv6Address):
        if ip.teredo is not None:
            return True
        embedded = _embedded_ipv4(ip)
        if embedded is not None:
            return is_forbidden(embedded, allow_loopback=allow_loopback)
    return (
        not ip.is_global
        or ip.is_multicast
        or ip.is_unspecified
        or ip.is_reserved
        or ip.is_loopback
        or ip.is_link_local
        or ip.is_private
    )
