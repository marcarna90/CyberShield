"""Network helpers with explicit, predictable address classification.

``ipaddress.is_private`` also returns ``True`` for documentation ranges
(TEST-NET-1/2/3, 2001:db8::/32), which would make traffic to them look
"internal". CyberShield uses explicit lists instead.
"""

from __future__ import annotations

import ipaddress
from functools import lru_cache

INTERNAL_NETWORKS = tuple(
    ipaddress.ip_network(n)
    for n in (
        "10.0.0.0/8",
        "172.16.0.0/12",
        "192.168.0.0/16",
        "127.0.0.0/8",
        "169.254.0.0/16",
        "100.64.0.0/10",  # carrier-grade NAT
        "fc00::/7",  # IPv6 unique local
        "fe80::/10",  # IPv6 link local
        "::1/128",
    )
)
DOCUMENTATION_NETWORKS = tuple(
    ipaddress.ip_network(n) for n in ("192.0.2.0/24", "198.51.100.0/24", "203.0.113.0/24", "2001:db8::/32")
)


@lru_cache(maxsize=65_536)
def is_internal(value: str) -> bool:
    """``True`` for RFC 1918, loopback, link-local, CGNAT and IPv6 ULA addresses."""
    try:
        ip = ipaddress.ip_address(value)
    except ValueError:
        return False
    return any(ip.version == net.version and ip in net for net in INTERNAL_NETWORKS)


def classify_ip(value: str) -> str:
    """Return a coarse classification used in reports and reputation lookups."""
    try:
        ip = ipaddress.ip_address(value)
    except ValueError:
        return "invalid"
    if ip.is_loopback:
        return "loopback"
    if ip.is_multicast:
        return "multicast"
    if ip.is_link_local:
        return "link_local"
    if any(ip.version == net.version and ip in net for net in DOCUMENTATION_NETWORKS):
        return "documentation"
    if is_internal(value):
        return "private"
    if ip.is_unspecified or ip.is_reserved or not ip.is_global:
        return "reserved"
    return "public"
