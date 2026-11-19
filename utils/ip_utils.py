"""IP address helpers.

These functions only *validate and compare* addresses locally. The project
never performs external lookups, scans, or blocking of any address.
"""

from __future__ import annotations

import ipaddress
import re
from typing import Iterable

IPNetwork = ipaddress.IPv4Network | ipaddress.IPv6Network

# Something that "looks like" an IPv4 address (4 dot-separated numbers) or an
# IPv6 address (hex groups with colons). Used to decide whether an invalid
# value should be rejected (bad IP) or simply ignored (e.g. a hostname).
_LOOKS_LIKE_IPV4 = re.compile(r"^\d{1,4}(\.\d{1,4}){3}$")
_LOOKS_LIKE_IPV6 = re.compile(r"^[0-9a-fA-F:]+:[0-9a-fA-F:.]*$")


def normalize_ip(value: object) -> str | None:
    """Return the canonical string form of a valid IP, otherwise ``None``."""
    if value is None:
        return None
    text = str(value).strip().strip("[]")
    if not text:
        return None
    try:
        return str(ipaddress.ip_address(text))
    except ValueError:
        return None


def is_valid_ip(value: object) -> bool:
    return normalize_ip(value) is not None


def looks_like_ip(value: object) -> bool:
    """True when the value resembles an IP address (valid or not)."""
    if value is None:
        return False
    text = str(value).strip().strip("[]")
    return bool(_LOOKS_LIKE_IPV4.match(text) or _LOOKS_LIKE_IPV6.match(text))


def parse_watchlist(entries: Iterable[str]) -> tuple[list[IPNetwork], list[str]]:
    """Parse watchlist entries (single IPs or CIDR ranges).

    Returns ``(valid_networks, invalid_entries)``. Comments after ``#`` and
    blank lines are ignored.
    """
    networks: list[IPNetwork] = []
    invalid: list[str] = []
    for raw in entries:
        entry = str(raw).split("#", 1)[0].strip()
        if not entry:
            continue
        try:
            networks.append(ipaddress.ip_network(entry, strict=False))
        except ValueError:
            invalid.append(entry)
    return networks, invalid


def ip_in_networks(ip: str | None, networks: Iterable[IPNetwork]) -> bool:
    """Check whether ``ip`` belongs to any of the given networks."""
    canonical = normalize_ip(ip)
    if canonical is None:
        return False
    address = ipaddress.ip_address(canonical)
    return any(address.version == net.version and address in net for net in networks)


def is_documentation_ip(ip: str | None) -> bool:
    """True for RFC 5737 / RFC 3849 documentation-only ranges (used by samples)."""
    canonical = normalize_ip(ip)
    if canonical is None:
        return False
    doc_ranges = [
        ipaddress.ip_network("192.0.2.0/24"),
        ipaddress.ip_network("198.51.100.0/24"),
        ipaddress.ip_network("203.0.113.0/24"),
        ipaddress.ip_network("2001:db8::/32"),
    ]
    return ip_in_networks(canonical, doc_ranges)
