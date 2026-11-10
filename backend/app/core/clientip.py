"""Client IP resolution; X-Forwarded-For is honoured only from a trusted direct peer."""

import ipaddress
from collections.abc import Sequence

from starlette.requests import Request

IPNetwork = ipaddress.IPv4Network | ipaddress.IPv6Network
IPAddress = ipaddress.IPv4Address | ipaddress.IPv6Address

UNKNOWN = "unknown"


def _parse(value: str) -> IPAddress | None:
    try:
        ip = ipaddress.ip_address(value.strip())
    except ValueError:
        return None
    if isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped is not None:
        return ip.ipv4_mapped
    return ip


def _trusted(ip: IPAddress, networks: Sequence[IPNetwork]) -> bool:
    return any(ip.version == n.version and ip in n for n in networks)


def resolve_client_ip(
    peer: str | None, forwarded_for: str | None, trusted: Sequence[IPNetwork]
) -> str:
    """Return the client address.

    Without a trusted direct peer the socket address wins and the header is ignored (it is
    attacker-controlled). With a trusted peer the chain is walked right to left and the first
    entry that is not itself a trusted proxy is the client. A malformed entry stops the walk
    and falls back to the peer, so garbage can never choose the identity.
    """
    peer_ip = _parse(peer) if peer else None
    if peer_ip is None:
        return peer or UNKNOWN
    if not trusted or not _trusted(peer_ip, trusted) or not forwarded_for:
        return str(peer_ip)
    entries = [e for e in forwarded_for.split(",") if e.strip()]
    for raw in reversed(entries):
        candidate = _parse(raw)
        if candidate is None:
            return str(peer_ip)
        if not _trusted(candidate, trusted):
            return str(candidate)
    # every hop was a trusted proxy: the left-most is the origin as far as we can tell
    first = _parse(entries[0]) if entries else None
    return str(first or peer_ip)


def client_ip(request: Request) -> str:
    """Resolved client IP for rate limiting and audit (cached per request)."""
    cached: str | None = getattr(request.state, "client_ip", None)
    if cached is not None:
        return cached
    trusted: Sequence[IPNetwork] = getattr(request.app.state, "trusted_proxies", ())
    peer = request.client.host if request.client else None
    xff = ",".join(request.headers.getlist("x-forwarded-for")) or None
    resolved = resolve_client_ip(peer, xff, trusted)
    request.state.client_ip = resolved
    return resolved
