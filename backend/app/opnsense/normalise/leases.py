"""Dnsmasq DHCP leases (ADR-0008). MAC addresses, client ids and IAIDs are never passed on."""

import ipaddress
from datetime import UTC, datetime
from typing import Any

from pydantic import BaseModel

MAX_LEASES = 1000


class LeaseInfo(BaseModel):
    address: str
    ip_version: int
    hostname: str | None = None
    interface: str | None = None
    lease_type: str | None = None
    vendor: str | None = None
    expires: str | None = None


class LeasesResult(BaseModel):
    leases: list[LeaseInfo] = []
    truncated: bool = False


def normalise_leases(raw: Any) -> LeasesResult:
    """Tolerant mapping of `rows`. Rows without a valid IP address are skipped."""
    rows = raw.get("rows") if isinstance(raw, dict) else None
    if not isinstance(rows, list):
        return LeasesResult()
    out: list[LeaseInfo] = []
    for row in rows[:MAX_LEASES]:
        if not isinstance(row, dict):
            continue
        address = row.get("address")
        if not isinstance(address, str):
            continue
        try:
            version = ipaddress.ip_address(address).version
        except ValueError:
            continue
        kind = row.get("lease_type")
        out.append(
            LeaseInfo(
                address=address,
                ip_version=version,
                hostname=_text(row.get("hostname"), 255, unset="*"),
                interface=_text(row.get("if_descr"), 64) or _text(row.get("if_name"), 64),
                lease_type=kind if kind in ("dynamic", "static") else None,
                vendor=_text(row.get("mac_info"), 128),
                expires=_expiry(row.get("expire")),
            )
        )
    return LeasesResult(leases=out, truncated=len(rows) > MAX_LEASES)


def _text(value: Any, limit: int, unset: str | None = None) -> str | None:
    if not isinstance(value, str) or not value or value == unset:
        return None
    return value[:limit]


def _expiry(value: Any) -> str | None:
    if isinstance(value, bool):
        return None
    if isinstance(value, str) and value.isdigit():
        value = int(value)
    if not isinstance(value, int) or value <= 0:
        return None  # 0 means an infinite lease in dnsmasq
    try:
        return datetime.fromtimestamp(value, UTC).isoformat()
    except OverflowError, OSError, ValueError:
        return None
