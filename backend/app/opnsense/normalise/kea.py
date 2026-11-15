"""Kea DHCPv4 leases, reservations and subnets (ADR-0020). Field names are unverified on the lab.

Leases never carry MAC addresses or client ids. Reservations do, and their endpoint is closed to
roles that may not manage hosts.
"""

import ipaddress
from datetime import UTC, datetime
from typing import Any

from pydantic import BaseModel

MAX_ROWS = 1000


class KeaLease(BaseModel):
    address: str
    hostname: str | None = None
    interface: str | None = None
    state: str | None = None
    expires: str | None = None


class KeaLeasesResult(BaseModel):
    leases: list[KeaLease] = []
    truncated: bool = False


class KeaReservation(BaseModel):
    uuid: str
    subnet: str | None = None
    ip_address: str
    hw_address: str | None = None
    hostname: str | None = None
    description: str | None = None


class KeaReservationsResult(BaseModel):
    reservations: list[KeaReservation] = []
    truncated: bool = False


class KeaSubnet(BaseModel):
    uuid: str
    subnet: str
    pools: list[str] = []
    description: str | None = None


class KeaSubnetsResult(BaseModel):
    subnets: list[KeaSubnet] = []
    truncated: bool = False


def _rows(raw: Any) -> list[Any] | None:
    rows = raw.get("rows") if isinstance(raw, dict) else None
    return rows if isinstance(rows, list) else None


def _text(value: Any, limit: int) -> str | None:
    if not isinstance(value, str) or not value or value == "*":
        return None
    return value[:limit]


def _ipv4(value: Any) -> str | None:
    if not isinstance(value, str):
        return None
    try:
        return str(ipaddress.IPv4Address(value))
    except ValueError:
        return None


def _expiry(value: Any) -> str | None:
    if isinstance(value, bool):
        return None
    if isinstance(value, str) and value.isdigit():
        value = int(value)
    if not isinstance(value, int) or value <= 0:
        return None
    try:
        return datetime.fromtimestamp(value, UTC).isoformat()
    except OverflowError, OSError, ValueError:
        return None


def normalise_kea_leases(raw: Any) -> KeaLeasesResult:
    rows = _rows(raw)
    if rows is None:
        return KeaLeasesResult()
    out: list[KeaLease] = []
    for row in rows[:MAX_ROWS]:
        address = _ipv4(row.get("address")) if isinstance(row, dict) else None
        if address is None:
            continue
        out.append(
            KeaLease(
                address=address,
                hostname=_text(row.get("hostname"), 255),
                interface=_text(row.get("if_name"), 64),
                state=_text(row.get("state"), 32),
                expires=_expiry(row.get("expire")),
            )
        )
    return KeaLeasesResult(leases=out, truncated=len(rows) > MAX_ROWS)


def normalise_kea_reservations(raw: Any) -> KeaReservationsResult:
    rows = _rows(raw)
    if rows is None:
        return KeaReservationsResult()
    out: list[KeaReservation] = []
    for row in rows[:MAX_ROWS]:
        if not isinstance(row, dict):
            continue
        uuid = _text(row.get("uuid"), 64)
        address = _ipv4(row.get("ip_address"))
        if uuid is None or address is None:
            continue
        out.append(
            KeaReservation(
                uuid=uuid,
                subnet=_text(row.get("%subnet"), 64) or _text(row.get("subnet"), 64),
                ip_address=address,
                hw_address=_text(row.get("hw_address"), 32),
                hostname=_text(row.get("hostname"), 255),
                description=_text(row.get("description"), 255),
            )
        )
    return KeaReservationsResult(reservations=out, truncated=len(rows) > MAX_ROWS)


def normalise_kea_subnets(raw: Any) -> KeaSubnetsResult:
    rows = _rows(raw)
    if rows is None:
        return KeaSubnetsResult()
    out: list[KeaSubnet] = []
    for row in rows[:MAX_ROWS]:
        if not isinstance(row, dict):
            continue
        uuid = _text(row.get("uuid"), 64)
        subnet = _text(row.get("subnet"), 64)
        if uuid is None or subnet is None:
            continue
        pools = row.get("pools")
        if isinstance(pools, str):
            pools = pools.replace(",", "\n").splitlines()
        if not isinstance(pools, list):
            pools = []
        lines = [p.strip()[:64] for p in pools if isinstance(p, str) and p.strip()]
        out.append(
            KeaSubnet(
                uuid=uuid,
                subnet=subnet,
                pools=lines[:20],
                description=_text(row.get("description"), 255),
            )
        )
    return KeaSubnetsResult(subnets=out, truncated=len(rows) > MAX_ROWS)
