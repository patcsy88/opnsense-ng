"""WireGuard status (ADR-0009). Built from a whitelist: no private, preshared or public keys."""

from datetime import UTC, datetime
from typing import Any

from pydantic import BaseModel

MAX_RECORDS = 500
PEER_STATUSES = ("online", "stale", "offline")


class WireguardRecord(BaseModel):
    interface: str
    type: str
    tunnel_name: str | None = None
    name: str | None = None
    status: str | None = None
    endpoint: str | None = None
    listen_port: int | None = None
    allowed_ips: list[str] = []
    latest_handshake: str | None = None
    rx_bytes: int | None = None
    tx_bytes: int | None = None
    keepalive: int | None = None


class WireguardResult(BaseModel):
    records: list[WireguardRecord] = []
    truncated: bool = False


def normalise_wireguard(raw: Any) -> WireguardResult:
    """Tolerant mapping of `rows`. Rows without an interface or a known type are skipped."""
    rows = raw.get("rows") if isinstance(raw, dict) else None
    if not isinstance(rows, list):
        return WireguardResult()
    out: list[WireguardRecord] = []
    for row in rows[:MAX_RECORDS]:
        if not isinstance(row, dict):
            continue
        interface = _text(row.get("if"), 64)
        kind = row.get("type")
        if interface is None or kind not in ("interface", "peer"):
            continue
        common: dict[str, Any] = {
            "interface": interface,
            "type": kind,
            "tunnel_name": _text(row.get("ifname"), 128),
            "name": _text(row.get("name"), 128),
        }
        if kind == "interface":
            status = row.get("status")
            out.append(
                WireguardRecord(
                    **common,
                    status=status if status in ("up", "down") else None,
                    listen_port=_number(row.get("listen-port")),
                )
            )
            continue
        status = row.get("peer-status")
        ips = row.get("allowed-ips")
        endpoint = _text(row.get("endpoint"), 255)
        out.append(
            WireguardRecord(
                **common,
                status=status if status in PEER_STATUSES else None,
                endpoint=None if endpoint == "(none)" else endpoint,
                allowed_ips=_ips(ips),
                latest_handshake=_handshake(row.get("latest-handshake")),
                rx_bytes=_number(row.get("transfer-rx")),
                tx_bytes=_number(row.get("transfer-tx")),
                keepalive=_number(row.get("persistent-keepalive")),
            )
        )
    return WireguardResult(records=out, truncated=len(rows) > MAX_RECORDS)


def _text(value: Any, limit: int) -> str | None:
    if not isinstance(value, str) or not value:
        return None
    return value[:limit]


def _number(value: Any) -> int | None:
    if isinstance(value, bool):
        return None
    if isinstance(value, str) and value.isdigit():
        return int(value)
    return value if isinstance(value, int) and value >= 0 else None


def _ips(value: Any) -> list[str]:
    if not isinstance(value, str) or value in ("", "(none)"):
        return []
    return [part.strip()[:64] for part in value.split(",") if part.strip()][:64]


def _handshake(value: Any) -> str | None:
    seconds = _number(value)
    if not seconds:
        return None
    try:
        return datetime.fromtimestamp(seconds, UTC).isoformat()
    except OverflowError, OSError, ValueError:
        return None
