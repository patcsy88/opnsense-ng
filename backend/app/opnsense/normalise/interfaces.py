"""Map the OPNsense interface overview to our internal schema."""

from typing import Any

from pydantic import BaseModel

MAX_INTERFACES = 256


class InterfaceInfo(BaseModel):
    identifier: str | None = None
    description: str | None = None
    device: str | None = None
    status: str | None = None
    enabled: bool | None = None
    link_type: str | None = None
    ipv4: list[str] = []
    ipv6: list[str] = []
    gateways: list[str] = []
    vlan_tag: int | None = None


def normalise_interfaces(raw: Any) -> list[InterfaceInfo]:
    """Tolerant mapping of the `rows` list; unexpected shapes yield fewer or empty fields.
    MAC addresses and counters are deliberately not passed on."""
    rows = raw.get("rows") if isinstance(raw, dict) else None
    if not isinstance(rows, list):
        return []
    result: list[InterfaceInfo] = []
    for row in rows[:MAX_INTERFACES]:
        if not isinstance(row, dict):
            continue
        result.append(
            InterfaceInfo(
                identifier=_str(row.get("identifier")),
                description=_str(row.get("description")),
                device=_str(row.get("device")),
                status=_str(row.get("status")),
                enabled=row.get("enabled") if isinstance(row.get("enabled"), bool) else None,
                link_type=_str(row.get("link_type")),
                ipv4=_addresses(row.get("ipv4")),
                ipv6=_addresses(row.get("ipv6")),
                gateways=[g for g in _list(row.get("gateways")) if isinstance(g, str)],
                vlan_tag=_vlan(row.get("vlan_tag")),
            )
        )
    return result


def _str(value: Any) -> str | None:
    return value if isinstance(value, str) and value else None


def _list(value: Any) -> list[Any]:
    return value if isinstance(value, list) else []


def _addresses(value: Any) -> list[str]:
    out: list[str] = []
    for item in _list(value):
        address = item.get("ipaddr") if isinstance(item, dict) else item
        if isinstance(address, str) and address:
            out.append(address)
    return out


def _vlan(value: Any) -> int | None:
    if isinstance(value, bool):
        return None
    if isinstance(value, int):
        return value if 0 < value < 4095 else None
    if isinstance(value, str) and value.isdigit():
        return _vlan(int(value))
    return None
