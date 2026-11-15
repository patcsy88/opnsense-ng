"""Local validation of proposed Kea DHCPv4 reservations (ADR-0021, layer one).

Only subnet, IP, MAC, hostname and description are supported. Client id, options, next server and
DDNS stay untouched.
"""

import ipaddress
import re
import uuid as uuidlib
from typing import Any

from pydantic import BaseModel, ConfigDict, Field, field_validator

_LABEL = re.compile(r"^[A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?$")
_MAC = re.compile(r"^[0-9a-f]{2}(:[0-9a-f]{2}){5}$")


def _mac(value: str) -> str:
    item = value.strip().lower().replace("-", ":")
    if not _MAC.match(item):
        raise ValueError("MAC addresses look like aa:bb:cc:dd:ee:ff")
    return item


def reservation_key(ip: str | None) -> str:
    return (ip or "").strip()


class KeaReservationProposal(BaseModel):
    model_config = ConfigDict(extra="forbid")

    subnet: str
    ip_address: str
    hw_address: str
    hostname: str | None = Field(default=None, max_length=253)
    description: str | None = Field(default=None, max_length=255)

    @field_validator("subnet")
    @classmethod
    def _subnet(cls, v: str) -> str:
        try:
            return str(uuidlib.UUID(v.strip()))
        except ValueError:
            raise ValueError("The subnet is chosen by id from the list") from None

    @field_validator("ip_address")
    @classmethod
    def _ip(cls, v: str) -> str:
        try:
            return str(ipaddress.IPv4Address(v.strip()))
        except ValueError:
            raise ValueError("Not a valid IPv4 address") from None

    @field_validator("hw_address")
    @classmethod
    def _hw(cls, v: str) -> str:
        return _mac(v)

    @field_validator("hostname")
    @classmethod
    def _host(cls, v: str | None) -> str | None:
        if v is None or not v.strip():
            return None
        item = v.strip().rstrip(".").lower()
        if not all(_LABEL.match(p) for p in item.split(".")):
            raise ValueError("Hostname is not a valid DNS name")
        return item

    @field_validator("description")
    @classmethod
    def _descr(cls, v: str | None) -> str | None:
        if v is None or not v.strip():
            return None
        return v.strip()

    def risk_changes(self, current: Any) -> list[str]:
        """High-risk differences from the reservation that is on the firewall now."""
        reasons: list[str] = []
        if current is None:
            return reasons
        if (current.hw_address or "").lower() != self.hw_address:
            reasons.append("changes the MAC address, which moves this address to another device")
        if current.ip_address != self.ip_address:
            reasons.append("changes the IP address of the reservation")
        return reasons


def kea_reservation_conflict(
    proposed: dict[str, Any], reservations: list[Any], own: str | None
) -> str | None:
    """Same IP in any subnet, or same MAC in the same subnet, ignoring the entry being edited."""
    ip = proposed.get("ip_address")
    mac = str(proposed.get("hw_address") or "").lower()
    subnet = proposed.get("subnet")
    for r in reservations:
        if r.uuid == own:
            continue
        if r.ip_address == ip:
            return "A reservation for this IP address already exists on the firewall"
        if mac and (r.hw_address or "").lower() == mac and r.subnet_id == subnet:
            return "Another reservation in this subnet already uses this MAC address"
    return None


def _pool_range(line: str) -> tuple[ipaddress.IPv4Address, ipaddress.IPv4Address] | None:
    try:
        if "-" in line:
            a, b = line.split("-", 1)
            return ipaddress.IPv4Address(a.strip()), ipaddress.IPv4Address(b.strip())
        net = ipaddress.IPv4Network(line.strip(), strict=False)
        return net[0], net[-1]
    except ValueError:
        return None


def subnet_problem(ip: str, subnet: Any) -> str | None:
    """The IP must lie inside the chosen subnet and outside its dynamic pools."""
    try:
        addr = ipaddress.IPv4Address(ip)
        net = ipaddress.IPv4Network(subnet.subnet, strict=False)
    except ValueError:
        return "The subnet on the firewall could not be read"
    if addr not in net:
        return f"The IP address is outside the subnet {subnet.subnet}"
    for line in subnet.pools:
        rng = _pool_range(line)
        if rng is not None and rng[0] <= addr <= rng[1]:
            return "The IP address lies inside a dynamic pool of this subnet"
    return None
