"""Local validation of proposed firewall rules (ADR-0005, layer one).

Only a narrow subset of OPNsense rule fields is supported. Everything else is refused.
Alias names used as addresses or ports are checked against the firewall at stage time.
"""

import ipaddress
import re
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from app.changes.schemas import RESERVED_NAMES, _valid_port

_IFACE = re.compile(r"^[a-z][a-z0-9_]{0,31}$")
_ALIAS = re.compile(r"^[A-Za-z_][A-Za-z0-9_]{0,31}$")
PORT_PROTOCOLS = frozenset({"TCP", "UDP", "TCP/UDP"})

Action = Literal["pass", "block", "reject"]
Direction = Literal["in", "out"]
IpProtocol = Literal["inet", "inet6"]
Protocol = Literal["any", "TCP", "UDP", "TCP/UDP", "ICMP"]


def _address(value: str) -> str:
    """'any', an IP or CIDR, or an alias name. Returns the cleaned value."""
    item = value.strip()
    if item == "any":
        return item
    try:
        ipaddress.ip_address(item)
        return item
    except ValueError:
        pass
    if "/" in item:
        try:
            ipaddress.ip_network(item, strict=True)
        except ValueError:
            raise ValueError("Not a valid address or network") from None
        return item
    if _ALIAS.match(item) and item.lower() not in RESERVED_NAMES:
        return item
    raise ValueError("Use 'any', an IP address, a CIDR network or an alias name")


def _port(value: str) -> str:
    item = value.strip()
    if item == "" or _valid_port(item):
        return item
    if _ALIAS.match(item) and item.lower() not in RESERVED_NAMES:
        return item
    raise ValueError("Use a port, a port range (80:90) or an alias name")


class RuleProposal(BaseModel):
    model_config = ConfigDict(extra="forbid")

    enabled: bool = True
    action: Action
    interface: str = Field(min_length=1, max_length=32)
    direction: Direction = "in"
    ip_protocol: IpProtocol = "inet"
    protocol: Protocol = "any"
    source: str = Field(default="any", min_length=1, max_length=64)
    source_port: str = Field(default="", max_length=64)
    destination: str = Field(default="any", min_length=1, max_length=64)
    destination_port: str = Field(default="", max_length=64)
    log: bool = False
    description: str = Field(default="", max_length=255)  # required; checked after stripping

    @field_validator("interface")
    @classmethod
    def _check_interface(cls, value: str) -> str:
        if not _IFACE.match(value):
            raise ValueError("Use the interface identifier (for example lan, wan, opt1)")
        return value

    @field_validator("source", "destination")
    @classmethod
    def _check_address(cls, value: str) -> str:
        return _address(value)

    @field_validator("source_port", "destination_port")
    @classmethod
    def _check_port(cls, value: str) -> str:
        return _port(value)

    @field_validator("description")
    @classmethod
    def _check_description(cls, value: str) -> str:
        if any(ord(ch) < 32 or ord(ch) == 127 for ch in value):
            raise ValueError("Description must not contain control characters")
        return value.strip()

    @model_validator(mode="after")
    def _check_combination(self) -> RuleProposal:
        if (self.source_port or self.destination_port) and self.protocol not in PORT_PROTOCOLS:
            raise ValueError("Ports can only be set for TCP, UDP or TCP/UDP")
        if self.protocol == "ICMP" and self.ip_protocol != "inet":
            raise ValueError("ICMP applies to IPv4 only")
        if not self.description:
            raise ValueError("A description is required; it identifies the rule")
        return self

    def alias_references(self) -> set[str]:
        """Names that must exist as aliases on the firewall."""
        found: set[str] = set()
        for value in (self.source, self.destination):
            if value != "any" and "/" not in value and not _is_ip(value):
                found.add(value)
        for value in (self.source_port, self.destination_port):
            if value and not _valid_port(value):
                found.add(value)
        return found

    def risk_reasons(self) -> list[str]:
        """Why this rule needs an admin approver and a typed confirmation."""
        reasons: list[str] = []
        if self.action == "pass" and self.source == "any" and self.destination == "any":
            reasons.append("passes any source to any destination")
        if self.interface == "wan":
            reasons.append("changes the WAN interface")
        return reasons


def _is_ip(value: str) -> bool:
    try:
        ipaddress.ip_address(value)
    except ValueError:
        return False
    return True
