"""Local validation of proposed NAT port forwards (ADR-0006, layer one).

Only a narrow subset of the OPNsense port forward fields is supported. Everything else is
refused, and the backend fixes the rest (pass: Manual, no pool options, no reflection, no tags).
"""

import ipaddress
import re
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from app.changes.rule_schemas import _address, _is_ip, _port
from app.changes.schemas import RESERVED_NAMES, _valid_port

_IFACE = re.compile(r"^[a-z][a-z0-9_]{0,31}$")
_ALIAS = re.compile(r"^[A-Za-z_][A-Za-z0-9_]{0,31}$")

IpProtocol = Literal["inet", "inet6"]
Protocol = Literal["TCP", "UDP", "TCP/UDP"]


def _is_range(value: str) -> bool:
    return ":" in value


class ForwardProposal(BaseModel):
    model_config = ConfigDict(extra="forbid")

    enabled: bool = True
    interface: str = Field(min_length=1, max_length=32)
    ip_protocol: IpProtocol = "inet"
    protocol: Protocol = "TCP"
    source: str = Field(default="any", min_length=1, max_length=64)
    source_port: str = Field(default="", max_length=64)
    destination: str = Field(min_length=1, max_length=64)
    destination_port: str = Field(default="", max_length=64)
    target: str = Field(min_length=1, max_length=64)
    target_port: str = Field(default="", max_length=64)
    log: bool = False
    description: str = Field(default="", max_length=255)  # required; checked after stripping

    @field_validator("interface")
    @classmethod
    def _check_interface(cls, value: str) -> str:
        if not _IFACE.match(value):
            raise ValueError("Use the interface identifier (for example wan, lan, opt1)")
        return value

    @field_validator("source")
    @classmethod
    def _check_source(cls, value: str) -> str:
        return _address(value)

    @field_validator("source_port", "destination_port")
    @classmethod
    def _check_port(cls, value: str) -> str:
        return _port(value)

    @field_validator("target_port")
    @classmethod
    def _check_target_port(cls, value: str) -> str:
        item = _port(value)
        if _is_range(item):
            raise ValueError("The redirect port must be a single port or an alias name")
        return item

    @field_validator("description")
    @classmethod
    def _check_description(cls, value: str) -> str:
        if any(ord(ch) < 32 or ord(ch) == 127 for ch in value):
            raise ValueError("Description must not contain control characters")
        return value.strip()

    @model_validator(mode="after")
    def _check_combination(self) -> ForwardProposal:
        if not self.description:
            raise ValueError("A description is required; it identifies the forward")
        self.destination = self._check_destination(self.destination)
        self._check_target(self.target)
        for value in (self.source, self.destination, self.target):
            if _is_ip(value) and self._family(value) != self.ip_protocol:
                raise ValueError("Address does not match the selected IP version")
        for value in (self.source, self.destination):
            if "/" in value and self._family(value.split("/")[0]) != self.ip_protocol:
                raise ValueError("Network does not match the selected IP version")
        return self

    @property
    def interface_keyword(self) -> str:
        return f"{self.interface}ip"

    def _check_destination(self, value: str) -> str:
        item = value.strip()
        if item == self.interface_keyword:
            return item
        return _address(item)

    def _check_target(self, value: str) -> None:
        item = value.strip()
        if item == "any" or "/" in item:
            raise ValueError("The redirect target must be one IP address or an alias name")
        if _is_ip(item):
            return
        if _ALIAS.match(item) and item.lower() not in RESERVED_NAMES:
            return
        raise ValueError("The redirect target must be one IP address or an alias name")

    @staticmethod
    def _family(value: str) -> str:
        return "inet6" if ipaddress.ip_address(value).version == 6 else "inet"

    def alias_references(self) -> set[str]:
        """Names that must exist as aliases on the firewall."""
        found: set[str] = set()
        for value in (self.source, self.destination, self.target):
            if (
                value != "any"
                and value != self.interface_keyword
                and "/" not in value
                and not _is_ip(value)
            ):
                found.add(value)
        for value in (self.source_port, self.destination_port, self.target_port):
            if value and not _valid_port(value):
                found.add(value)
        return found

    def risk_reasons(self) -> list[str]:
        """Why this forward needs an admin approver and a typed confirmation."""
        reasons: list[str] = []
        if self.interface == "wan":
            reasons.append("exposes a host on the WAN interface")
        if self.source == "any" and (not self.destination_port or _is_range(self.destination_port)):
            reasons.append("accepts any source on an empty or ranged destination port")
        return reasons
