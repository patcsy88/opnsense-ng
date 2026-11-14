"""Local validation of proposed Unbound host overrides (ADR-0018, layer one).

Only A and AAAA records are supported. MX, TXT and aliases are out of scope. No wildcards.
"""

import ipaddress
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from app.changes.dnsmasq_schemas import _LABEL, BROAD_SUFFIXES, _ip, _name, domain_key, host_risk


def unbound_host_key(
    hostname: str | None, domain: str | None, rr: str | None
) -> tuple[str, str, str]:
    return ((hostname or "").lower(), (domain or "").lower().rstrip("."), (rr or "").upper())


class UnboundHostProposal(BaseModel):
    model_config = ConfigDict(extra="forbid")

    hostname: str = Field(min_length=1, max_length=63)
    domain: str = Field(min_length=1, max_length=253)
    rr: Literal["A", "AAAA"] = "A"
    server: str = Field(min_length=1, max_length=64)
    ttl: int | None = Field(default=None, ge=0, le=2147483647)
    description: str = Field(min_length=1, max_length=255)
    enabled: bool = True

    @field_validator("hostname")
    @classmethod
    def _hostname(cls, v: str) -> str:
        item = v.strip().lower()
        if not _LABEL.match(item):
            raise ValueError(
                "Host must be a single DNS label (letters, digits, hyphens; no wildcard)"
            )
        return item

    @field_validator("domain")
    @classmethod
    def _domain(cls, v: str) -> str:
        return _name(v, "Domain")

    @field_validator("server")
    @classmethod
    def _server(cls, v: str) -> str:
        return _ip(v)

    @field_validator("description")
    @classmethod
    def _description(cls, v: str) -> str:
        if any(ord(ch) < 32 or ord(ch) == 127 for ch in v):
            raise ValueError("Description must not contain control characters")
        item = v.strip()
        if not item:
            raise ValueError("A description is required; it identifies the entry")
        return item

    @model_validator(mode="after")
    def _family(self) -> UnboundHostProposal:
        version = ipaddress.ip_address(self.server).version
        if (self.rr == "A") != (version == 4):
            raise ValueError("The address must be IPv4 for an A record and IPv6 for AAAA")
        return self

    def risk_reasons(
        self,
        firewall_addresses: frozenset[str] = frozenset(),
        firewall_hostname: str | None = None,
    ) -> list[str]:
        return host_risk(
            host=self.hostname,
            ips=[self.server],
            ignore=False,
            firewall_addresses=firewall_addresses,
            firewall_hostname=firewall_hostname,
        )


def inside_forward(domain: str | None, forwards: list[str]) -> str | None:
    """The first forwarded domain that this domain equals or sits under."""
    name = domain_key(domain)
    for fwd in forwards:
        key = domain_key(fwd)
        if key and (name == key or name.endswith("." + key)):
            return key
    return None


class UnboundForwardProposal(BaseModel):
    """An Unbound domain forward: ask one DNS server for one domain (ADR-0018). TCP-upstream and
    forward-first stay at defaults. No wildcards, and never an empty or broad domain."""

    model_config = ConfigDict(extra="forbid")

    domain: str = Field(min_length=1, max_length=253)
    server: str = Field(min_length=1, max_length=64)
    port: int | None = Field(default=None, ge=1, le=65535)
    description: str = Field(min_length=1, max_length=255)
    enabled: bool = True

    @field_validator("domain")
    @classmethod
    def _domain(cls, v: str) -> str:
        item = _name(v, "Domain")
        if "." not in item:
            raise ValueError("Use a domain with at least two labels, such as corp.example")
        if item in BROAD_SUFFIXES:
            raise ValueError("That domain is too broad to forward")
        return item

    @field_validator("server")
    @classmethod
    def _server(cls, v: str) -> str:
        return _ip(v)

    @field_validator("description")
    @classmethod
    def _description(cls, v: str) -> str:
        if any(ord(ch) < 32 or ord(ch) == 127 for ch in v):
            raise ValueError("Description must not contain control characters")
        item = v.strip()
        if not item:
            raise ValueError("A description is required; it identifies the entry")
        return item

    def risk_reasons(self) -> list[str]:
        """Every forward is high risk: it decides where a whole domain is resolved."""
        where = f"{self.server}:{self.port}" if self.port else self.server
        return [f"sends all lookups for {self.domain} to the DNS server {where}"]
