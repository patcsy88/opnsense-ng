"""Local validation of proposed Dnsmasq static hosts (ADR-0017, layer one).

Only a narrow subset of the host fields is supported. Client id, lease time, tags, `local` and
comments are left at their defaults. Wildcard names are refused.
"""

import ipaddress
import re

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

_LABEL = re.compile(r"^[A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?$")
_MAC = re.compile(r"^[0-9a-f]{2}(:[0-9a-f]{2}){5}$")
LOCAL_NAMES = frozenset({"localhost"})


def _name(value: str, what: str) -> str:
    item = value.strip().rstrip(".").lower()
    if not item or len(item) > 253 or not all(_LABEL.match(p) for p in item.split(".")):
        raise ValueError(f"{what} is not a valid DNS name (no wildcards)")
    return item


def _mac(value: str) -> str:
    item = value.strip().lower().replace("-", ":")
    if not _MAC.match(item):
        raise ValueError("MAC addresses look like aa:bb:cc:dd:ee:ff")
    return item


def _ip(value: str) -> str:
    try:
        return str(ipaddress.ip_address(value.strip()))
    except ValueError:
        raise ValueError("Not a valid IP address") from None


def _unique(items: list[str]) -> list[str]:
    seen: list[str] = []
    for item in items:
        if item in seen:
            raise ValueError("Duplicate entries are not allowed")
        seen.append(item)
    return seen


def host_key(host: str | None, domain: str | None) -> tuple[str, str]:
    return ((host or "").lower(), (domain or "").lower())


def host_risk(
    *,
    host: str,
    ips: list[str],
    ignore: bool,
    firewall_addresses: frozenset[str] = frozenset(),
    firewall_hostname: str | None = None,
) -> list[str]:
    """ADR-0017 risk rules for a host entry. Also used on entries read back from the firewall."""
    reasons: list[str] = []
    if ignore:
        reasons.append("blocks this device from DHCP (ignore)")
    own = sorted(set(ips) & firewall_addresses)
    if own:
        reasons.append(f"uses the firewall's own address {own[0]}")
    names = LOCAL_NAMES | ({firewall_hostname.lower()} if firewall_hostname else set())
    if host.lower() in names:
        reasons.append(f"uses the name '{host.lower()}', which belongs to the firewall itself")
    return reasons


class HostProposal(BaseModel):
    model_config = ConfigDict(extra="forbid")

    host: str = Field(min_length=1, max_length=63)
    domain: str = Field(default="", max_length=253)
    ips: list[str] = Field(min_length=1, max_length=8)
    hwaddrs: list[str] = Field(default_factory=list, max_length=8)
    cnames: list[str] = Field(default_factory=list, max_length=16)
    ignore: bool = False
    description: str = Field(min_length=1, max_length=255)

    @field_validator("host")
    @classmethod
    def _host(cls, v: str) -> str:
        item = v.strip().lower()
        if not _LABEL.match(item):
            raise ValueError(
                "Host must be a single DNS label (letters, digits, hyphens; no wildcard)"
            )
        return item

    @field_validator("domain")
    @classmethod
    def _domain(cls, v: str) -> str:
        return _name(v, "Domain") if v.strip() else ""

    @field_validator("ips")
    @classmethod
    def _ips(cls, v: list[str]) -> list[str]:
        return _unique([_ip(i) for i in v])

    @field_validator("hwaddrs")
    @classmethod
    def _macs(cls, v: list[str]) -> list[str]:
        return _unique([_mac(m) for m in v])

    @field_validator("cnames")
    @classmethod
    def _cnames(cls, v: list[str]) -> list[str]:
        return _unique([_name(c, "Alias") for c in v])

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
    def _check(self) -> HostProposal:
        if self.ignore and not self.hwaddrs:
            raise ValueError("'Ignore' needs at least one MAC address to block")
        return self

    def risk_reasons(
        self,
        firewall_addresses: frozenset[str] = frozenset(),
        firewall_hostname: str | None = None,
    ) -> list[str]:
        return host_risk(
            host=self.host,
            ips=self.ips,
            ignore=self.ignore,
            firewall_addresses=firewall_addresses,
            firewall_hostname=firewall_hostname,
        )


# Overrides for these would redirect name resolution for huge parts of the internet. The list is
# deliberately short and static (no public suffix dependency); a single label is refused anyway.
BROAD_SUFFIXES = frozenset(
    {
        "co.uk", "org.uk", "ac.uk", "gov.uk", "com.au", "net.au", "org.au", "co.nz", "co.jp",
        "com.br", "co.in", "co.za", "com.cn", "com.mx", "in-addr.arpa", "ip6.arpa",
    }
)  # fmt: skip


def domain_key(domain: str | None) -> str:
    return (domain or "").lower().rstrip(".")


class DomainProposal(BaseModel):
    """A Dnsmasq domain override: ask one DNS server for one domain (ADR-0017). Source IP, ipset
    and sequence stay at defaults. No wildcards."""

    model_config = ConfigDict(extra="forbid")

    domain: str = Field(min_length=1, max_length=253)
    server: str = Field(min_length=1, max_length=64)
    port: int | None = Field(default=None, ge=1, le=65535)
    description: str = Field(min_length=1, max_length=255)

    @field_validator("domain")
    @classmethod
    def _domain(cls, v: str) -> str:
        item = _name(v, "Domain")
        if "." not in item:
            raise ValueError("Use a domain with at least two labels, such as corp.example")
        if item in BROAD_SUFFIXES:
            raise ValueError("That domain is too broad to override")
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
        """Every override is high risk: it decides where a whole domain is resolved."""
        where = f"{self.server}:{self.port}" if self.port else self.server
        return [f"sends all lookups for {self.domain} to the DNS server {where}"]
