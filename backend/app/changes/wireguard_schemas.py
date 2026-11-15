"""Local validation of proposed WireGuard peers (ADR-0019, layer one).

A peer is identified by its public key. This app never accepts, stores or returns a private or
preshared key. Anything beyond the listed fields is refused.
"""

import base64
import binascii
import ipaddress
import re
import uuid as uuidlib
from collections.abc import Iterable
from typing import Any

from pydantic import BaseModel, ConfigDict, Field, field_validator

_NAME = re.compile(r"^[A-Za-z0-9_.-]{1,64}$")
_HOST = re.compile(
    r"^[A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?(\.[A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?)*$"
)


def valid_pubkey(value: str) -> str:
    item = value.strip()
    if len(item) != 44 or not item.endswith("="):
        raise ValueError("A WireGuard public key is 44 characters of base64")
    try:
        raw = base64.b64decode(item, validate=True)
    except binascii.Error:
        raise ValueError("A WireGuard public key is 44 characters of base64") from None
    if len(raw) != 32:
        raise ValueError("A WireGuard public key is 44 characters of base64")
    return item


def host_address(value: str) -> str:
    """One host address with a full-length prefix, e.g. 10.10.0.5/32 or fd00::5/128."""
    item = value.strip()
    try:
        iface = ipaddress.ip_interface(item if "/" in item else item + "/32")
        if "/" not in item and iface.version == 6:
            iface = ipaddress.ip_interface(item + "/128")
    except ValueError:
        raise ValueError("Not a valid address; use a single host such as 10.10.0.5/32") from None
    if iface.network.prefixlen != iface.max_prefixlen:
        raise ValueError("A peer address must be a single host (/32 for IPv4, /128 for IPv6)")
    return str(iface)


def address_set(values: Iterable[str]) -> set[str]:
    out: set[str] = set()
    for v in values:
        try:
            out.add(str(ipaddress.ip_interface(v).ip))
        except ValueError:
            continue
    return out


def peer_conflict(proposed: dict[str, Any], peers: list[Any], own: str | None) -> str | None:
    """Duplicate public key, or an address already used by another peer."""
    key = proposed.get("pubkey")
    mine = address_set(proposed.get("tunneladdress") or [])
    for p in peers:
        if p.uuid == own:
            continue
        if key and p.pubkey == key:
            return "A peer with this public key already exists"
        if mine & address_set(p.tunneladdress):
            return "Another peer already uses one of these tunnel addresses"
    return None


def outside_tunnels(addresses: list[str], tunnels: list[Any], server_ids: list[str]) -> str | None:
    """Every peer address must sit inside a network of at least one chosen tunnel."""
    chosen = [t for t in tunnels if t.uuid in server_ids]
    nets = []
    for t in chosen:
        for a in t.tunneladdress:
            try:
                nets.append(ipaddress.ip_interface(a).network)
            except ValueError:
                continue
    for a in addresses:
        ip = ipaddress.ip_interface(a).ip
        if not any(ip.version == n.version and ip in n for n in nets):
            return f"{a} is not inside the network of the chosen tunnel"
    return None


class WireguardPeerProposal(BaseModel):
    model_config = ConfigDict(extra="forbid")

    name: str = Field(min_length=1, max_length=64)
    pubkey: str = Field(min_length=44, max_length=44)
    tunneladdress: list[str] = Field(min_length=1, max_length=8)
    servers: list[str] = Field(min_length=1, max_length=16)
    serveraddress: str | None = Field(default=None, max_length=253)
    serverport: int | None = Field(default=None, ge=1, le=65535)
    keepalive: int | None = Field(default=None, ge=0, le=65535)
    enabled: bool = True

    @field_validator("name")
    @classmethod
    def _name(cls, v: str) -> str:
        item = v.strip()
        if not _NAME.match(item):
            raise ValueError("Name may use letters, digits, dot, dash and underscore (max 64)")
        return item

    @field_validator("pubkey")
    @classmethod
    def _pubkey(cls, v: str) -> str:
        return valid_pubkey(v)

    @field_validator("tunneladdress")
    @classmethod
    def _addresses(cls, v: list[str]) -> list[str]:
        out = [host_address(a) for a in v]
        if len(set(out)) != len(out):
            raise ValueError("Duplicate addresses are not allowed")
        return out

    @field_validator("servers")
    @classmethod
    def _servers(cls, v: list[str]) -> list[str]:
        out: list[str] = []
        for item in v:
            try:
                out.append(str(uuidlib.UUID(item.strip())))
            except ValueError:
                raise ValueError("Tunnels are chosen by id from the list") from None
        if len(set(out)) != len(out):
            raise ValueError("Duplicate tunnels are not allowed")
        return out

    @field_validator("serveraddress")
    @classmethod
    def _endpoint(cls, v: str | None) -> str | None:
        if v is None or not v.strip():
            return None
        item = v.strip().rstrip(".")
        try:
            return str(ipaddress.ip_address(item))
        except ValueError:
            pass
        if not _HOST.match(item):
            raise ValueError("Endpoint must be an IP address or a host name")
        return item.lower()

    def risk_changes(self, current: Any) -> list[str]:
        """High-risk differences from the peer that is on the firewall now."""
        reasons: list[str] = []
        if current is None:
            return reasons
        if self.pubkey != current.pubkey:
            reasons.append("changes the public key, which moves this access to another key")
        if address_set(self.tunneladdress) != address_set(current.tunneladdress):
            reasons.append("changes the tunnel address")
        if set(self.servers) != set(current.servers):
            reasons.append("changes which tunnels the peer belongs to")
        return reasons


def tunnel_conflict(proposed: dict[str, Any], tunnels: list[Any], own: str | None) -> str | None:
    """Duplicate name or port, or a tunnel network that overlaps another tunnel's."""
    nets = []
    for a in proposed.get("tunneladdress") or []:
        try:
            nets.append(ipaddress.ip_interface(a).network)
        except ValueError:
            continue
    for t in tunnels:
        if t.uuid == own:
            continue
        if (t.name or "").lower() == str(proposed.get("name", "")).lower():
            return "A tunnel with this name already exists"
        if t.port and str(proposed.get("port")) == t.port:
            return "Another tunnel already listens on this port"
        for a in t.tunneladdress:
            try:
                other = ipaddress.ip_interface(a).network
            except ValueError:
                continue
            if any(n.version == other.version and n.overlaps(other) for n in nets):
                return "This tunnel network overlaps another tunnel's network"
    return None


class WireguardTunnelProposal(BaseModel):
    """A tunnel without any key. The firewall makes the private key itself on creation and this
    app never reads, sends or stores it."""

    model_config = ConfigDict(extra="forbid")

    name: str = Field(min_length=1, max_length=64)
    port: int = Field(ge=1, le=65535)
    tunneladdress: list[str] = Field(min_length=1, max_length=8)
    mtu: int | None = Field(default=None, ge=576, le=9000)
    disableroutes: bool = False
    peers: list[str] = Field(default_factory=list, max_length=256)
    enabled: bool = True

    @field_validator("name")
    @classmethod
    def _name(cls, v: str) -> str:
        item = v.strip()
        if not _NAME.match(item):
            raise ValueError("Name may use letters, digits, dot, dash and underscore (max 64)")
        return item

    @field_validator("tunneladdress")
    @classmethod
    def _addresses(cls, v: list[str]) -> list[str]:
        out: list[str] = []
        for item in v:
            try:
                iface = ipaddress.ip_interface(item.strip())
            except ValueError:
                raise ValueError("Use an address with a prefix, such as 10.10.0.1/24") from None
            if "/" not in item or iface.network.prefixlen == iface.max_prefixlen:
                raise ValueError("A tunnel address needs a network prefix, such as 10.10.0.1/24")
            out.append(str(iface))
        if len(set(out)) != len(out):
            raise ValueError("Duplicate addresses are not allowed")
        return out

    @field_validator("peers")
    @classmethod
    def _peers(cls, v: list[str]) -> list[str]:
        out: list[str] = []
        for item in v:
            try:
                out.append(str(uuidlib.UUID(item.strip())))
            except ValueError:
                raise ValueError("Peers are chosen by id from the list") from None
        if len(set(out)) != len(out):
            raise ValueError("Duplicate peers are not allowed")
        return out
