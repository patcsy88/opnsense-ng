"""WireGuard peers and tunnels as configured on the firewall (ADR-0019).

Built from a whitelist. Private keys are never read. A preshared key is reduced to a flag.
OPNsense calls peers "clients" and tunnels "servers".
"""

from typing import Any

from pydantic import BaseModel

from app.opnsense.normalise.dnsmasq import MAX_HOSTS, _flag, _items, _text


def _port(value: Any) -> str | None:
    text = str(value) if isinstance(value, int) and not isinstance(value, bool) else value
    return _text(text, 5)


class WireguardPeerInfo(BaseModel):
    uuid: str | None = None
    enabled: bool = True
    name: str | None = None
    pubkey: str | None = None
    tunneladdress: list[str] = []
    serveraddress: str | None = None
    serverport: str | None = None
    keepalive: str | None = None
    servers: list[str] = []
    has_psk: bool = False


class WireguardPeersResult(BaseModel):
    peers: list[WireguardPeerInfo] = []
    truncated: bool = False


def _uuid_list(value: Any) -> list[str]:
    """Multi-value fields come back as a comma string, a list, or a dict of option objects."""
    if isinstance(value, dict):
        value = [k for k, v in value.items() if isinstance(v, dict) and v.get("selected")]
    return _items(value, 64, 64)


def normalise_wireguard_peers(raw: Any) -> WireguardPeersResult:
    rows = raw.get("rows") if isinstance(raw, dict) else None
    if not isinstance(rows, list):
        return WireguardPeersResult()
    out: list[WireguardPeerInfo] = []
    for row in rows[:MAX_HOSTS]:
        if not isinstance(row, dict):
            continue
        uuid = _text(row.get("uuid"), 64)
        if uuid is None:
            continue
        out.append(
            WireguardPeerInfo(
                uuid=uuid,
                enabled=row.get("enabled") is None or _flag(row.get("enabled")),
                name=_text(row.get("name"), 128),
                pubkey=_text(row.get("pubkey"), 64),
                tunneladdress=_items(row.get("tunneladdress"), 64, 32),
                serveraddress=_text(row.get("serveraddress"), 255),
                serverport=_port(row.get("serverport")),
                keepalive=_port(row.get("keepalive")),
                servers=_uuid_list(row.get("servers")),
                has_psk=bool(_text(row.get("psk"), 64)),
            )
        )
    return WireguardPeersResult(peers=out, truncated=len(rows) > MAX_HOSTS)


class WireguardTunnelInfo(BaseModel):
    uuid: str | None = None
    enabled: bool = True
    name: str | None = None
    pubkey: str | None = None
    port: str | None = None
    tunneladdress: list[str] = []
    mtu: str | None = None
    disableroutes: bool = False
    peers: list[str] = []


class WireguardTunnelsResult(BaseModel):
    tunnels: list[WireguardTunnelInfo] = []
    truncated: bool = False


def normalise_wireguard_tunnels(raw: Any) -> WireguardTunnelsResult:
    rows = raw.get("rows") if isinstance(raw, dict) else None
    if not isinstance(rows, list):
        return WireguardTunnelsResult()
    out: list[WireguardTunnelInfo] = []
    for row in rows[:MAX_HOSTS]:
        if not isinstance(row, dict):
            continue
        uuid = _text(row.get("uuid"), 64)
        if uuid is None:
            continue
        out.append(
            WireguardTunnelInfo(
                uuid=uuid,
                enabled=row.get("enabled") is None or _flag(row.get("enabled")),
                name=_text(row.get("name"), 128),
                pubkey=_text(row.get("pubkey"), 64),
                port=_port(row.get("port")),
                tunneladdress=_items(row.get("tunneladdress"), 64, 32),
                mtu=_port(row.get("mtu")),
                disableroutes=_flag(row.get("disableroutes")),
                peers=_uuid_list(row.get("peers")),
            )
        )
    return WireguardTunnelsResult(tunnels=out, truncated=len(rows) > MAX_HOSTS)
