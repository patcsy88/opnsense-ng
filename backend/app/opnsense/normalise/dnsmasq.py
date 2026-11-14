"""Dnsmasq static host entries (ADR-0017). MAC addresses are kept here and filtered by role in
the API layer, because only admin and network_admin may see them."""

from typing import Any

from pydantic import BaseModel

MAX_HOSTS = 1000


class HostInfo(BaseModel):
    uuid: str | None = None
    host: str | None = None
    domain: str | None = None
    ips: list[str] = []
    hwaddrs: list[str] = []
    cnames: list[str] = []
    ignore: bool = False
    description: str | None = None


class HostsResult(BaseModel):
    hosts: list[HostInfo] = []
    truncated: bool = False


def _text(value: Any, limit: int) -> str | None:
    if not isinstance(value, str) or not value.strip():
        return None
    return value.strip()[:limit]


def _items(value: Any, limit: int, count: int) -> list[str]:
    """OPNsense returns multi-value fields as a comma separated string."""
    if isinstance(value, list):
        parts = [v for v in value if isinstance(v, str)]
    elif isinstance(value, str):
        parts = value.split(",")
    else:
        return []
    return [p.strip()[:limit] for p in parts if p.strip()][:count]


def _flag(value: Any) -> bool:
    return value in (True, 1, "1", "true", "yes")


def normalise_hosts(raw: Any) -> HostsResult:
    """Tolerant mapping of `rows`. Rows without a uuid are skipped, because they cannot be
    changed or compared."""
    rows = raw.get("rows") if isinstance(raw, dict) else None
    if not isinstance(rows, list):
        return HostsResult()
    out: list[HostInfo] = []
    for row in rows[:MAX_HOSTS]:
        if not isinstance(row, dict):
            continue
        uuid = _text(row.get("uuid"), 64)
        if uuid is None:
            continue
        out.append(
            HostInfo(
                uuid=uuid,
                host=_text(row.get("host"), 255),
                domain=_text(row.get("domain"), 255),
                ips=_items(row.get("ip"), 64, 16),
                hwaddrs=[m.lower() for m in _items(row.get("hwaddr"), 17, 16)],
                cnames=_items(row.get("cnames"), 255, 32),
                ignore=_flag(row.get("ignore")),
                description=_text(row.get("descr"), 255),
            )
        )
    return HostsResult(hosts=out, truncated=len(rows) > MAX_HOSTS)


class DomainInfo(BaseModel):
    uuid: str | None = None
    domain: str | None = None
    server: str | None = None
    port: str | None = None
    description: str | None = None


class DomainsResult(BaseModel):
    domains: list[DomainInfo] = []
    truncated: bool = False


def normalise_domains(raw: Any) -> DomainsResult:
    """Tolerant mapping of `rows` for domain overrides. Rows without a uuid are skipped."""
    rows = raw.get("rows") if isinstance(raw, dict) else None
    if not isinstance(rows, list):
        return DomainsResult()
    out: list[DomainInfo] = []
    for row in rows[:MAX_HOSTS]:
        if not isinstance(row, dict):
            continue
        uuid = _text(row.get("uuid"), 64)
        if uuid is None:
            continue
        port = row.get("port")
        out.append(
            DomainInfo(
                uuid=uuid,
                domain=_text(row.get("domain"), 255),
                server=_text(row.get("ip"), 64),
                port=_text(str(port) if isinstance(port, int) else port, 5),
                description=_text(row.get("descr"), 255),
            )
        )
    return DomainsResult(domains=out, truncated=len(rows) > MAX_HOSTS)
