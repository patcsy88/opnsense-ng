"""Unbound host overrides (ADR-0018). Only A and AAAA records are editable here; MX and TXT hosts
are listed but flagged as not editable. Aliases are returned inside `_children` and ignored."""

from typing import Any

from pydantic import BaseModel, computed_field

from app.opnsense.normalise.dnsmasq import MAX_HOSTS, _flag, _text

EDITABLE_RR = ("A", "AAAA")


class UnboundHostInfo(BaseModel):
    uuid: str | None = None
    enabled: bool = True
    hostname: str | None = None
    domain: str | None = None
    rr: str | None = None
    server: str | None = None
    ttl: str | None = None
    description: str | None = None

    @computed_field  # type: ignore[prop-decorator]
    @property
    def editable(self) -> bool:
        return self.rr in EDITABLE_RR


class UnboundHostsResult(BaseModel):
    hosts: list[UnboundHostInfo] = []
    truncated: bool = False


def normalise_unbound_hosts(raw: Any) -> UnboundHostsResult:
    """Tolerant mapping of `rows`. Rows without a uuid, and alias rows, are skipped."""
    rows = raw.get("rows") if isinstance(raw, dict) else None
    if not isinstance(rows, list):
        return UnboundHostsResult()
    out: list[UnboundHostInfo] = []
    for row in rows[:MAX_HOSTS]:
        if not isinstance(row, dict) or _flag(row.get("isAlias")):
            continue
        uuid = _text(row.get("uuid"), 64)
        if uuid is None:
            continue
        ttl = row.get("ttl")
        rr = _text(row.get("rr"), 8)
        out.append(
            UnboundHostInfo(
                uuid=uuid,
                enabled=row.get("enabled") is None or _flag(row.get("enabled")),
                hostname=_text(row.get("hostname"), 255),
                domain=_text(row.get("domain"), 255),
                rr=rr.upper() if rr else None,
                server=_text(row.get("server"), 64),
                ttl=_text(str(ttl) if isinstance(ttl, int) else ttl, 10),
                description=_text(row.get("description"), 255),
            )
        )
    return UnboundHostsResult(hosts=out, truncated=len(rows) > MAX_HOSTS)
