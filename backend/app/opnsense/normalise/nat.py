"""Map the OPNsense NAT search results (port forwards and outbound NAT) to our schema."""

from typing import Any, Literal

from pydantic import BaseModel

from app.opnsense.normalise.rules import MAX_RULES, _flag, _int, _text

NatKind = Literal["port_forward", "outbound"]


class NatRule(BaseModel):
    uuid: str | None = None
    enabled: bool | None = None
    # Exception rules: port forward "no redirect", outbound "do not NAT".
    excluded: bool | None = None
    interface: str | None = None
    ip_protocol: str | None = None
    protocol: str | None = None
    source: str | None = None
    source_port: str | None = None
    destination: str | None = None
    destination_port: str | None = None
    target: str | None = None
    target_port: str | None = None
    description: str | None = None
    log: bool | None = None
    sequence: int | None = None
    automatic: bool = False


class NatResult(BaseModel):
    rules: list[NatRule]
    truncated: bool = False


def normalise_nat(raw: Any, kind: NatKind) -> NatResult:
    """Tolerant mapping of the `rows` list. Port forwards use dotted field names and a
    `disabled` flag; outbound rules use `enabled`. Categories, statistics and audit metadata are
    not passed on."""
    rows = raw.get("rows") if isinstance(raw, dict) else None
    if not isinstance(rows, list):
        return NatResult(rules=[])
    rules: list[NatRule] = []
    for row in rows[:MAX_RULES]:
        if not isinstance(row, dict):
            continue
        if kind == "port_forward":
            disabled = _flag(row.get("disabled"))
            rules.append(
                NatRule(
                    uuid=_text(row.get("uuid"), 64),
                    enabled=None if disabled is None else not disabled,
                    excluded=_flag(row.get("nordr")),
                    interface=_text(row.get("interface")),
                    ip_protocol=_text(row.get("ipprotocol"), 32),
                    protocol=_text(row.get("protocol"), 32),
                    source=_text(row.get("source.network")),
                    source_port=_text(row.get("source.port")),
                    destination=_text(row.get("destination.network")),
                    destination_port=_text(row.get("destination.port")),
                    target=_text(row.get("target")),
                    target_port=_text(row.get("local-port")),
                    description=_text(row.get("descr")),
                    log=_flag(row.get("log")),
                    sequence=_int(row.get("sequence")),
                    automatic=_flag(row.get("is_automatic")) is True,
                )
            )
        else:
            rules.append(
                NatRule(
                    uuid=_text(row.get("uuid"), 64),
                    enabled=_flag(row.get("enabled")),
                    excluded=_flag(row.get("nonat")),
                    interface=_text(row.get("interface")),
                    ip_protocol=_text(row.get("ipprotocol"), 32),
                    protocol=_text(row.get("protocol"), 32),
                    source=_text(row.get("source_net")),
                    source_port=_text(row.get("source_port")),
                    destination=_text(row.get("destination_net")),
                    destination_port=_text(row.get("destination_port")),
                    target=_text(row.get("target")),
                    target_port=_text(row.get("target_port")),
                    description=_text(row.get("description")),
                    log=_flag(row.get("log")),
                    sequence=_int(row.get("sequence")),
                    automatic=_flag(row.get("is_automatic")) is True,
                )
            )
    return NatResult(rules=rules, truncated=len(rows) > MAX_RULES)
