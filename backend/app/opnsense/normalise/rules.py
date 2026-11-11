"""Map the OPNsense firewall rule search result to our internal schema."""

from typing import Any

from pydantic import BaseModel

MAX_RULES = 2000
MAX_TEXT = 500


class RuleInfo(BaseModel):
    uuid: str | None = None
    enabled: bool | None = None
    action: str | None = None
    interface: str | None = None
    direction: str | None = None
    ip_protocol: str | None = None
    protocol: str | None = None
    source: str | None = None
    source_port: str | None = None
    destination: str | None = None
    destination_port: str | None = None
    description: str | None = None
    log: bool | None = None
    sequence: int | None = None


class RulesResult(BaseModel):
    rules: list[RuleInfo]
    truncated: bool = False


def normalise_rules(raw: Any) -> RulesResult:
    """Tolerant mapping of the `rows` list. OPNsense sends flags as "0"/"1" strings; unexpected
    shapes yield empty fields. Categories, statistics and internal metadata are not passed on."""
    rows = raw.get("rows") if isinstance(raw, dict) else None
    if not isinstance(rows, list):
        return RulesResult(rules=[])
    rules: list[RuleInfo] = []
    for row in rows[:MAX_RULES]:
        if not isinstance(row, dict):
            continue
        rules.append(
            RuleInfo(
                uuid=_text(row.get("uuid"), 64),
                enabled=_flag(row.get("enabled")),
                action=_text(row.get("action"), 32),
                interface=_text(row.get("interface")),
                direction=_text(row.get("direction"), 32),
                ip_protocol=_text(row.get("ipprotocol"), 32),
                protocol=_text(row.get("protocol"), 32),
                source=_text(row.get("source_net")),
                source_port=_text(row.get("source_port")),
                destination=_text(row.get("destination_net")),
                destination_port=_text(row.get("destination_port")),
                description=_text(row.get("description")),
                log=_flag(row.get("log")),
                sequence=_int(row.get("sequence")),
            )
        )
    return RulesResult(rules=rules, truncated=len(rows) > MAX_RULES)


def _text(value: Any, limit: int = MAX_TEXT) -> str | None:
    return value[:limit] if isinstance(value, str) and value else None


def _flag(value: Any) -> bool | None:
    if isinstance(value, bool):
        return value
    if value in ("1", 1):
        return True
    if value in ("0", 0, ""):
        return False
    return None


def _int(value: Any) -> int | None:
    if isinstance(value, bool):
        return None
    if isinstance(value, int):
        return value
    if isinstance(value, str) and value.isdigit():
        return int(value)
    return None
