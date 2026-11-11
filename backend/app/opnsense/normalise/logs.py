"""Map the OPNsense firewall log (`diagnostics/firewall/log`) to our internal schema."""

from typing import Any

from pydantic import BaseModel

from app.opnsense.normalise.rules import _int, _text

MAX_LOG_ROWS = 200


class LogEntry(BaseModel):
    time: str | None = None
    action: str | None = None
    interface: str | None = None
    direction: str | None = None
    ip_version: int | None = None
    protocol: str | None = None
    source: str | None = None
    source_port: int | None = None
    destination: str | None = None
    destination_port: int | None = None
    rule: str | None = None
    reason: str | None = None


class LogResult(BaseModel):
    entries: list[LogEntry]
    truncated: bool = False


def normalise_log(raw: Any) -> LogResult:
    """Tolerant mapping of the record list (newest first). Only the fields shown in the UI are
    passed on; TCP internals, digests and raw lines are dropped. Output is capped."""
    rows = raw.get("rows") if isinstance(raw, dict) else raw
    if not isinstance(rows, list):
        return LogResult(entries=[])
    entries: list[LogEntry] = []
    for row in rows[:MAX_LOG_ROWS]:
        if not isinstance(row, dict):
            continue
        entries.append(
            LogEntry(
                time=_text(row.get("__timestamp__"), 40),
                action=_text(row.get("action"), 16),
                interface=_text(row.get("interface"), 32),
                direction=_text(row.get("dir"), 8),
                ip_version=_int(row.get("ipversion")),
                protocol=_text(row.get("protoname"), 32),
                source=_text(row.get("src"), 64),
                source_port=_int(row.get("srcport")),
                destination=_text(row.get("dst"), 64),
                destination_port=_int(row.get("dstport")),
                rule=_text(row.get("label"), 200),
                reason=_text(row.get("reason"), 32),
            )
        )
    return LogResult(entries=entries, truncated=len(rows) > MAX_LOG_ROWS)
