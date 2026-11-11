"""Map the OPNsense firewall log (`diagnostics/firewall/log`) to our internal schema."""

from collections import Counter
from typing import Any

from pydantic import BaseModel

from app.opnsense.normalise.rules import _int, _text

MAX_LOG_ROWS = 200
MAX_SUMMARY_ROWS = 1000
TOP_N = 10


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


class TopItem(BaseModel):
    label: str
    count: int


class LogSummary(BaseModel):
    """Counts over the records the firewall returned (not only the ones shown)."""

    records: int = 0
    blocked: int = 0
    passed: int = 0
    newest: str | None = None
    oldest: str | None = None
    top_blocked_sources: list[TopItem] = []
    top_blocked_destinations: list[TopItem] = []
    top_blocked_ports: list[TopItem] = []
    blocked_by_interface: list[TopItem] = []
    blocked_by_rule: list[TopItem] = []


def _top(counter: Counter[str]) -> list[TopItem]:
    return [TopItem(label=k, count=v) for k, v in counter.most_common(TOP_N)]


def summarise_log(raw: Any) -> LogSummary:
    rows = raw.get("rows") if isinstance(raw, dict) else raw
    if not isinstance(rows, list):
        return LogSummary()
    sources: Counter[str] = Counter()
    destinations: Counter[str] = Counter()
    ports: Counter[str] = Counter()
    interfaces: Counter[str] = Counter()
    rules: Counter[str] = Counter()
    blocked = passed = records = 0
    times: list[str] = []
    for row in rows[:MAX_SUMMARY_ROWS]:
        if not isinstance(row, dict):
            continue
        records += 1
        stamp = _text(row.get("__timestamp__"), 40)
        if stamp:
            times.append(stamp)
        action = row.get("action")
        if action == "pass":
            passed += 1
        if action != "block":
            continue
        blocked += 1
        if src := _text(row.get("src"), 64):
            sources[src] += 1
        if dst := _text(row.get("dst"), 64):
            destinations[dst] += 1
        port = _int(row.get("dstport"))
        if port is not None:
            proto = _text(row.get("protoname"), 16) or "?"
            ports[f"{port}/{proto}"] += 1
        interfaces[_text(row.get("interface"), 32) or "unknown"] += 1
        rules[_text(row.get("label"), 200) or "no rule label"] += 1
    return LogSummary(
        records=records,
        blocked=blocked,
        passed=passed,
        newest=times[0] if times else None,
        oldest=times[-1] if times else None,
        top_blocked_sources=_top(sources),
        top_blocked_destinations=_top(destinations),
        top_blocked_ports=_top(ports),
        blocked_by_interface=_top(interfaces),
        blocked_by_rule=_top(rules),
    )
