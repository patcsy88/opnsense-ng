"""Map the OPNsense firewall log (`diagnostics/firewall/log`) to our internal schema."""

import re
from collections import Counter
from typing import Any

from pydantic import BaseModel

from app.geoip import CountryLookup
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
    source_country: str | None = None
    source_port: int | None = None
    destination: str | None = None
    destination_port: int | None = None
    rule: str | None = None
    reason: str | None = None


class LogResult(BaseModel):
    entries: list[LogEntry]
    truncated: bool = False


_DIGEST = re.compile(r"^[0-9a-f]{32}$")


def log_cursor(raw: Any) -> str | None:
    """Digest of the newest record, used as an opaque position marker for the live view."""
    rows = raw.get("rows") if isinstance(raw, dict) else raw
    if isinstance(rows, list) and rows and isinstance(rows[0], dict):
        digest = rows[0].get("__digest__")
        if isinstance(digest, str) and _DIGEST.match(digest):
            return digest
    return None


def normalise_log(
    raw: Any, after: str | None = None, country: CountryLookup | None = None
) -> LogResult:
    """Tolerant mapping of the record list (newest first). Only the fields shown in the UI are
    passed on; TCP internals, digests and raw lines are dropped. Output is capped. `after` is a
    digest: records from that one onwards (older) are cut off."""
    rows = raw.get("rows") if isinstance(raw, dict) else raw
    if not isinstance(rows, list):
        return LogResult(entries=[])
    if after is not None:
        # The firewall includes the marker record itself; stop there.
        trimmed: list[Any] = []
        for row in rows:
            if isinstance(row, dict) and row.get("__digest__") == after:
                break
            trimmed.append(row)
        rows = trimmed
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
                source=(src := _text(row.get("src"), 64)),
                source_country=country(src) if country and src else None,
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
    country: str | None = None


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
    blocked_by_country: list[TopItem] = []


def _top(counter: Counter[str]) -> list[TopItem]:
    return [TopItem(label=k, count=v) for k, v in counter.most_common(TOP_N)]


def summarise_log(raw: Any, country: CountryLookup | None = None) -> LogSummary:
    rows = raw.get("rows") if isinstance(raw, dict) else raw
    if not isinstance(rows, list):
        return LogSummary()
    sources: Counter[str] = Counter()
    destinations: Counter[str] = Counter()
    ports: Counter[str] = Counter()
    interfaces: Counter[str] = Counter()
    rules: Counter[str] = Counter()
    countries: Counter[str] = Counter()
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
            if country and (code := country(src)):
                countries[code] += 1
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
        top_blocked_sources=[
            TopItem(label=k, count=v, country=country(k) if country else None)
            for k, v in sources.most_common(TOP_N)
        ],
        top_blocked_destinations=_top(destinations),
        top_blocked_ports=_top(ports),
        blocked_by_interface=_top(interfaces),
        blocked_by_rule=_top(rules),
        blocked_by_country=_top(countries),
    )
