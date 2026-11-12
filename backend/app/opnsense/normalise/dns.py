"""Unbound DNS overview (ADR-0010). Whitelisted counters and top domains; no client data."""

from typing import Any

from pydantic import BaseModel

MAX_TOP = 10


class TopDomain(BaseModel):
    domain: str
    count: int
    blocklist: str | None = None


class DnsResult(BaseModel):
    stats_available: bool = False
    totals_available: bool = False
    queries: int | None = None
    cache_hits: int | None = None
    cache_misses: int | None = None
    hit_rate: float | None = None
    uptime_seconds: int | None = None
    logged_queries: int | None = None
    blocked: int | None = None
    blocked_percent: float | None = None
    blocklist_size: int | None = None
    top_queried: list[TopDomain] = []
    top_blocked: list[TopDomain] = []


def normalise_dns(stats_raw: Any, totals_raw: Any) -> DnsResult:
    """Tolerant mapping of the two Unbound responses. Missing parts stay unavailable, not zero."""
    result = DnsResult()
    data = stats_raw.get("data") if isinstance(stats_raw, dict) else None
    if isinstance(stats_raw, dict) and stats_raw.get("status") == "ok" and isinstance(data, dict):
        num = _node(_node(data, "total"), "num")
        queries = _int(num.get("queries"))
        hits = _int(num.get("cachehits"))
        if queries is not None:
            result.stats_available = True
            result.queries = queries
            result.cache_hits = hits
            result.cache_misses = _int(num.get("cachemiss"))
            if hits is not None and queries > 0:
                result.hit_rate = round(min(hits, queries) * 100 / queries, 1)
            uptime = _float(_node(data, "time").get("up"))
            result.uptime_seconds = int(uptime) if uptime is not None else None

    if isinstance(totals_raw, dict):
        logged = _int(totals_raw.get("total"))
        if logged:
            result.totals_available = True
            result.logged_queries = logged
            blocked = totals_raw.get("blocked")
            if isinstance(blocked, dict):
                result.blocked = _int(blocked.get("total"))
                result.blocked_percent = _round(blocked.get("pcnt"))
            result.blocklist_size = _int(totals_raw.get("blocklist_size"))
            result.top_queried = _top(totals_raw.get("top"), with_blocklist=False)
            result.top_blocked = _top(totals_raw.get("top_blocked"), with_blocklist=True)
    return result


def _node(value: Any, key: str) -> dict[str, Any]:
    child = value.get(key) if isinstance(value, dict) else None
    return child if isinstance(child, dict) else {}


def _top(value: Any, *, with_blocklist: bool) -> list[TopDomain]:
    if not isinstance(value, dict):
        return []
    out: list[TopDomain] = []
    for domain, row in value.items():
        count = _int(row.get("total")) if isinstance(row, dict) else None
        if not isinstance(domain, str) or not domain or count is None:
            continue
        blocklist = row.get("blocklist") if with_blocklist and isinstance(row, dict) else None
        out.append(
            TopDomain(
                domain=domain[:253],
                count=count,
                blocklist=blocklist[:64] if isinstance(blocklist, str) and blocklist else None,
            )
        )
    out.sort(key=lambda d: d.count, reverse=True)
    return out[:MAX_TOP]


def _int(value: Any) -> int | None:
    if isinstance(value, bool):
        return None
    if isinstance(value, int):
        return value if value >= 0 else None
    if isinstance(value, str) and value.isdigit():
        return int(value)
    return None


def _float(value: Any) -> float | None:
    if isinstance(value, bool):
        return None
    if isinstance(value, (int, float)):
        return float(value) if value >= 0 else None
    if isinstance(value, str):
        try:
            number = float(value)
        except ValueError:
            return None
        return number if number >= 0 else None
    return None


def _round(value: Any) -> float | None:
    number = _float(value)
    return round(number, 1) if number is not None else None
