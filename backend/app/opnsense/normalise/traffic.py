"""Interface traffic counters (ADR-0007). Cumulative values; rates are computed by the browser."""

from typing import Any

from pydantic import BaseModel

MAX_INTERFACES = 64
_COUNTER_MAX = 2**64


class TrafficInterface(BaseModel):
    interface: str
    name: str | None = None
    in_bytes: int
    out_bytes: int
    in_packets: int
    out_packets: int


class TrafficResult(BaseModel):
    time: float | None = None
    interfaces: list[TrafficInterface] = []


def normalise_traffic(raw: Any) -> TrafficResult:
    """Tolerant mapping of `{time, interfaces: {key: {...}}}`. Interfaces without all four
    counters are skipped, so a bad shape gives fewer rows rather than wrong numbers."""
    if not isinstance(raw, dict):
        return TrafficResult()
    rows = raw.get("interfaces")
    if not isinstance(rows, dict):
        return TrafficResult()
    out: list[TrafficInterface] = []
    for key, row in list(rows.items())[:MAX_INTERFACES]:
        if not isinstance(key, str) or not isinstance(row, dict):
            continue
        counters = [
            _counter(row.get(f))
            for f in (
                "bytes received",
                "bytes transmitted",
                "packets received",
                "packets transmitted",
            )
        ]
        if any(c is None for c in counters):
            continue
        name = row.get("name")
        out.append(
            TrafficInterface(
                interface=key[:64],
                name=name[:64] if isinstance(name, str) and name else None,
                in_bytes=counters[0] or 0,
                out_bytes=counters[1] or 0,
                in_packets=counters[2] or 0,
                out_packets=counters[3] or 0,
            )
        )
    stamp = raw.get("time")
    time_value = (
        float(stamp) if isinstance(stamp, int | float) and not isinstance(stamp, bool) else None
    )
    return TrafficResult(time=time_value, interfaces=out)


def _counter(value: Any) -> int | None:
    if isinstance(value, bool):
        return None
    if isinstance(value, str) and value.isdigit():
        value = int(value)
    if isinstance(value, int) and 0 <= value < _COUNTER_MAX:
        return value
    return None
