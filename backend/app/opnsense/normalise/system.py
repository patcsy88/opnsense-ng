"""Map OPNsense system responses to our internal schemas."""

from typing import Any

from pydantic import BaseModel


class SystemStatus(BaseModel):
    hostname: str | None = None
    versions: list[str] = []
    updates: str | None = None
    server_time: str | None = None
    uptime: str | None = None
    load_average: str | None = None
    memory_total_bytes: int | None = None
    memory_used_bytes: int | None = None
    memory_used_percent: float | None = None
    cpu_used_percent: float | None = None
    disk_total_bytes: int | None = None
    disk_used_bytes: int | None = None
    disk_used_percent: float | None = None


def normalise_system_status(
    information: Any,
    time_info: Any = None,
    resources: Any = None,
    cpu_percent: float | None = None,
    disk: Any = None,
) -> SystemStatus:
    """Tolerant mapping: unexpected shapes yield empty fields instead of leaking raw JSON."""
    info = information if isinstance(information, dict) else {}
    versions = info.get("versions")
    t = time_info if isinstance(time_info, dict) else {}
    total, used = _memory(resources)
    disk_total, disk_used = _root_disk(disk)
    return SystemStatus(
        hostname=_str(info.get("name")),
        versions=[str(v) for v in versions] if isinstance(versions, list) else [],
        updates=_str(info.get("updates")),
        server_time=_str(t.get("datetime")),
        uptime=_str(t.get("uptime")),
        load_average=_load(t.get("loadavg")),
        memory_total_bytes=total,
        memory_used_bytes=used,
        memory_used_percent=round(used / total * 100, 1) if total and used is not None else None,
        cpu_used_percent=cpu_percent,
        disk_total_bytes=disk_total,
        disk_used_bytes=disk_used,
        disk_used_percent=(
            round(disk_used / disk_total * 100, 1) if disk_total and disk_used is not None else None
        ),
    )


def _root_disk(disk: Any) -> tuple[int | None, int | None]:
    """Total/used bytes of the root filesystem (mountpoint "/")."""
    devices = disk.get("devices") if isinstance(disk, dict) else None
    if not isinstance(devices, list):
        return None, None
    for device in devices:
        if isinstance(device, dict) and device.get("mountpoint") == "/":
            total, used = _int(device.get("total_bytes")), _int(device.get("used_bytes"))
            if not total or used is None or used > total:
                return None, None
            return total, used
    return None, None


def _memory(resources: Any) -> tuple[int | None, int | None]:
    memory = resources.get("memory") if isinstance(resources, dict) else None
    if not isinstance(memory, dict):
        return None, None
    total, used = _int(memory.get("total")), _int(memory.get("used"))
    if not total or used is None or used > total:
        return None, None
    return total, used


def _int(value: Any) -> int | None:
    # OPNsense reports "N/A" when a value is unavailable; bool is an int subclass, so exclude it.
    if isinstance(value, bool):
        return None
    if isinstance(value, int | float):
        return int(value) if value >= 0 else None
    if isinstance(value, str) and value.isdigit():
        return int(value)
    return None


def _load(value: Any) -> str | None:
    # "N/A" is what OPNsense sends when the load average cannot be read.
    return value if isinstance(value, str) and value != "N/A" else None


def _str(value: Any) -> str | None:
    return value if isinstance(value, str) else None


def normalise_cpu_events(events: Any) -> float | None:
    """Reduce SSE samples to a 0-100 CPU usage figure from the latest usable event.
    Accepts `total` (used %) or `idle`. The real payload is confirmed on the lab."""
    if not isinstance(events, list):
        return None
    for event in reversed(events):
        if not isinstance(event, dict):
            continue
        total = _percent(event.get("total"))
        if total is not None:
            return total
        idle = _percent(event.get("idle"))
        if idle is not None:
            return round(100 - idle, 1)
    return None


def _percent(value: Any) -> float | None:
    if isinstance(value, bool) or not isinstance(value, int | float | str):
        return None
    try:
        number = float(value)
    except ValueError:
        return None
    return round(number, 1) if 0 <= number <= 100 else None
