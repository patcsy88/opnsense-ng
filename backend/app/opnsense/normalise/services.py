"""Service status list (Status: Services). Read-only; start/stop/restart are not supported."""

from typing import Any

from pydantic import BaseModel

MAX_SERVICES = 500


class ServiceInfo(BaseModel):
    id: str
    name: str
    description: str | None = None
    running: bool
    locked: bool


class ServicesResult(BaseModel):
    services: list[ServiceInfo] = []
    truncated: bool = False


def normalise_services(raw: Any) -> ServicesResult:
    """Tolerant mapping of `rows`. Rows without a name or a running flag are skipped, so a bad
    shape gives fewer rows rather than a wrong status."""
    rows = raw.get("rows") if isinstance(raw, dict) else None
    if not isinstance(rows, list):
        return ServicesResult()
    out: list[ServiceInfo] = []
    for row in rows[:MAX_SERVICES]:
        if not isinstance(row, dict):
            continue
        name = row.get("name")
        running = _flag(row.get("running"))
        if not isinstance(name, str) or not name or running is None:
            continue
        ident = row.get("id")
        description = row.get("description")
        out.append(
            ServiceInfo(
                id=(ident if isinstance(ident, str) and ident else name)[:128],
                name=name[:128],
                description=description[:255]
                if isinstance(description, str) and description
                else None,
                running=running,
                locked=_flag(row.get("locked")) is True,
            )
        )
    return ServicesResult(services=out, truncated=len(rows) > MAX_SERVICES)


def _flag(value: Any) -> bool | None:
    if isinstance(value, bool):
        return value
    if value in (0, 1, "0", "1"):
        return str(value) == "1"
    return None
