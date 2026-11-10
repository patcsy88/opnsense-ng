"""Map OPNsense system responses to our internal schemas."""

from typing import Any

from pydantic import BaseModel


class SystemStatus(BaseModel):
    hostname: str | None = None
    versions: list[str] = []
    updates: str | None = None
    server_time: str | None = None
    uptime: str | None = None


def normalise_system_status(information: Any, time_info: Any = None) -> SystemStatus:
    """Tolerant mapping: unexpected shapes yield empty fields instead of leaking raw JSON."""
    info = information if isinstance(information, dict) else {}
    versions = info.get("versions")
    t = time_info if isinstance(time_info, dict) else {}
    return SystemStatus(
        hostname=_str(info.get("name")),
        versions=[str(v) for v in versions] if isinstance(versions, list) else [],
        updates=_str(info.get("updates")),
        server_time=_str(t.get("datetime")),
        uptime=_str(t.get("uptime")),
    )


def _str(value: Any) -> str | None:
    return value if isinstance(value, str) else None
