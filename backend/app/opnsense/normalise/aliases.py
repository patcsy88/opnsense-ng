"""Map the OPNsense alias search result to our internal schema."""

import re
from typing import Any

from pydantic import BaseModel

MAX_ALIASES = 1000
MAX_CONTENT_ITEMS = 200
MAX_TEXT = 500
_SEPARATORS = re.compile(r"[,\r\n]+")


class AliasInfo(BaseModel):
    uuid: str | None = None
    name: str | None = None
    type: str | None = None
    enabled: bool | None = None
    description: str | None = None
    content: list[str] = []
    content_truncated: bool = False


class AliasesResult(BaseModel):
    aliases: list[AliasInfo]
    truncated: bool = False


def normalise_aliases(raw: Any) -> AliasesResult:
    """Tolerant mapping of the `rows` list. `content` arrives as one string, separated by
    newlines (commas are tolerated). Categories and runtime counters are not passed on."""
    rows = raw.get("rows") if isinstance(raw, dict) else None
    if not isinstance(rows, list):
        return AliasesResult(aliases=[])
    aliases: list[AliasInfo] = []
    for row in rows[:MAX_ALIASES]:
        if not isinstance(row, dict):
            continue
        items = _split(row.get("content"))
        aliases.append(
            AliasInfo(
                uuid=_text(row.get("uuid"), 64),
                name=_text(row.get("name"), 128),
                type=_text(row.get("type"), 32),
                enabled=_flag(row.get("enabled")),
                description=_text(row.get("description")),
                content=items[:MAX_CONTENT_ITEMS],
                content_truncated=len(items) > MAX_CONTENT_ITEMS,
            )
        )
    return AliasesResult(aliases=aliases, truncated=len(rows) > MAX_ALIASES)


def _text(value: Any, limit: int = MAX_TEXT) -> str | None:
    return value[:limit] if isinstance(value, str) and value else None


def _split(value: Any) -> list[str]:
    if not isinstance(value, str):
        return []
    return [part.strip()[:MAX_TEXT] for part in _SEPARATORS.split(value) if part.strip()]


def _flag(value: Any) -> bool | None:
    if isinstance(value, bool):
        return value
    if value in ("1", 1):
        return True
    if value in ("0", 0, ""):
        return False
    return None
