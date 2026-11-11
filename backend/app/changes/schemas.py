"""Local validation of proposed alias changes (ADR-0005, layer one).

OPNsense validates again when the change is applied; these checks catch the common mistakes
early and bound what can be stored. Only host, network and port aliases are supported.
"""

import ipaddress
import re
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

MAX_CONTENT_ITEMS = 200
MAX_ITEM_LENGTH = 253
_NAME = re.compile(r"^[A-Za-z_][A-Za-z0-9_]{0,31}$")
_LABEL = re.compile(r"^[A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?$")
RESERVED_NAMES = frozenset(
    {
        "all",
        "any",
        "block",
        "drop",
        "in",
        "inet",
        "inet6",
        "no",
        "out",
        "pass",
        "port",
        "quick",
        "reject",
        "self",
        "to",
        "from",
        "table",
    }
)

AliasType = Literal["host", "network", "port"]


def _valid_host(item: str) -> bool:
    try:
        ipaddress.ip_address(item)
    except ValueError:
        pass
    else:
        return True
    if len(item) > MAX_ITEM_LENGTH or item.isdigit():
        return False
    return all(_LABEL.match(label) for label in item.rstrip(".").split("."))


def _valid_network(item: str) -> bool:
    try:
        ipaddress.ip_network(item, strict=True)
    except ValueError:
        return False
    return "/" in item


def _valid_port(item: str) -> bool:
    parts = item.split(":")
    if len(parts) > 2 or not all(p.isdigit() and p.isascii() for p in parts):
        return False
    numbers = [int(p) for p in parts]
    return all(1 <= n <= 65535 for n in numbers) and numbers == sorted(numbers)


_CHECKS = {"host": _valid_host, "network": _valid_network, "port": _valid_port}


class AliasProposal(BaseModel):
    model_config = ConfigDict(extra="forbid")

    name: str = Field(min_length=1, max_length=32)
    type: AliasType
    content: list[str] = Field(min_length=1, max_length=MAX_CONTENT_ITEMS)
    description: str = Field(default="", max_length=255)
    enabled: bool = True

    @field_validator("name")
    @classmethod
    def _check_name(cls, value: str) -> str:
        if not _NAME.match(value):
            raise ValueError(
                "Name must start with a letter or underscore and use only letters, digits "
                "and underscores (max 32)"
            )
        if value.lower() in RESERVED_NAMES:
            raise ValueError("This name is reserved")
        return value

    @field_validator("description")
    @classmethod
    def _check_description(cls, value: str) -> str:
        if any(ord(ch) < 32 or ord(ch) == 127 for ch in value):
            raise ValueError("Description must not contain control characters")
        return value.strip()

    @model_validator(mode="after")
    def _check_content(self) -> AliasProposal:
        check = _CHECKS[self.type]
        cleaned: list[str] = []
        for raw in self.content:
            item = raw.strip()
            if not item or len(item) > MAX_ITEM_LENGTH:
                raise ValueError("Content entries must be 1-253 characters")
            if not check(item):
                raise ValueError(f"Entry is not a valid {self.type} value")
            if item not in cleaned:
                cleaned.append(item)
        self.content = cleaned
        return self
