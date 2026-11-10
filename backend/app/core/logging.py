"""structlog configuration with secret redaction."""

import re
import sys
from collections.abc import Mapping, MutableMapping
from typing import Any, TextIO

import structlog

REDACTED = "[REDACTED]"
_SENSITIVE_FRAGMENTS = (
    "password",
    "passwd",
    "secret",
    "token",
    "api_key",
    "apikey",
    "authorization",
    "cookie",
    "credential",
    "csrf",
)
_known_secrets: set[str] = set()


def register_secret(value: str) -> None:
    """Make sure this literal value is scrubbed from any log output (min length 8)."""
    if len(value) >= 8:
        _known_secrets.add(value)


def _is_sensitive_key(key: str) -> bool:
    lowered = key.lower()
    return lowered == "key" or any(f in lowered for f in _SENSITIVE_FRAGMENTS)


def _scrub_string(value: str) -> str:
    for secret in _known_secrets:
        value = value.replace(secret, REDACTED)
    return re.sub(r"(?i)(bearer|basic)\s+[A-Za-z0-9._~+/=-]+", r"\1 " + REDACTED, value)


def _scrub(value: Any, key: str | None = None) -> Any:
    if key is not None and _is_sensitive_key(key):
        return REDACTED
    if isinstance(value, Mapping):
        return {str(k): _scrub(v, str(k)) for k, v in value.items()}
    if isinstance(value, list | tuple | set):
        return [_scrub(v) for v in value]
    if isinstance(value, str):
        return _scrub_string(value)
    return value


def redact_processor(
    _logger: Any, _method: str, event_dict: MutableMapping[str, Any]
) -> Mapping[str, Any]:
    return {k: _scrub(v, k) for k, v in event_dict.items()}


def configure_logging(stream: TextIO | None = None) -> None:
    structlog.configure(
        processors=[
            structlog.contextvars.merge_contextvars,
            structlog.processors.add_log_level,
            structlog.processors.TimeStamper(fmt="iso", utc=True),
            structlog.processors.format_exc_info,
            redact_processor,
            structlog.processors.JSONRenderer(),
        ],
        wrapper_class=structlog.make_filtering_bound_logger(20),
        logger_factory=structlog.PrintLoggerFactory(file=stream or sys.stdout),
        cache_logger_on_first_use=False,
    )


def get_logger(name: str = "app") -> Any:
    return structlog.get_logger(name)
