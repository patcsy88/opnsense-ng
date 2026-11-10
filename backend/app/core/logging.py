"""structlog configuration with secret redaction."""

import logging
import re
import sys
from collections import OrderedDict
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
MAX_KNOWN_SECRETS = 1000
# Insertion-ordered and bounded: the oldest registrations are dropped first, so the set (and
# the per-message scrubbing cost) cannot grow without limit as firewalls/keys are rotated.
_known_secrets: OrderedDict[str, None] = OrderedDict()


def register_secret(value: str) -> None:
    """Make sure this literal value is scrubbed from any log output (min length 8)."""
    if len(value) < 8:
        return
    _known_secrets.pop(value, None)
    _known_secrets[value] = None
    while len(_known_secrets) > MAX_KNOWN_SECRETS:
        _known_secrets.popitem(last=False)


def _is_sensitive_key(key: str) -> bool:
    lowered = key.lower()
    return lowered == "key" or any(f in lowered for f in _SENSITIVE_FRAGMENTS)


def _scrub_string(value: str) -> str:
    for secret in tuple(_known_secrets):
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


class RedactingFilter(logging.Filter):
    """Scrub stdlib log records (uvicorn, sqlalchemy, httpx, ...) with the same rules."""

    def filter(self, record: logging.LogRecord) -> bool:
        try:
            message = record.getMessage()
        except Exception:
            message = str(record.msg)
        record.msg = _scrub_string(message)
        record.args = None
        if record.exc_info:
            record.exc_text = _scrub_string(logging.Formatter().formatException(record.exc_info))
            record.exc_info = None
        return True


_STDLIB_LOGGERS = ("", "uvicorn", "uvicorn.error", "uvicorn.access", "httpx", "httpcore")


def _install_stdlib_redaction() -> None:
    redactor = RedactingFilter()
    for name in _STDLIB_LOGGERS:
        logger = logging.getLogger(name)
        if not any(isinstance(f, RedactingFilter) for f in logger.filters):
            logger.addFilter(redactor)
        # Filters on a logger do not apply to records from children, so attach to handlers too.
        for handler in logger.handlers:
            if not any(isinstance(f, RedactingFilter) for f in handler.filters):
                handler.addFilter(redactor)


def configure_logging(stream: TextIO | None = None) -> None:
    _install_stdlib_redaction()
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
