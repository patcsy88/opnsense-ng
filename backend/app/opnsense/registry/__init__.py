"""Capability registry: the ONLY source of operations the OPNsense client may execute."""

from app.opnsense.registry.entries import REGISTRY, get_operation, list_operations
from app.opnsense.registry.model import (
    HttpMethod,
    Operation,
    ResponseKind,
    UnknownOperationError,
    UnsupportedOperationError,
)

__all__ = [
    "REGISTRY",
    "HttpMethod",
    "Operation",
    "ResponseKind",
    "UnknownOperationError",
    "UnsupportedOperationError",
    "get_operation",
    "list_operations",
]
