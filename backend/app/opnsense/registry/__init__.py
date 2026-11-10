"""Capability registry: the ONLY source of operations the OPNsense client may execute."""

from app.opnsense.registry.entries import REGISTRY, get_operation, list_operations
from app.opnsense.registry.model import (
    HttpMethod,
    Operation,
    UnknownOperationError,
    UnsupportedOperationError,
)

__all__ = [
    "REGISTRY",
    "HttpMethod",
    "Operation",
    "UnknownOperationError",
    "UnsupportedOperationError",
    "get_operation",
    "list_operations",
]
