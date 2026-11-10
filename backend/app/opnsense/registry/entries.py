from app.opnsense.registry.model import (
    HttpMethod,
    Operation,
    UnknownOperationError,
    UnsupportedOperationError,
)

SYSTEM_STATUS = "system.status"
CONNECTIVITY_CHECK = "system.connectivity"

# NOTE: endpoints/privileges must be verified against a disposable lab OPNsense before release.
_ENTRIES = (
    Operation(
        operation_id=SYSTEM_STATUS,
        method=HttpMethod.GET,
        endpoint="/api/diagnostics/system/system_information",
        required_privilege="Diagnostics: System Information",
        read_only=True,
    ),
    Operation(
        operation_id=CONNECTIVITY_CHECK,
        method=HttpMethod.GET,
        endpoint="/api/diagnostics/system/system_time",
        required_privilege="Diagnostics: System Information",
        read_only=True,
        notes="Cheap authenticated call used to verify reachability, TLS and credentials.",
    ),
)

REGISTRY: dict[str, Operation] = {op.operation_id: op for op in _ENTRIES}


def get_operation(operation_id: str) -> Operation:
    """Return an executable operation or raise. Unknown and unsupported ids are rejected."""
    op = REGISTRY.get(operation_id)
    if op is None:
        raise UnknownOperationError(operation_id)
    if not op.supported:
        raise UnsupportedOperationError(operation_id)
    return op


def list_operations() -> list[Operation]:
    return list(REGISTRY.values())
