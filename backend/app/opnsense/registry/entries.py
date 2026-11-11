from app.opnsense.registry.model import (
    HttpMethod,
    Operation,
    UnknownOperationError,
    UnsupportedOperationError,
)

SYSTEM_STATUS = "system.status"
CONNECTIVITY_CHECK = "system.connectivity"
SYSTEM_TIME = "system.time"

# New entries must be verified against a disposable lab OPNsense before verified=True.
# The three below were verified on OPNsense 26.7.8_2 (lab, 2026-11-11) with a non-admin API user
# holding only the "Lobby: Dashboard" privilege.
_ENTRIES = (
    Operation(
        operation_id=SYSTEM_STATUS,
        method=HttpMethod.GET,
        endpoint="/api/diagnostics/system/system_information",
        required_privilege="Lobby: Dashboard",
        read_only=True,
        min_version="26.7.8_2",
        verified=True,
    ),
    Operation(
        operation_id=SYSTEM_TIME,
        method=HttpMethod.GET,
        endpoint="/api/diagnostics/system/system_time",
        required_privilege="Lobby: Dashboard",
        read_only=True,
        min_version="26.7.8_2",
        verified=True,
        notes="Uptime, firewall time, boot time and load average.",
    ),
    Operation(
        operation_id=CONNECTIVITY_CHECK,
        method=HttpMethod.GET,
        endpoint="/api/diagnostics/system/system_time",
        required_privilege="Lobby: Dashboard",
        read_only=True,
        min_version="26.7.8_2",
        verified=True,
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
