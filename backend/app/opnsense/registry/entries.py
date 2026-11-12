from app.opnsense.registry.model import (
    HttpMethod,
    Operation,
    ResponseKind,
    UnknownOperationError,
    UnsupportedOperationError,
)

SYSTEM_STATUS = "system.status"
CONNECTIVITY_CHECK = "system.connectivity"
SYSTEM_TIME = "system.time"
SYSTEM_RESOURCES = "system.resources"
CPU_USAGE = "cpu.usage"
SYSTEM_DISK = "system.disk"
INTERFACES_OVERVIEW = "interfaces.overview"
FIREWALL_RULES_LIST = "firewall.rules.list"
FIREWALL_ALIASES_LIST = "firewall.aliases.list"
FIREWALL_ALIASES_ADD = "firewall.aliases.add"
FIREWALL_ALIASES_RECONFIGURE = "firewall.aliases.reconfigure"
FIREWALL_ALIASES_UPDATE = "firewall.aliases.update"
FIREWALL_ALIASES_DELETE = "firewall.aliases.delete"
FIREWALL_RULES_ADD = "firewall.rules.add"
FIREWALL_RULES_UPDATE = "firewall.rules.update"
FIREWALL_RULES_DELETE = "firewall.rules.delete"
FIREWALL_RULES_TOGGLE = "firewall.rules.toggle"
FIREWALL_RULES_APPLY = "firewall.rules.apply"
FIREWALL_LOG = "firewall.log"
FIREWALL_NAT_PORT_FORWARDS = "firewall.nat.port_forwards.list"
FIREWALL_NAT_OUTBOUND = "firewall.nat.outbound.list"
FORWARDS_ADD = "firewall.nat.port_forwards.add"
FORWARDS_UPDATE = "firewall.nat.port_forwards.update"
FORWARDS_DELETE = "firewall.nat.port_forwards.delete"
FORWARDS_ENABLE = "firewall.nat.port_forwards.enable"
FORWARDS_DISABLE = "firewall.nat.port_forwards.disable"
FORWARDS_APPLY = "firewall.nat.port_forwards.apply"

# Entries start unverified and are verified against a disposable lab OPNsense before verified=True.
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
        operation_id=SYSTEM_RESOURCES,
        method=HttpMethod.GET,
        endpoint="/api/diagnostics/system/system_resources",
        required_privilege="Lobby: Dashboard",
        read_only=True,
        min_version="26.7.8_2",
        verified=True,
        notes="Memory total/used.",
    ),
    Operation(
        operation_id=SYSTEM_DISK,
        method=HttpMethod.GET,
        endpoint="/api/diagnostics/system/system_disk",
        required_privilege="Lobby: Dashboard",
        read_only=True,
        min_version="26.7.8_2",
        verified=True,
        notes="Filesystems with total/used bytes; the dashboard uses the root (/) mount.",
    ),
    Operation(
        operation_id=INTERFACES_OVERVIEW,
        method=HttpMethod.GET,
        endpoint="/api/interfaces/overview/interfacesInfo",
        required_privilege="Status: Interfaces",
        read_only=True,
        min_version="26.7.8_2",
        verified=True,
        notes="Interface list with status and addresses; needs Status: Interfaces as well.",
    ),
    Operation(
        operation_id=FIREWALL_RULES_LIST,
        method=HttpMethod.GET,
        endpoint="/api/firewall/filter/searchRule",
        required_privilege="Firewall: Rules [new]",
        read_only=True,
        min_version="26.7.8_2",
        verified=True,
        notes="Lists rules. The privilege also covers rule write endpoints; this app only reads.",
    ),
    Operation(
        operation_id=FIREWALL_ALIASES_LIST,
        method=HttpMethod.GET,
        endpoint="/api/firewall/alias/searchItem",
        required_privilege="Firewall: Aliases",
        read_only=True,
        min_version="26.7.8_2",
        verified=True,
        notes="Lists aliases with their content (newline-separated string).",
    ),
    Operation(
        operation_id=FIREWALL_ALIASES_ADD,
        method=HttpMethod.POST,
        endpoint="/api/firewall/alias/addItem",
        required_privilege="Firewall: Alias: Edit",
        read_only=False,
        apply_required=True,
        verified=True,
        min_version="26.7.8_2",
        notes="Saves a new alias on the firewall without activating it. Only called from the "
        "reviewed apply procedure (ADR-0005). Body: {alias: {...}}; reply: result and uuid.",
    ),
    Operation(
        operation_id=FIREWALL_ALIASES_RECONFIGURE,
        method=HttpMethod.POST,
        endpoint="/api/firewall/alias/reconfigure",
        required_privilege="Firewall: Alias: Edit",
        read_only=False,
        verified=True,
        min_version="26.7.8_2",
        notes="Activates saved alias changes. Only called from the reviewed apply procedure.",
    ),
    Operation(
        operation_id=FIREWALL_ALIASES_UPDATE,
        method=HttpMethod.POST,
        endpoint="/api/firewall/alias/setItem/{uuid}",
        path_params=("uuid",),
        required_privilege="Firewall: Alias: Edit",
        read_only=False,
        apply_required=True,
        min_version="26.7.8_2",
        verified=True,
        notes="Saves changes to an existing alias without activating them. setItem is an upsert "
        "on the firewall, so apply must confirm the alias exists first. Reviewed apply only.",
    ),
    Operation(
        operation_id=FIREWALL_ALIASES_DELETE,
        method=HttpMethod.POST,
        endpoint="/api/firewall/alias/delItem/{uuid}",
        path_params=("uuid",),
        required_privilege="Firewall: Alias: Edit",
        read_only=False,
        apply_required=True,
        min_version="26.7.8_2",
        verified=True,
        notes="Deletes an alias. The firewall refuses when it is still referenced. Reviewed "
        "apply only.",
    ),
    Operation(
        operation_id=FIREWALL_RULES_ADD,
        method=HttpMethod.POST,
        endpoint="/api/firewall/filter/addRule",
        required_privilege="Firewall: Rules [new]",
        read_only=False,
        apply_required=True,
        min_version="26.7.8_2",
        verified=True,
        notes="Saves a new rule without activating it. Reviewed apply only (ADR-0005). Body: "
        "{rule: {...}}; reply: result and uuid.",
    ),
    Operation(
        operation_id=FIREWALL_RULES_UPDATE,
        method=HttpMethod.POST,
        endpoint="/api/firewall/filter/setRule/{uuid}",
        path_params=("uuid",),
        required_privilege="Firewall: Rules [new]",
        read_only=False,
        apply_required=True,
        min_version="26.7.8_2",
        verified=True,
        notes="Saves changes to an existing rule. setRule is an upsert, so apply confirms the "
        "rule exists first. Reviewed apply only. Verified on the lab.",
    ),
    Operation(
        operation_id=FIREWALL_RULES_DELETE,
        method=HttpMethod.POST,
        endpoint="/api/firewall/filter/delRule/{uuid}",
        path_params=("uuid",),
        required_privilege="Firewall: Rules [new]",
        read_only=False,
        apply_required=True,
        min_version="26.7.8_2",
        verified=True,
        notes="Deletes a rule. Always high risk. Reviewed apply only. Verified on the lab.",
    ),
    Operation(
        operation_id=FIREWALL_RULES_TOGGLE,
        method=HttpMethod.POST,
        endpoint="/api/firewall/filter/toggleRule/{uuid}",
        path_params=("uuid",),
        required_privilege="Firewall: Rules [new]",
        read_only=False,
        apply_required=True,
        min_version="26.7.8_2",
        verified=True,
        notes="Flips a rule's enabled flag. Apply passes no explicit state, so it checks the "
        "stored state first. Reviewed apply only. Verified on the lab.",
    ),
    Operation(
        operation_id=FIREWALL_RULES_APPLY,
        method=HttpMethod.POST,
        endpoint="/api/firewall/filter/apply",
        required_privilege="Firewall: Rules [new]",
        read_only=False,
        min_version="26.7.8_2",
        verified=True,
        notes="Activates saved rule changes (filter reload). Reply: {status: ok}. Only called "
        "from the reviewed apply procedure.",
    ),
    Operation(
        operation_id=FORWARDS_ADD,
        method=HttpMethod.POST,
        endpoint="/api/firewall/d_nat/addRule",
        required_privilege="Firewall: NAT: Destination NAT",
        read_only=False,
        apply_required=True,
        min_version="26.7.8_2",
        verified=True,
        notes="Saves a new port forward without activating it. Reviewed apply only "
        "(ADR-0006). Body: {rule: {...}}. Verified on the lab.",
    ),
    Operation(
        operation_id=FORWARDS_UPDATE,
        method=HttpMethod.POST,
        endpoint="/api/firewall/d_nat/setRule/{uuid}",
        path_params=("uuid",),
        required_privilege="Firewall: NAT: Destination NAT",
        read_only=False,
        apply_required=True,
        min_version="26.7.8_2",
        verified=True,
        notes="Saves changes to a port forward. setRule is an upsert, so apply confirms the "
        "forward exists first. Reviewed apply only. Verified on the lab.",
    ),
    Operation(
        operation_id=FORWARDS_DELETE,
        method=HttpMethod.POST,
        endpoint="/api/firewall/d_nat/delRule/{uuid}",
        path_params=("uuid",),
        required_privilege="Firewall: NAT: Destination NAT",
        read_only=False,
        apply_required=True,
        min_version="26.7.8_2",
        verified=True,
        notes="Deletes a port forward. Always high risk. Reviewed apply only. Verified on the lab.",
    ),
    Operation(
        operation_id=FORWARDS_ENABLE,
        method=HttpMethod.POST,
        endpoint="/api/firewall/d_nat/toggleRule/{uuid}/0",
        path_params=("uuid",),
        required_privilege="Firewall: NAT: Destination NAT",
        read_only=False,
        apply_required=True,
        min_version="26.7.8_2",
        verified=True,
        notes="Enables a port forward with an explicit disabled=0, never the flip default. "
        "Reviewed apply only. Verified on the lab.",
    ),
    Operation(
        operation_id=FORWARDS_DISABLE,
        method=HttpMethod.POST,
        endpoint="/api/firewall/d_nat/toggleRule/{uuid}/1",
        path_params=("uuid",),
        required_privilege="Firewall: NAT: Destination NAT",
        read_only=False,
        apply_required=True,
        min_version="26.7.8_2",
        verified=True,
        notes="Disables a port forward with an explicit disabled=1, never the flip default. "
        "Reviewed apply only. Verified on the lab.",
    ),
    Operation(
        operation_id=FORWARDS_APPLY,
        method=HttpMethod.POST,
        endpoint="/api/firewall/d_nat/apply",
        required_privilege="Firewall: NAT: Destination NAT",
        read_only=False,
        min_version="26.7.8_2",
        verified=True,
        notes="Activates saved port forward changes (filter reload, skip alias). Only called "
        "from the reviewed apply procedure. Verified on the lab.",
    ),
    Operation(
        operation_id=FIREWALL_LOG,
        method=HttpMethod.GET,
        endpoint="/api/diagnostics/firewall/log",
        query_params=("limit", "digest"),
        required_privilege="Diagnostics: Logs: Firewall: Live View",
        read_only=True,
        min_version="26.7.8_2",
        verified=True,
        notes="Recent packet-filter log records, newest first (default 1000, capped when "
        "normalised). Verified on the lab.",
    ),
    Operation(
        operation_id=FIREWALL_NAT_PORT_FORWARDS,
        method=HttpMethod.GET,
        endpoint="/api/firewall/d_nat/searchRule",
        required_privilege="Firewall: NAT: Destination NAT",
        read_only=True,
        min_version="26.7.8_2",
        verified=True,
        notes="Lists port forward (destination NAT) rules. The privilege also covers the write "
        "endpoints under /api/firewall/d_nat/*; this app only reads. Verified on the lab.",
    ),
    Operation(
        operation_id=FIREWALL_NAT_OUTBOUND,
        method=HttpMethod.GET,
        endpoint="/api/firewall/source_nat/searchRule",
        required_privilege="Firewall: NAT: Source NAT",
        read_only=True,
        min_version="26.7.8_2",
        verified=True,
        notes="Lists outbound (source NAT) rules, including automatic ones depending on the "
        "outbound mode. The privilege also covers the write endpoints under "
        "/api/firewall/source_nat/*; this app only reads. Verified on the lab.",
    ),
    Operation(
        operation_id=CPU_USAGE,
        method=HttpMethod.GET,
        endpoint="/api/diagnostics/cpu_usage/stream",
        required_privilege="Lobby: Dashboard",
        read_only=True,
        response_kind=ResponseKind.sse,
        min_version="26.7.8_2",
        verified=True,
        notes="SSE stream, sampled for a few events. Events: total (used %), user, nice, sys, "
        "intr, idle (integers).",
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
