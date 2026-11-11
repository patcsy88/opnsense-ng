import httpx
import pytest
import respx

from app.opnsense.client import OPNsenseClient
from app.opnsense.errors import ConnectionStatus, FirewallError
from app.opnsense.normalise import (
    normalise_cpu_events,
    normalise_interfaces,
    normalise_rules,
    normalise_system_status,
)
from app.opnsense.registry import (
    REGISTRY,
    Operation,
    UnknownOperationError,
    UnsupportedOperationError,
    get_operation,
)
from app.opnsense.registry.model import HttpMethod

BASE = "https://fw.example.test"
STATUS_URL = f"{BASE}/api/diagnostics/system/system_information"


def make_client(**kw: object) -> OPNsenseClient:
    return OPNsenseClient(
        base_url=BASE,
        api_key="k",
        api_secret="s",
        backoff_base_s=0,
        **kw,  # type: ignore[arg-type]
    )


def test_registry_rejects_unknown_ids() -> None:
    for bad in ("", "nope", "/api/core/system/reboot", "system.status/../x"):
        with pytest.raises(UnknownOperationError):
            get_operation(bad)


def test_registry_rejects_unsupported() -> None:
    op = Operation(
        operation_id="x.unsupported",
        method=HttpMethod.GET,
        endpoint="/api/x/y",
        required_privilege="p",
        read_only=True,
        supported=False,
    )
    REGISTRY[op.operation_id] = op
    try:
        with pytest.raises(UnsupportedOperationError):
            get_operation("x.unsupported")
    finally:
        del REGISTRY[op.operation_id]


def test_registry_entry_fields_and_path_validation() -> None:
    op = get_operation("system.status")
    assert op.read_only and not op.apply_required and op.supported
    with pytest.raises(ValueError):
        Operation(
            operation_id="bad.path",
            method=HttpMethod.GET,
            endpoint="https://evil.test/x",
            required_privilege="p",
            read_only=True,
        )


async def test_client_refuses_unknown_operation_without_http() -> None:
    with respx.mock(assert_all_called=False) as router:
        client = make_client()
        with pytest.raises(UnknownOperationError):
            await client.execute("/api/core/firmware/upgrade")
        assert router.calls.call_count == 0
        await client.aclose()


async def test_client_success_and_normalise() -> None:
    with respx.mock() as router:
        route = router.get(STATUS_URL).respond(
            200, json={"name": "fw1", "versions": ["OPNsense 26.1"], "updates": "ok"}
        )
        client = make_client()
        data = await client.execute("system.status")
        await client.aclose()
    assert route.calls.last.request.headers["authorization"].startswith("Basic ")
    status = normalise_system_status(data)
    assert status.hostname == "fw1" and status.versions == ["OPNsense 26.1"]


def test_normalise_maps_time_fields() -> None:
    info = {"name": "fw1.internal", "versions": ["OPNsense 26.7"], "updates": "ok"}
    time_info = {
        "uptime": "2 days, 03:04:05",
        "datetime": "Wed Nov 11 10:00:00 UTC 2026",
        "boottime": "Mon Nov 9 07:00:00 UTC 2026",
        "config": "Tue Nov 10 12:00:00 UTC 2026",
        "loadavg": "0.10, 0.20, 0.30",
    }
    status = normalise_system_status(info, time_info)
    assert status.uptime == "2 days, 03:04:05"
    assert status.server_time == "Wed Nov 11 10:00:00 UTC 2026"
    assert normalise_system_status(info, None).uptime is None


def test_normalise_maps_memory_and_load() -> None:
    resources = {"memory": {"total": "8589934592", "used": 2147483648}}
    status = normalise_system_status({}, {"loadavg": "0.10, 0.20, 0.30"}, resources)
    assert status.memory_total_bytes == 8589934592
    assert status.memory_used_bytes == 2147483648
    assert status.memory_used_percent == 25.0
    assert status.load_average == "0.10, 0.20, 0.30"


@pytest.mark.parametrize(
    "resources",
    [
        None,
        [],
        {"memory": {"used": "N/A"}},
        {"memory": {"total": 100, "used": 200}},
        {"memory": {"total": 0, "used": 0}},
        {"memory": {"total": True, "used": 1}},
        {"memory": {"total": -5, "used": 1}},
    ],
)
def test_normalise_memory_rejects_bad_shapes(resources: object) -> None:
    status = normalise_system_status({}, {"loadavg": "N/A"}, resources)
    assert status.memory_total_bytes is None and status.memory_used_percent is None
    assert status.load_average is None


def test_normalise_tolerates_garbage() -> None:
    assert normalise_system_status(["x"]).hostname is None


async def test_timeout_is_retried_then_reported() -> None:
    with respx.mock() as router:
        route = router.get(STATUS_URL).mock(side_effect=httpx.ReadTimeout("t"))
        client = make_client(max_retries=2)
        with pytest.raises(FirewallError) as exc:
            await client.execute("system.status")
        await client.aclose()
    assert exc.value.status is ConnectionStatus.timeout
    assert route.call_count == 3


async def test_outage_retry_recovers() -> None:
    with respx.mock() as router:
        router.get(STATUS_URL).mock(
            side_effect=[httpx.ConnectError("down"), httpx.Response(200, json={"name": "a"})]
        )
        client = make_client(max_retries=2)
        assert (await client.execute("system.status"))["name"] == "a"
        await client.aclose()


async def test_http_errors_map_to_status_without_retry() -> None:
    cases = {
        401: ConnectionStatus.auth_failed,
        403: ConnectionStatus.forbidden,
        404: ConnectionStatus.endpoint_not_found,
    }
    for code, expected in cases.items():
        with respx.mock() as router:
            route = router.get(STATUS_URL).respond(code)
            client = make_client(max_retries=2)
            with pytest.raises(FirewallError) as exc:
                await client.execute("system.status")
            await client.aclose()
        assert exc.value.status is expected and route.call_count == 1


async def test_503_retried_and_non_json_rejected() -> None:
    with respx.mock() as router:
        route = router.get(STATUS_URL).respond(503)
        client = make_client(max_retries=1)
        with pytest.raises(FirewallError) as exc:
            await client.execute("system.status")
        await client.aclose()
    assert exc.value.status is ConnectionStatus.server_error and route.call_count == 2
    with respx.mock() as router:
        router.get(STATUS_URL).respond(200, text="<html>")
        client = make_client()
        with pytest.raises(FirewallError) as exc:
            await client.execute("system.status")
        await client.aclose()
    assert exc.value.status is ConnectionStatus.bad_response


async def test_state_changing_operations_are_never_retried() -> None:
    op = Operation(
        operation_id="test.write",
        method=HttpMethod.POST,
        endpoint="/api/test/write",
        required_privilege="p",
        read_only=False,
    )
    REGISTRY[op.operation_id] = op
    try:
        with respx.mock() as router:
            route = router.post(f"{BASE}/api/test/write").mock(side_effect=httpx.ReadTimeout("t"))
            client = make_client(max_retries=3)
            with pytest.raises(FirewallError):
                await client.execute("test.write")
            await client.aclose()
        assert route.call_count == 1
    finally:
        del REGISTRY[op.operation_id]


CPU_URL = "https://fw.example.test/api/diagnostics/cpu_usage/stream"


async def test_sample_stream_reads_bounded_events() -> None:
    body = b"".join(b'data: {"total": %d}\n\n' % n for n in range(10))
    with respx.mock() as router:
        route = router.get(CPU_URL).respond(200, content=body)
        client = make_client()
        events = await client.sample_stream("cpu.usage", max_events=99)
        await client.aclose()
    assert events == [{"total": 0}, {"total": 1}, {"total": 2}]  # capped at 3
    assert route.calls.last.request.headers["accept"] == "text/event-stream"


async def test_sample_stream_ignores_garbage_lines() -> None:
    body = b': comment\nevent: x\ndata: not-json\ndata: {"total": 5}\n\n'
    with respx.mock() as router:
        router.get(CPU_URL).respond(200, content=body)
        client = make_client()
        events = await client.sample_stream("cpu.usage")
        await client.aclose()
    assert events == [{"total": 5}]


async def test_sample_stream_size_limit() -> None:
    with respx.mock() as router:
        router.get(CPU_URL).respond(200, content=b"x" * (70 * 1024))
        client = make_client()
        with pytest.raises(FirewallError) as err:
            await client.sample_stream("cpu.usage")
        await client.aclose()
    assert err.value.status is ConnectionStatus.bad_response


@pytest.mark.parametrize(
    ("code", "status"),
    [
        (401, ConnectionStatus.auth_failed),
        (403, ConnectionStatus.forbidden),
        (404, ConnectionStatus.endpoint_not_found),
    ],
)
async def test_sample_stream_maps_http_errors(code: int, status: ConnectionStatus) -> None:
    with respx.mock() as router:
        router.get(CPU_URL).respond(code)
        client = make_client()
        with pytest.raises(FirewallError) as err:
            await client.sample_stream("cpu.usage")
        await client.aclose()
    assert err.value.status is status


async def test_sample_stream_no_data_is_error() -> None:
    with respx.mock() as router:
        router.get(CPU_URL).respond(200, content=b"")
        client = make_client()
        with pytest.raises(FirewallError):
            await client.sample_stream("cpu.usage", timeout_s=0.2)
        await client.aclose()


async def test_stream_and_json_operations_are_not_interchangeable() -> None:
    client = make_client()
    with pytest.raises(UnsupportedOperationError):
        await client.execute("cpu.usage")
    with pytest.raises(UnsupportedOperationError):
        await client.sample_stream("system.status")
    await client.aclose()


def test_normalise_cpu_events() -> None:
    assert normalise_cpu_events([{"total": 12}, {"total": "40.26"}]) == 40.3
    assert normalise_cpu_events([{"idle": 90}]) == 10.0
    assert normalise_cpu_events([{"total": 150}, {"total": True}, "x"]) is None
    assert normalise_cpu_events(None) is None
    assert normalise_cpu_events([{"total": 150}, {"total": 7}]) == 7.0


def test_cpu_sampler_caches_and_guards_concurrency() -> None:
    import uuid

    from app.opnsense import cpu_sampler

    fid = uuid.uuid4()
    calls: list[int] = []
    nested: list[float | None] = []

    def fetch() -> float | None:
        calls.append(1)
        nested.append(cpu_sampler.sample_cpu(fid, lambda: 99.0))  # overlapping request
        return 20.0

    assert cpu_sampler.sample_cpu(fid, fetch) == 20.0
    assert nested == [None] and len(calls) == 1
    assert cpu_sampler.sample_cpu(fid, lambda: 1.0) == 20.0  # served from cache


def test_normalise_disk_uses_root_filesystem() -> None:
    disk = {
        "devices": [
            {"mountpoint": "/var", "total_bytes": 10, "used_bytes": 9},
            {"mountpoint": "/", "total_bytes": "4000", "used_bytes": 1000},
        ]
    }
    status = normalise_system_status({}, None, None, None, disk)
    assert status.disk_total_bytes == 4000 and status.disk_used_percent == 25.0


@pytest.mark.parametrize(
    "disk",
    [
        None,
        [],
        {"devices": "x"},
        {"devices": [{"mountpoint": "/var", "total_bytes": 1, "used_bytes": 1}]},
        {"devices": [{"mountpoint": "/", "total_bytes": 10, "used_bytes": 20}]},
        {"devices": [{"mountpoint": "/", "total_bytes": 0, "used_bytes": 0}]},
        {"devices": ["x", None]},
    ],
)
def test_normalise_disk_rejects_bad_shapes(disk: object) -> None:
    status = normalise_system_status({}, None, None, None, disk)
    assert status.disk_total_bytes is None and status.disk_used_percent is None


def test_normalise_interfaces_maps_rows_and_drops_extras() -> None:
    raw = {
        "total": 2,
        "rows": [
            {
                "identifier": "lan",
                "description": "LAN",
                "device": "vtnet1",
                "status": "up",
                "enabled": True,
                "link_type": "static",
                "ipv4": [{"ipaddr": "192.168.1.1/24"}],
                "ipv6": [{"ipaddr": "fe80::1/64", "vhid": "1"}],
                "gateways": ["LAN_GW"],
                "vlan_tag": "20",
                "macaddr": "aa:bb:cc:dd:ee:ff",
            },
            "junk",
            {"identifier": "", "ipv4": "x", "vlan_tag": True, "enabled": "yes"},
        ],
    }
    lan, odd = normalise_interfaces(raw)
    assert lan.identifier == "lan" and lan.ipv4 == ["192.168.1.1/24"] and lan.vlan_tag == 20
    assert lan.ipv6 == ["fe80::1/64"] and lan.gateways == ["LAN_GW"]
    assert "aa:bb" not in lan.model_dump_json()
    assert odd.identifier is None and odd.ipv4 == [] and odd.vlan_tag is None
    assert odd.enabled is None


@pytest.mark.parametrize("raw", [None, [], {}, {"rows": "x"}, {"rows": None}])
def test_normalise_interfaces_rejects_bad_shapes(raw: object) -> None:
    assert normalise_interfaces(raw) == []


def test_normalise_rules_maps_flags_and_drops_extras() -> None:
    raw = {
        "rows": [
            {
                "uuid": "abc-1",
                "enabled": "1",
                "action": "pass",
                "interface": "lan",
                "direction": "in",
                "ipprotocol": "inet",
                "protocol": "TCP",
                "source_net": "any",
                "destination_net": "10.0.0.0/8",
                "destination_port": "443",
                "description": "Allow HTTPS",
                "log": "0",
                "sequence": "5",
                "categories": "secret-cat",
                "category_colors": ["ff0000"],
            },
            "junk",
            {"enabled": "maybe", "sequence": True, "description": "x" * 2000},
        ]
    }
    result = normalise_rules(raw)
    first, odd = result.rules
    assert first.enabled is True and first.log is False and first.sequence == 5
    assert first.ip_protocol == "inet" and first.destination == "10.0.0.0/8"
    assert "secret-cat" not in first.model_dump_json()
    assert odd.enabled is None and odd.sequence is None and len(odd.description or "") == 500
    assert result.truncated is False


def test_normalise_rules_truncates_and_rejects_bad_shapes() -> None:
    many = {"rows": [{"uuid": str(n)} for n in range(2500)]}
    result = normalise_rules(many)
    assert len(result.rules) == 2000 and result.truncated is True
    bad_shapes: list[object] = [None, [], {}, {"rows": "x"}]
    for bad in bad_shapes:
        assert normalise_rules(bad).rules == []
