import httpx
import pytest
import respx

from app.opnsense.client import OPNsenseClient
from app.opnsense.errors import ConnectionStatus, FirewallError
from app.opnsense.normalise import normalise_system_status
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
