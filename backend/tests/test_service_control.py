"""Service start, stop and restart (ADR-0016)."""

import asyncio
import uuid

import httpx
import pytest
import respx
from sqlalchemy import select

from app.api import service_control
from app.db.models import AuditLog, RateLimitCounter, Role
from app.opnsense.registry.entries import get_operation
from tests.conftest import csrf_headers
from tests.test_api import FW_BODY, login_as
from tests.test_security import db_rows

pytestmark = pytest.mark.usefixtures("db")

BASE = "https://fw.example.test/api/core/service"


def rows(*items: dict[str, object]) -> dict[str, object]:
    return {"rows": list(items), "rowCount": len(items)}


def svc(name: str, running: bool, **extra: object) -> dict[str, object]:
    return {
        "id": name,
        "name": name,
        "description": name,
        "running": 1 if running else 0,
        "locked": 0,
        **extra,
    }


async def setup(client: httpx.AsyncClient, *, allow_writes: bool = True) -> str:
    await login_as(client, Role.admin)
    r = await client.post("/api/v1/firewalls", json=FW_BODY, headers=csrf_headers(client))
    fid = str(r.json()["id"])
    if allow_writes:
        r = await client.patch(
            f"/api/v1/firewalls/{fid}", json={"allow_writes": True}, headers=csrf_headers(client)
        )
        assert r.status_code == 200
    return fid


def do(client: httpx.AsyncClient, fid: str, action: str, **body: object):  # type: ignore[no-untyped-def]
    return client.post(
        f"/api/v1/firewalls/{fid}/services/{action}", json=body, headers=csrf_headers(client)
    )


def actions(client: httpx.AsyncClient) -> list[AuditLog]:
    found = db_rows(client, select(AuditLog).where(AuditLog.action.like("firewall.service.%")))
    return list(found)


def detail(row: AuditLog) -> dict[str, object]:
    assert row.detail is not None
    return row.detail


@pytest.fixture(autouse=True)
def fast(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(service_control, "READBACK_INTERVAL", 0.01)
    monkeypatch.setattr(service_control, "READBACK_SECONDS", 0.05)


async def test_start_is_confirmed_by_reading_the_list_back(app_client: httpx.AsyncClient) -> None:
    fid = await setup(app_client)
    with respx.mock(assert_all_called=False) as router:
        router.get(f"{BASE}/search").mock(
            side_effect=[
                httpx.Response(200, json=rows(svc("ntpd", False))),
                httpx.Response(200, json=rows(svc("ntpd", False))),
                httpx.Response(200, json=rows(svc("ntpd", True))),
            ]
        )
        start = router.post(f"{BASE}/start/ntpd").respond(200, json={"result": "ok"})
        r = await do(app_client, fid, "start", service="ntpd")
        assert start.called
    body = r.json()
    assert r.status_code == 200 and body["confirmed"] is True and body["running"] is True
    assert body["was_running"] is False and body["message"] == "Running, confirmed"
    [row] = actions(app_client)
    assert row.action == "firewall.service.start" and row.outcome == "success"
    assert detail(row)["confirmed"] is True and detail(row)["service"] == "ntpd"


async def test_stop_not_confirmed_when_state_never_changes(app_client: httpx.AsyncClient) -> None:
    fid = await setup(app_client)
    with respx.mock(assert_all_called=False) as router:
        router.get(f"{BASE}/search").respond(200, json=rows(svc("ntpd", True)))
        router.post(f"{BASE}/stop/ntpd").respond(200, json={"result": "ok"})
        r = await do(app_client, fid, "stop", service="ntpd", confirm_name="ntpd")
    body = r.json()
    assert r.status_code == 200 and body["confirmed"] is False and body["running"] is True
    assert body["message"].startswith("Not confirmed")
    assert detail(actions(app_client)[0])["confirmed"] is False


async def test_restart_with_instance_uses_the_instance_path(
    app_client: httpx.AsyncClient,
) -> None:
    fid = await setup(app_client)
    listed = svc("lowvpn", True, id="lowvpn/abc")
    with respx.mock(assert_all_called=False) as router:
        router.get(f"{BASE}/search").respond(200, json=rows(listed))
        call = router.post(f"{BASE}/restart/lowvpn/abc").respond(200, json={"result": "ok"})
        r = await do(app_client, fid, "restart", service="lowvpn", instance="abc")
    assert call.called and r.status_code == 200 and r.json()["confirmed"] is True


async def test_high_impact_stop_needs_the_name_typed(app_client: httpx.AsyncClient) -> None:
    fid = await setup(app_client)
    with respx.mock(assert_all_called=False) as router:
        router.get(f"{BASE}/search").respond(200, json=rows(svc("unbound", True)))
        stop = router.post(f"{BASE}/stop/unbound").respond(200, json={"result": "ok"})
        missing = await do(app_client, fid, "stop", service="unbound")
        wrong = await do(app_client, fid, "restart", service="unbound", confirm_name="dns")
        assert not stop.called
    assert missing.status_code == 422 and wrong.status_code == 422
    assert [detail(r)["reason"] for r in actions(app_client)] == ["confirmation_required"] * 2


async def test_start_of_high_impact_service_needs_no_typed_name(
    app_client: httpx.AsyncClient,
) -> None:
    fid = await setup(app_client)
    with respx.mock(assert_all_called=False) as router:
        router.get(f"{BASE}/search").respond(200, json=rows(svc("unbound", True)))
        router.post(f"{BASE}/start/unbound").respond(200, json={"result": "ok"})
        r = await do(app_client, fid, "start", service="unbound")
    assert r.status_code == 200


@pytest.mark.parametrize("name", ["configd", "webgui"])
async def test_protected_services_cannot_be_stopped_or_restarted(
    app_client: httpx.AsyncClient, name: str
) -> None:
    fid = await setup(app_client)
    with respx.mock(assert_all_called=False) as router:
        router.get(f"{BASE}/search").respond(200, json=rows(svc(name, True)))
        call = router.post(url__startswith=BASE).respond(200, json={"result": "ok"})
        for action in ("stop", "restart"):
            r = await do(app_client, fid, action, service=name, confirm_name=name)
            assert r.status_code == 403
        assert not call.called
    assert {detail(r)["reason"] for r in actions(app_client)} == {"protected"}


async def test_locked_and_unknown_services_are_refused(app_client: httpx.AsyncClient) -> None:
    fid = await setup(app_client)
    with respx.mock(assert_all_called=False) as router:
        router.get(f"{BASE}/search").respond(
            200, json=rows(svc("pf", True, locked=1), svc("ntpd", True))
        )
        call = router.post(url__startswith=BASE).respond(200, json={"result": "ok"})
        locked = await do(app_client, fid, "restart", service="pf")
        unknown = await do(app_client, fid, "start", service="nothing")
        wrong_instance = await do(app_client, fid, "start", service="ntpd", instance="x")
        assert not call.called
    assert locked.status_code == 403
    assert unknown.status_code == 404 and wrong_instance.status_code == 404
    reasons = [detail(r)["reason"] for r in actions(app_client)]
    assert reasons == ["locked", "unknown_service", "unknown_service"]


async def test_refused_when_allow_writes_is_off(app_client: httpx.AsyncClient) -> None:
    fid = await setup(app_client, allow_writes=False)
    with respx.mock(assert_all_called=False) as router:
        call = router.route().respond(200, json={})
        r = await do(app_client, fid, "start", service="ntpd")
        assert not call.called
    assert r.status_code == 403
    assert detail(actions(app_client)[0])["reason"] == "writes_disabled"


@pytest.mark.parametrize("role", [Role.network_admin, Role.security_admin, Role.read_only])
async def test_only_admin_may_control_services(app_client: httpx.AsyncClient, role: Role) -> None:
    fid = await setup(app_client)
    await app_client.post("/api/v1/auth/logout", headers=csrf_headers(app_client))
    await login_as(app_client, role)
    with respx.mock(assert_all_called=False) as router:
        call = router.route().respond(200, json={})
        r = await do(app_client, fid, "start", service="ntpd")
        assert not call.called
    assert r.status_code == 403


async def test_requires_authentication_and_csrf(app_client: httpx.AsyncClient) -> None:
    fid = str(uuid.uuid4())
    anon = await app_client.post(f"/api/v1/firewalls/{fid}/services/start", json={"service": "x"})
    assert anon.status_code == 401
    await login_as(app_client, Role.admin)
    no_csrf = await app_client.post(
        f"/api/v1/firewalls/{fid}/services/start", json={"service": "ntpd"}
    )
    assert no_csrf.status_code == 403


async def test_invalid_names_and_actions_are_rejected(app_client: httpx.AsyncClient) -> None:
    fid = await setup(app_client)
    with respx.mock(assert_all_called=False) as router:
        call = router.route().respond(200, json={})
        for name in ("../etc", "a b", "x/y", "", "a" * 65):
            assert (await do(app_client, fid, "start", service=name)).status_code == 422
        bad_instance = await do(app_client, fid, "start", service="ntpd", instance="../1")
        extra = await do(app_client, fid, "start", service="ntpd", path="/api/x")
        assert (await do(app_client, fid, "reboot", service="ntpd")).status_code == 422
        assert not call.called
    assert bad_instance.status_code == 422 and extra.status_code == 422


async def test_unknown_firewall(app_client: httpx.AsyncClient) -> None:
    await login_as(app_client, Role.admin)
    r = await do(app_client, str(uuid.uuid4()), "start", service="ntpd")
    assert r.status_code == 404


async def test_second_action_on_the_same_firewall_gets_409(app_client: httpx.AsyncClient) -> None:
    fid = await setup(app_client)
    gate = asyncio.Event()

    async def slow(request: httpx.Request) -> httpx.Response:
        await gate.wait()
        return httpx.Response(200, json=rows(svc("ntpd", True)))

    with respx.mock(assert_all_called=False) as router:
        router.get(f"{BASE}/search").mock(side_effect=slow)
        router.post(url__startswith=BASE).respond(200, json={"result": "ok"})
        first = asyncio.create_task(
            do(app_client, fid, "restart", service="ntpd", confirm_name="ntpd")
        )
        await asyncio.sleep(0.3)
        second = await do(app_client, fid, "start", service="ntpd")
        gate.set()
        done = await first
    assert second.status_code == 409 and done.status_code == 200
    assert "busy" in [detail(r).get("reason") for r in actions(app_client)]


async def test_rate_limit_per_user(app_client: httpx.AsyncClient) -> None:
    fid = await setup(app_client)
    with respx.mock(assert_all_called=False) as router:
        router.get(f"{BASE}/search").respond(200, json=rows(svc("ntpd", True)))
        router.post(url__startswith=BASE).respond(200, json={"result": "ok"})
        codes = [
            (await do(app_client, fid, "start", service="ntpd")).status_code for _ in range(11)
        ]
    assert codes[:10] == [200] * 10 and codes[10] == 429
    keys = [r.key for r in db_rows(app_client, select(RateLimitCounter))]
    assert any(k.startswith("service:") for k in keys)


async def test_firewall_error_is_audited_and_collapsed_for_the_api(
    app_client: httpx.AsyncClient,
) -> None:
    fid = await setup(app_client)
    with respx.mock(assert_all_called=False) as router:
        router.route().mock(side_effect=httpx.ConnectError("refused"))
        r = await do(app_client, fid, "start", service="ntpd")
    assert r.status_code >= 500 or r.status_code == 502
    assert detail(actions(app_client)[0])["reason"] == "firewall_error"


async def test_registry_entries_are_unverified_writes_with_safe_paths() -> None:
    for op_id in ("services.start", "services.stop", "services.restart"):
        op = get_operation(op_id)
        assert op.read_only is False and op.verified is False
        assert op.resolve_endpoint({"service": "ntpd", "instance": ""}).endswith(
            f"/{op_id[9:]}/ntpd"
        )
        assert op.resolve_endpoint({"service": "a", "instance": "b"}).endswith("/a/b")
        for bad in ("../x", "a/b", "a b", "", "a" * 65):
            with pytest.raises(ValueError):
                op.resolve_endpoint({"service": bad})
        with pytest.raises(ValueError):
            op.resolve_endpoint({})
        with pytest.raises(ValueError):
            op.resolve_endpoint({"service": "ntpd", "instance": "../1"})
