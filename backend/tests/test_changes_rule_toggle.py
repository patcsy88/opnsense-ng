"""Rule enable/disable requests (ADR-0005 step 6, slice 2). OPNsense is mocked."""

import json
from typing import Any

import httpx
import respx
from sqlalchemy import select

from app.db.models import AuditLog, Role
from tests.conftest import csrf_headers
from tests.test_api import create_fw, login_as
from tests.test_changes_api import act, switch

BASE = "https://fw.example.test"
LIST = f"{BASE}/api/firewall/filter/searchRule"
APPLY = f"{BASE}/api/firewall/filter/apply"
CHANGES = "/api/v1/changes"
UUID = "0b3a6c1e-1d2f-4a5b-8c7d-9e0f1a2b3c4d"
TOGGLE = f"{BASE}/api/firewall/filter/toggleRule/{UUID}"


def rule(**kw: Any) -> dict[str, Any]:
    base = {
        "uuid": UUID,
        "enabled": "1",
        "action": "pass",
        "interface": "lan",
        "direction": "in",
        "ipprotocol": "inet",
        "protocol": "TCP",
        "source_net": "10.0.0.0/24",
        "destination_net": "10.0.1.5",
        "destination_port": "443",
        "description": "Web out",
        "log": "0",
        "sequence": "10",
    }
    base.update(kw)
    return base


async def setup(client: httpx.AsyncClient) -> str:
    await login_as(client, Role.admin)
    fid = await create_fw(client)
    r = await client.patch(
        f"/api/v1/firewalls/{fid}", json={"allow_writes": True}, headers=csrf_headers(client)
    )
    assert r.status_code == 200
    return fid


async def stage(
    client: httpx.AsyncClient, fid: str, enabled: bool, target: str = UUID
) -> httpx.Response:
    return await client.post(
        f"{CHANGES}/rules/{target}/toggle",
        json={"firewall_id": fid, "enabled": enabled},
        headers=csrf_headers(client),
    )


async def apply(client: httpx.AsyncClient, cid: str, **body: Any) -> httpx.Response:
    return await client.post(f"{CHANGES}/{cid}/apply", json=body, headers=csrf_headers(client))


async def approve(client: httpx.AsyncClient, cid: str) -> None:
    await act(client, cid, "submit")
    assert (await act(client, cid, "approve")).status_code == 200


async def staged_disable(client: httpx.AsyncClient, fid: str, **kw: Any) -> str:
    with respx.mock() as router:
        router.get(LIST).respond(200, json={"rows": [rule(**kw)]})
        r = await stage(client, fid, False)
    assert r.status_code == 201, r.text
    return str(r.json()["id"])


async def test_toggle_records_base_and_applies_in_order(app_client: httpx.AsyncClient) -> None:
    fid = await setup(app_client)
    cid = await staged_disable(app_client, fid, sequence="10")
    await approve(app_client, cid)
    with respx.mock() as router:
        lst = router.get(LIST).mock(
            side_effect=[
                httpx.Response(200, json={"rows": [rule()]}),
                httpx.Response(200, json={"rows": [rule(enabled="0")]}),
            ]
        )
        tog = router.post(TOGGLE).respond(200, json={"result": "Disabled", "changed": True})
        app = router.post(APPLY).respond(200, json={"status": "OK"})
        done = await apply(app_client, cid)
        order = [c.request.url.path for c in router.calls]
    body = done.json()
    assert body["status"] == "applied", body
    assert lst.call_count == 2 and tog.call_count == 1 and app.call_count == 1
    assert order.index(f"/api/firewall/filter/toggleRule/{UUID}") < order.index(
        "/api/firewall/filter/apply"
    )
    assert body["high_risk"] is False and body["proposed"]["enabled"] is False
    assert json.loads(tog.calls.last.request.content or b"{}") == {}
    with app_client.app.state.sessionmaker() as db:  # type: ignore[attr-defined]
        actions = {a.action for a in db.scalars(select(AuditLog))}
    assert {"firewall.firewall.rules.toggle", "firewall.firewall.rules.apply"} <= actions


async def test_toggle_is_stale_when_rule_changed_or_removed(
    app_client: httpx.AsyncClient,
) -> None:
    fid = await setup(app_client)
    cid = await staged_disable(app_client, fid)
    await approve(app_client, cid)
    with respx.mock(assert_all_called=False) as router:
        router.get(LIST).respond(200, json={"rows": [rule(destination_port="22")]})
        tog = router.post(TOGGLE)
        r = await apply(app_client, cid)
    assert r.json()["status"] == "stale" and tog.call_count == 0

    cid2 = await staged_disable(app_client, fid)  # first request is closed now
    await approve(app_client, cid2)
    with respx.mock(assert_all_called=False) as router:
        router.get(LIST).respond(200, json={"rows": []})
        tog = router.post(TOGGLE)
        r = await apply(app_client, cid2)
    assert r.json()["status"] == "stale" and tog.call_count == 0


async def test_unexpected_toggle_reply_fails_and_never_activates(
    app_client: httpx.AsyncClient,
) -> None:
    fid = await setup(app_client)
    cid = await staged_disable(app_client, fid)
    await approve(app_client, cid)
    with respx.mock(assert_all_called=False) as router:
        router.get(LIST).respond(200, json={"rows": [rule()]})
        router.post(TOGGLE).respond(200, json={"result": "Enabled"})  # the wrong direction
        app = router.post(APPLY)
        r = await apply(app_client, cid)
    assert r.json()["status"] == "failed" and app.call_count == 0


async def test_activation_failure_is_reported_as_saved_but_not_active(
    app_client: httpx.AsyncClient,
) -> None:
    fid = await setup(app_client)
    cid = await staged_disable(app_client, fid)
    await approve(app_client, cid)
    with respx.mock() as router:
        router.get(LIST).respond(200, json={"rows": [rule()]})
        router.post(TOGGLE).respond(200, json={"result": "Disabled"})
        router.post(APPLY).respond(200, json={"status": "error"})
        r = await apply(app_client, cid)
    assert r.json()["status"] == "failed"
    assert "saved on the firewall but NOT active" in r.json()["failure_message"]


async def test_staging_refuses_noop_unknown_and_duplicate(app_client: httpx.AsyncClient) -> None:
    fid = await setup(app_client)
    with respx.mock() as router:
        router.get(LIST).respond(200, json={"rows": [rule()]})
        assert (await stage(app_client, fid, True)).status_code == 400  # already enabled
        other = "11111111-2222-4333-8444-555555555555"
        assert (await stage(app_client, fid, False, other)).status_code == 400
        assert (await stage(app_client, fid, False, "nope")).status_code == 422
        assert (await stage(app_client, fid, False, UUID.upper())).status_code == 422
        assert (await stage(app_client, fid, False)).status_code == 201
        assert (await stage(app_client, fid, False)).status_code == 400  # open request exists


async def test_high_risk_rules_need_admin_approver_and_typed_label(
    app_client: httpx.AsyncClient,
) -> None:
    fid = await setup(app_client)
    await switch(app_client, Role.network_admin, "alice")
    with respx.mock() as router:
        router.get(LIST).respond(
            200, json={"rows": [rule(source_net="any", destination_net="any")]}
        )
        staged = (await stage(app_client, fid, False)).json()
    cid = staged["id"]
    assert staged["high_risk"] is True
    await act(app_client, cid, "submit")
    await switch(app_client, Role.network_admin, "bob")
    assert (await act(app_client, cid, "approve")).status_code == 403
    await switch(app_client, Role.admin, "root2")
    assert (await act(app_client, cid, "approve")).status_code == 200
    with respx.mock(assert_all_called=False) as router:
        wrong = await apply(app_client, cid, confirm_name="nope")
        assert not router.calls
    assert wrong.status_code == 400 and "rule label" in wrong.json()["detail"]
    with respx.mock() as router:
        router.get(LIST).respond(
            200, json={"rows": [rule(source_net="any", destination_net="any")]}
        )
        router.post(TOGGLE).respond(200, json={"result": "Disabled"})
        router.post(APPLY).respond(200, json={"status": "ok"})
        done = await apply(app_client, cid, confirm_name="Web out")
    assert done.json()["status"] == "applied"


async def test_wan_and_system_rules_are_high_risk(app_client: httpx.AsyncClient) -> None:
    fid = await setup(app_client)
    with respx.mock() as router:
        router.get(LIST).respond(200, json={"rows": [rule(interface="wan")]})
        assert (await stage(app_client, fid, False)).json()["high_risk"] is True
    await act(app_client, (await app_client.get(CHANGES)).json()[0]["id"], "cancel")
    with respx.mock() as router:
        router.get(LIST).respond(200, json={"rows": [rule(sequence="")]})
        assert (await stage(app_client, fid, False)).json()["high_risk"] is True


async def test_view_only_roles_cannot_stage_and_staging_never_writes(
    app_client: httpx.AsyncClient,
) -> None:
    fid = await setup(app_client)
    for role in (Role.read_only, Role.security_admin):
        await switch(app_client, role, f"v_{role.value}")
        with respx.mock(assert_all_called=False) as router:
            assert (await stage(app_client, fid, False)).status_code == 403
        assert not router.calls
    await switch(app_client, Role.network_admin, "net")
    with respx.mock(assert_all_called=False) as router:
        router.get(LIST).respond(200, json={"rows": [rule()]})
        writes = [router.post(TOGGLE), router.post(APPLY)]
        await stage(app_client, fid, False)
    assert all(w.call_count == 0 for w in writes)
    r = await app_client.post(
        f"{CHANGES}/rules/{UUID}/toggle", json={"firewall_id": fid, "enabled": False}
    )
    assert r.status_code == 403  # no CSRF header
