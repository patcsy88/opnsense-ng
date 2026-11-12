"""Applying port forward changes (ADR-0006 step 3). OPNsense is mocked."""

import json
from typing import Any

import httpx
import respx
from sqlalchemy import select

from app.db.models import AuditLog
from tests.conftest import csrf_headers
from tests.test_changes_forward_stage import DNAT, TARGET, forward, live, stage
from tests.test_changes_rule_create import ALIASES, CHANGES, apply, approve, setup

BASE = "https://fw.example.test/api/firewall/d_nat"
NEW_UUID = "5d6e7f80-1a2b-4c3d-8e4f-5a6b7c8d9e0f"
OK = {"status": "ok"}


async def staged(
    client: httpx.AsyncClient, fid: str, rows: list[Any], path: str = "forwards", **body: Any
) -> str:
    r = await stage(client, fid, rows, path, **body)
    assert r.status_code == 201, r.text
    cid = str(r.json()["id"])
    await approve(client, cid)
    return cid


def sequence_of(sent: dict[str, Any]) -> str:
    return str(sent["rule"]["sequence"])


async def test_create_saves_then_activates_with_manual_pass(app_client: httpx.AsyncClient) -> None:
    fid = await setup(app_client)
    cid = await staged(
        app_client, fid, [live()], forward=forward(description="New forward", target="10.0.0.9")
    )
    created = live(uuid=NEW_UUID, descr="New forward", sequence="6", target="10.0.0.9")
    with respx.mock() as router:
        router.get(DNAT).mock(
            side_effect=[
                httpx.Response(200, json={"rows": [live()]}),
                httpx.Response(200, json={"rows": [live(), created]}),
            ]
        )
        add = router.post(f"{BASE}/addRule").respond(
            200, json={"result": "saved", "uuid": NEW_UUID}
        )
        act = router.post(f"{BASE}/apply").respond(200, json=OK)
        done = await apply(app_client, cid)
        order = [c.request.url.path for c in router.calls]
    assert done.json()["status"] == "applied", done.text
    assert order.index("/api/firewall/d_nat/addRule") < order.index("/api/firewall/d_nat/apply")
    rule = json.loads(add.calls.last.request.content)["rule"]
    assert rule["pass"] == "" and rule["nordr"] == "0" and rule["natreflection"] == ""
    assert rule["sequence"] == "6" and rule["disabled"] == "0"
    assert rule["source"]["network"] == "10.0.0.0/24" and rule["destination"]["port"] == "8443"
    assert rule["target"] == "10.0.0.9" and rule["local-port"] == "443"
    assert act.call_count == 1
    assert done.json()["failure_message"] is None
    with app_client.app.state.sessionmaker() as db:  # type: ignore[attr-defined]
        actions = {a.action for a in db.scalars(select(AuditLog))}
    expected = {
        "firewall.firewall.nat.port_forwards.add",
        "firewall.firewall.nat.port_forwards.apply",
    }
    assert expected <= actions


async def test_high_risk_create_needs_the_typed_description(app_client: httpx.AsyncClient) -> None:
    fid = await setup(app_client)
    cid = await staged(
        app_client,
        fid,
        [],
        forward=forward(interface="wan", destination="wanip", description="Public web"),
    )
    with respx.mock(assert_all_called=False) as router:
        add = router.post(f"{BASE}/addRule")
        refused = await apply(app_client, cid)
        wrong = await apply(app_client, cid, confirm_name="nope")
    assert refused.status_code == 400 and wrong.status_code == 400 and add.call_count == 0
    with respx.mock() as router:
        router.get(DNAT).respond(200, json={"rows": []})
        router.post(f"{BASE}/addRule").respond(200, json={"result": "saved", "uuid": NEW_UUID})
        router.post(f"{BASE}/apply").respond(200, json=OK)
        done = await apply(app_client, cid, confirm_name="Public web")
    assert done.json()["status"] == "applied"


async def test_create_is_stale_when_description_now_exists(app_client: httpx.AsyncClient) -> None:
    fid = await setup(app_client)
    cid = await staged(app_client, fid, [], forward=forward(description="Fresh"))
    with respx.mock(assert_all_called=False) as router:
        router.get(DNAT).respond(200, json={"rows": [live(descr="Fresh")]})
        add = router.post(f"{BASE}/addRule")
        r = await apply(app_client, cid)
    assert r.json()["status"] == "stale" and add.call_count == 0


async def test_update_keeps_sequence_and_omits_fixed_fields(app_client: httpx.AsyncClient) -> None:
    fid = await setup(app_client)
    path = f"forwards/{TARGET}/update"
    cid = await staged(app_client, fid, [live()], path, forward=forward(target="10.0.0.7"))
    with respx.mock() as router:
        router.get(DNAT).respond(200, json={"rows": [live()]})
        route = router.post(f"{BASE}/setRule/{TARGET}").respond(200, json={"result": "saved"})
        router.post(f"{BASE}/apply").respond(200, json=OK)
        done = await apply(app_client, cid)
    assert done.json()["status"] == "applied", done.text
    rule = json.loads(route.calls.last.request.content)["rule"]
    assert rule["sequence"] == "5" and rule["target"] == "10.0.0.7"
    assert "pass" not in rule and "nordr" not in rule and "poolopts" not in rule


async def test_update_is_stale_when_forward_changed_or_removed(
    app_client: httpx.AsyncClient,
) -> None:
    fid = await setup(app_client)
    path = f"forwards/{TARGET}/update"
    cid = await staged(app_client, fid, [live()], path, forward=forward(target="10.0.0.7"))
    with respx.mock(assert_all_called=False) as router:
        router.get(DNAT).respond(200, json={"rows": [live(target="10.9.9.9")]})
        write = router.post(f"{BASE}/setRule/{TARGET}")
        r = await apply(app_client, cid)
    assert r.json()["status"] == "stale" and write.call_count == 0
    cid2 = await staged(app_client, fid, [live()], path, forward=forward(target="10.0.0.8"))
    with respx.mock(assert_all_called=False) as router:
        router.get(DNAT).respond(200, json={"rows": []})
        write = router.post(f"{BASE}/setRule/{TARGET}")
        gone = await apply(app_client, cid2)
    assert gone.json()["status"] == "stale" and write.call_count == 0


async def test_toggle_sends_an_explicit_state(app_client: httpx.AsyncClient) -> None:
    fid = await setup(app_client)
    cid = await staged(app_client, fid, [live()], f"forwards/{TARGET}/toggle", enabled=False)
    with respx.mock(assert_all_called=False) as router:
        router.get(DNAT).respond(200, json={"rows": [live()]})
        off = router.post(f"{BASE}/toggleRule/{TARGET}/1").respond(200, json={"result": "Disabled"})
        flip = router.post(f"{BASE}/toggleRule/{TARGET}")
        router.post(f"{BASE}/apply").respond(200, json=OK)
        done = await apply(app_client, cid)
    assert done.json()["status"] == "applied", done.text
    assert off.call_count == 1 and flip.call_count == 0

    cid2 = await staged(
        app_client, fid, [live(disabled="1")], f"forwards/{TARGET}/toggle", enabled=True
    )
    with respx.mock(assert_all_called=False) as router:
        router.get(DNAT).respond(200, json={"rows": [live(disabled="1")]})
        on = router.post(f"{BASE}/toggleRule/{TARGET}/0").respond(200, json={"result": "Enabled"})
        router.post(f"{BASE}/apply").respond(200, json=OK)
        done2 = await apply(app_client, cid2)
    assert done2.json()["status"] == "applied" and on.call_count == 1


async def test_delete_is_high_risk_and_confirmed(app_client: httpx.AsyncClient) -> None:
    fid = await setup(app_client)
    cid = await staged(app_client, fid, [live()], f"forwards/{TARGET}/delete")
    with respx.mock(assert_all_called=False) as router:
        gone = router.post(f"{BASE}/delRule/{TARGET}")
        refused = await apply(app_client, cid)
    assert refused.status_code == 400 and gone.call_count == 0
    with respx.mock() as router:
        router.get(DNAT).respond(200, json={"rows": [live()]})
        route = router.post(f"{BASE}/delRule/{TARGET}").respond(200, json={"result": "deleted"})
        router.post(f"{BASE}/apply").respond(200, json=OK)
        done = await apply(app_client, cid, confirm_name="Old forward")
    assert done.json()["status"] == "applied" and route.call_count == 1


async def test_failed_activation_is_reported_as_saved_but_not_active(
    app_client: httpx.AsyncClient,
) -> None:
    fid = await setup(app_client)
    cid = await staged(app_client, fid, [], forward=forward(description="Fresh"))
    with respx.mock() as router:
        router.get(DNAT).respond(200, json={"rows": []})
        router.post(f"{BASE}/addRule").respond(200, json={"result": "saved", "uuid": NEW_UUID})
        router.post(f"{BASE}/apply").respond(200, json={"status": "error"})
        done = await apply(app_client, cid)
    body = done.json()
    assert body["status"] == "failed" and "NOT active" in body["failure_message"]


async def test_firewall_validation_failure_is_reported(app_client: httpx.AsyncClient) -> None:
    fid = await setup(app_client)
    cid = await staged(app_client, fid, [], forward=forward(description="Fresh"))
    with respx.mock(assert_all_called=False) as router:
        router.get(DNAT).respond(200, json={"rows": []})
        router.post(f"{BASE}/addRule").respond(
            200, json={"result": "failed", "validations": {"rule.target": "bad"}}
        )
        act = router.post(f"{BASE}/apply")
        done = await apply(app_client, cid)
    assert done.json()["status"] == "failed" and "rule.target" in done.json()["failure_message"]
    assert act.call_count == 0


async def test_apply_needs_admin_and_allow_writes(app_client: httpx.AsyncClient) -> None:
    fid = await setup(app_client)
    cid = await staged(app_client, fid, [], forward=forward(description="Fresh"))
    r = await app_client.patch(
        f"/api/v1/firewalls/{fid}", json={"allow_writes": False}, headers=csrf_headers(app_client)
    )
    assert r.status_code == 200
    with respx.mock(assert_all_called=False) as router:
        add = router.post(f"{BASE}/addRule")
        blocked = await apply(app_client, cid)
    assert blocked.status_code in (400, 403) and add.call_count == 0
    assert ALIASES and CHANGES
