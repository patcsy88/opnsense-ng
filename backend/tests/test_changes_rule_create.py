"""Rule creation requests (ADR-0005 step 6, slice 3). OPNsense is mocked."""

import json
from typing import Any

import httpx
import respx
from sqlalchemy import select

from app.db.models import AuditLog, ChangeRequest, Role
from tests.conftest import csrf_headers
from tests.test_api import create_fw, login_as
from tests.test_changes_api import act, switch

BASE = "https://fw.example.test"
RULES = f"{BASE}/api/firewall/filter/searchRule"
ALIASES = f"{BASE}/api/firewall/alias/searchItem"
ADD = f"{BASE}/api/firewall/filter/addRule"
APPLY = f"{BASE}/api/firewall/filter/apply"
CHANGES = "/api/v1/changes"
NEW_UUID = "5d6e7f80-1a2b-4c3d-8e4f-5a6b7c8d9e0f"


def existing(**kw: Any) -> dict[str, Any]:
    base = {
        "uuid": "0b3a6c1e-1d2f-4a5b-8c7d-9e0f1a2b3c4d",
        "enabled": "1",
        "action": "pass",
        "interface": "lan",
        "description": "Old rule",
        "sequence": "40",
    }
    base.update(kw)
    return base


def proposal(**kw: Any) -> dict[str, Any]:
    body: dict[str, Any] = {
        "action": "pass",
        "interface": "lan",
        "protocol": "TCP",
        "source": "10.0.0.0/24",
        "destination": "10.0.1.5",
        "destination_port": "443",
        "description": "Web to app",
    }
    body.update(kw)
    return body


async def setup(client: httpx.AsyncClient) -> str:
    await login_as(client, Role.admin)
    fid = await create_fw(client)
    r = await client.patch(
        f"/api/v1/firewalls/{fid}", json={"allow_writes": True}, headers=csrf_headers(client)
    )
    assert r.status_code == 200
    return fid


async def stage(client: httpx.AsyncClient, fid: str, **kw: Any) -> httpx.Response:
    return await client.post(
        f"{CHANGES}/rules",
        json={"firewall_id": fid, "rule": proposal(**kw)},
        headers=csrf_headers(client),
    )


async def apply(client: httpx.AsyncClient, cid: str, **body: Any) -> httpx.Response:
    return await client.post(f"{CHANGES}/{cid}/apply", json=body, headers=csrf_headers(client))


async def approve(client: httpx.AsyncClient, cid: str) -> None:
    await act(client, cid, "submit")
    assert (await act(client, cid, "approve")).status_code == 200


def mock_reads(
    router: respx.MockRouter, rules: list[Any], aliases: list[Any] | None = None
) -> None:
    router.get(RULES).respond(200, json={"rows": rules})
    router.get(ALIASES).respond(200, json={"rows": aliases or []})


async def staged(client: httpx.AsyncClient, fid: str, **kw: Any) -> str:
    with respx.mock(assert_all_called=False) as router:
        mock_reads(
            router,
            [existing()],
            [
                {
                    "uuid": "a" * 8 + "-1111-4222-8333-444444444444",
                    "name": "web_hosts",
                    "type": "host",
                    "content": "10.0.1.5",
                }
            ],
        )
        r = await stage(client, fid, **kw)
    assert r.status_code == 201, r.text
    return str(r.json()["id"])


async def test_create_applies_after_the_last_rule_in_order(app_client: httpx.AsyncClient) -> None:
    fid = await setup(app_client)
    cid = await staged(app_client, fid)
    await approve(app_client, cid)
    created = existing(uuid=NEW_UUID, description="Web to app", sequence="41")
    with respx.mock() as router:
        router.get(RULES).mock(
            side_effect=[
                httpx.Response(200, json={"rows": [existing()]}),
                httpx.Response(200, json={"rows": [existing(), created]}),
            ]
        )
        add = router.post(ADD).respond(200, json={"result": "saved", "uuid": NEW_UUID})
        app = router.post(APPLY).respond(200, json={"status": "ok"})
        done = await apply(app_client, cid)
        order = [c.request.url.path for c in router.calls]
    body = done.json()
    assert body["status"] == "applied", body
    assert order.index("/api/firewall/filter/addRule") < order.index("/api/firewall/filter/apply")
    sent = json.loads(add.calls.last.request.content)["rule"]
    assert sent["sequence"] == "41" and sent["quick"] == "1"
    assert sent["source_net"] == "10.0.0.0/24" and sent["destination_port"] == "443"
    assert sent["enabled"] == "1" and sent["log"] == "0" and sent["action"] == "pass"
    assert app.call_count == 1
    with app_client.app.state.sessionmaker() as db:  # type: ignore[attr-defined]
        snap = db.scalars(select(ChangeRequest)).one().result_snapshot
        actions = {a.action for a in db.scalars(select(AuditLog))}
    assert snap is not None and snap["uuid"] == NEW_UUID
    assert {"firewall.firewall.rules.add", "firewall.firewall.rules.apply"} <= actions


async def test_staging_refuses_duplicate_description_and_missing_or_wrong_alias(
    app_client: httpx.AsyncClient,
) -> None:
    fid = await setup(app_client)
    aliases = [
        {"uuid": "b" * 8 + "-1111-4222-8333-444444444444", "name": "web_hosts", "type": "host"},
        {"uuid": "c" * 8 + "-1111-4222-8333-444444444444", "name": "web_ports", "type": "port"},
    ]
    with respx.mock(assert_all_called=False) as router:
        mock_reads(router, [existing()], aliases)
        assert (await stage(app_client, fid, description="Old rule")).status_code == 400
        assert (await stage(app_client, fid, destination="missing")).status_code == 400
        assert (await stage(app_client, fid, destination="web_ports")).status_code == 400
        assert (await stage(app_client, fid, destination_port="web_hosts")).status_code == 400
        ok = await stage(app_client, fid, destination="web_hosts", destination_port="web_ports")
        assert ok.status_code == 201
        assert (
            await stage(app_client, fid, destination="web_hosts", destination_port="web_ports")
        ).status_code == 400  # same description already open


async def test_staging_rejects_invalid_input_and_extra_fields(
    app_client: httpx.AsyncClient,
) -> None:
    fid = await setup(app_client)
    with respx.mock(assert_all_called=False) as router:
        for bad in (
            {"action": "allow"},
            {"interface": "LAN"},
            {"gateway": "WAN_GW"},
            {"description": ""},
            {"protocol": "any", "destination_port": "80"},
        ):
            assert (await stage(app_client, fid, **bad)).status_code == 422
    assert not router.calls


async def test_create_is_stale_when_description_or_alias_appears_or_vanishes(
    app_client: httpx.AsyncClient,
) -> None:
    fid = await setup(app_client)
    cid = await staged(app_client, fid, destination="web_hosts")
    await approve(app_client, cid)
    with respx.mock(assert_all_called=False) as router:
        mock_reads(router, [existing(description="Web to app")])
        add = router.post(ADD)
        r = await apply(app_client, cid)
    assert r.json()["status"] == "stale" and add.call_count == 0

    cid2 = await staged(app_client, fid, destination="web_hosts")
    await approve(app_client, cid2)
    with respx.mock(assert_all_called=False) as router:
        mock_reads(router, [existing()], [])  # the alias was deleted meanwhile
        add = router.post(ADD)
        r = await apply(app_client, cid2)
    assert r.json()["status"] == "stale" and "web_hosts" in r.json()["failure_message"]
    assert add.call_count == 0


async def test_firewall_validation_error_ends_failed_and_never_activates(
    app_client: httpx.AsyncClient,
) -> None:
    fid = await setup(app_client)
    cid = await staged(app_client, fid)
    await approve(app_client, cid)
    with respx.mock(assert_all_called=False) as router:
        mock_reads(router, [existing()])
        router.post(ADD).respond(
            200, json={"result": "failed", "validations": {"rule.destination_port": "Invalid"}}
        )
        app = router.post(APPLY)
        r = await apply(app_client, cid)
    assert r.json()["status"] == "failed" and "destination_port" in r.json()["failure_message"]
    assert app.call_count == 0


async def test_activation_failure_is_reported_as_saved_but_not_active(
    app_client: httpx.AsyncClient,
) -> None:
    fid = await setup(app_client)
    cid = await staged(app_client, fid)
    await approve(app_client, cid)
    with respx.mock(assert_all_called=False) as router:
        mock_reads(router, [existing()])
        router.post(ADD).respond(200, json={"result": "saved", "uuid": NEW_UUID})
        router.post(APPLY).respond(200, json={"status": "error"})
        r = await apply(app_client, cid)
    assert r.json()["status"] == "failed"
    assert "saved on the firewall but NOT active" in r.json()["failure_message"]


async def test_risky_rules_need_admin_approver_and_typed_description(
    app_client: httpx.AsyncClient,
) -> None:
    fid = await setup(app_client)
    await switch(app_client, Role.network_admin, "alice")
    with respx.mock(assert_all_called=False) as router:
        mock_reads(router, [existing()])
        r = await stage(
            app_client, fid, source="any", destination="any", protocol="any", destination_port=""
        )
    body = r.json()
    cid = body["id"]
    assert body["high_risk"] is True and body["proposed"]["risk"] == [
        "passes any source to any destination"
    ]
    await act(app_client, cid, "submit")
    await switch(app_client, Role.network_admin, "bob")
    assert (await act(app_client, cid, "approve")).status_code == 403
    await switch(app_client, Role.admin, "root2")
    assert (await act(app_client, cid, "approve")).status_code == 200
    with respx.mock(assert_all_called=False) as router:
        wrong = await apply(app_client, cid, confirm_name="nope")
        assert not router.calls
    assert wrong.status_code == 400 and "rule label" in wrong.json()["detail"]
    with respx.mock(assert_all_called=False) as router:
        mock_reads(router, [existing()])
        router.post(ADD).respond(200, json={"result": "saved", "uuid": NEW_UUID})
        router.post(APPLY).respond(200, json={"status": "ok"})
        done = await apply(app_client, cid, confirm_name="Web to app")
    assert done.json()["status"] == "applied"


async def test_wan_rule_is_high_risk_and_plain_rule_is_not(app_client: httpx.AsyncClient) -> None:
    fid = await setup(app_client)
    with respx.mock(assert_all_called=False) as router:
        mock_reads(router, [existing()])
        wan = await stage(app_client, fid, interface="wan", description="wan rule")
        plain = await stage(app_client, fid, description="plain rule")
    assert wan.json()["high_risk"] is True and plain.json()["high_risk"] is False


async def test_view_only_roles_cannot_stage_and_staging_never_writes(
    app_client: httpx.AsyncClient,
) -> None:
    fid = await setup(app_client)
    for role in (Role.read_only, Role.security_admin):
        await switch(app_client, role, f"v_{role.value}")
        with respx.mock(assert_all_called=False) as router:
            assert (await stage(app_client, fid)).status_code == 403
        assert not router.calls
    await switch(app_client, Role.network_admin, "net")
    with respx.mock(assert_all_called=False) as router:
        mock_reads(router, [existing()])
        writes = [router.post(ADD), router.post(APPLY)]
        await stage(app_client, fid)
    assert all(w.call_count == 0 for w in writes)
    r = await app_client.post(f"{CHANGES}/rules", json={"firewall_id": fid, "rule": proposal()})
    assert r.status_code == 403  # no CSRF header
