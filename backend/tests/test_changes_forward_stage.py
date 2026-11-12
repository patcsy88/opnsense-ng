"""Staging port forward changes (ADR-0006 step 2). OPNsense is mocked; nothing is written."""

from typing import Any

import httpx
import respx
from sqlalchemy import select

from app.db.models import AuditLog, ChangeRequest, Role
from tests.conftest import csrf_headers
from tests.test_changes_api import act, switch
from tests.test_changes_rule_create import ALIASES, CHANGES, setup

DNAT = "https://fw.example.test/api/firewall/d_nat/searchRule"
TARGET = "0b3a6c1e-1d2f-4a5b-8c7d-9e0f1a2b3c4d"


def live(**kw: Any) -> dict[str, Any]:
    base = {
        "uuid": TARGET,
        "disabled": "0",
        "nordr": "0",
        "interface": "lan",
        "ipprotocol": "inet",
        "protocol": "TCP",
        "source.network": "10.0.0.0/24",
        "destination.network": "lanip",
        "destination.port": "8443",
        "target": "10.0.0.5",
        "local-port": "443",
        "descr": "Old forward",
        "sequence": "5",
    }
    base.update(kw)
    return base


def forward(**kw: Any) -> dict[str, Any]:
    body: dict[str, Any] = {
        "interface": "lan",
        "protocol": "TCP",
        "source": "10.0.0.0/24",
        "destination": "lanip",
        "destination_port": "8443",
        "target": "10.0.0.6",
        "target_port": "443",
        "description": "Old forward",
    }
    body.update(kw)
    return body


def reads(router: respx.MockRouter, rows: list[Any], aliases: list[Any] | None = None) -> None:
    router.get(DNAT).respond(200, json={"rows": rows})
    router.get(ALIASES).respond(200, json={"rows": aliases or []})


async def stage(
    client: httpx.AsyncClient, fid: str, rows: list[Any], path: str = "forwards", **body: Any
) -> httpx.Response:
    with respx.mock(assert_all_called=False) as router:
        reads(router, rows)
        return await client.post(
            f"{CHANGES}/{path}",
            json={"firewall_id": fid, **body},
            headers=csrf_headers(client),
        )


async def test_create_is_validated_and_reads_only(app_client: httpx.AsyncClient) -> None:
    fid = await setup(app_client)
    with respx.mock(assert_all_called=False) as router:
        reads(router, [live()])
        writes = router.post(url__regex=r".*/d_nat/.*")
        r = await app_client.post(
            f"{CHANGES}/forwards",
            json={"firewall_id": fid, "forward": forward(description="New forward")},
            headers=csrf_headers(app_client),
        )
    assert r.status_code == 201, r.text
    body = r.json()
    assert body["kind"] == "nat_forward" and body["action"] == "create"
    assert body["status"] == "validated" and body["high_risk"] is False
    assert body["proposed"]["label"] == "New forward"
    assert writes.call_count == 0


async def test_wan_and_wide_open_forwards_are_high_risk(app_client: httpx.AsyncClient) -> None:
    fid = await setup(app_client)
    wan = await stage(
        app_client,
        fid,
        [],
        forward=forward(interface="wan", destination="wanip", description="Public web"),
    )
    assert wan.json()["high_risk"] is True
    assert any("WAN" in x for x in wan.json()["proposed"]["risk"])
    wide = await stage(
        app_client,
        fid,
        [],
        forward=forward(source="any", destination_port="", description="Wide open"),
    )
    assert wide.json()["high_risk"] is True


async def test_create_refuses_duplicate_description_and_open_duplicate(
    app_client: httpx.AsyncClient,
) -> None:
    fid = await setup(app_client)
    dup = await stage(app_client, fid, [live()], forward=forward())
    assert dup.status_code == 400 and "already exists" in dup.text
    first = await stage(app_client, fid, [], forward=forward(description="Fresh"))
    assert first.status_code == 201
    second = await stage(app_client, fid, [], forward=forward(description="Fresh"))
    assert second.status_code == 400 and "open request" in second.text


async def test_create_checks_aliases(app_client: httpx.AsyncClient) -> None:
    fid = await setup(app_client)
    with respx.mock(assert_all_called=False) as router:
        reads(router, [])
        missing = await app_client.post(
            f"{CHANGES}/forwards",
            json={"firewall_id": fid, "forward": forward(description="A", target="WebHost")},
            headers=csrf_headers(app_client),
        )
    assert missing.status_code == 400 and "WebHost" in missing.text
    alias = {
        "uuid": "a" * 8 + "-1111-4222-8333-444444444444",
        "name": "WebHost",
        "type": "host",
        "content": "10.0.0.9",
    }
    with respx.mock(assert_all_called=False) as router:
        reads(router, [], [alias])
        ok = await app_client.post(
            f"{CHANGES}/forwards",
            json={"firewall_id": fid, "forward": forward(description="A", target="WebHost")},
            headers=csrf_headers(app_client),
        )
    assert ok.status_code == 201, ok.text


async def test_update_keeps_interface_and_description(app_client: httpx.AsyncClient) -> None:
    fid = await setup(app_client)
    path = f"forwards/{TARGET}/update"
    ok = await stage(app_client, fid, [live()], path, forward=forward(target="10.0.0.7"))
    assert ok.status_code == 201, ok.text
    assert ok.json()["target_uuid"] == TARGET and ok.json()["base_snapshot"]["target"] == "10.0.0.5"
    other = await stage(
        app_client, fid, [live()], path, forward=forward(description="Renamed", target="10.0.0.8")
    )
    assert other.status_code == 400 and "cannot be changed" in other.text
    missing = await stage(app_client, fid, [], path, forward=forward())
    assert missing.status_code == 400 and "not found" in missing.text


async def test_update_of_a_risky_forward_stays_high_risk(app_client: httpx.AsyncClient) -> None:
    fid = await setup(app_client)
    risky = live(interface="wan", **{"source.network": "any", "destination.port": ""})
    r = await stage(
        app_client,
        fid,
        [risky],
        f"forwards/{TARGET}/update",
        forward=forward(interface="wan", destination="wanip", target="10.0.0.7"),
    )
    assert r.status_code == 201 and r.json()["high_risk"] is True
    assert any("existing forward" in x for x in r.json()["proposed"]["risk"])


async def test_toggle_and_delete(app_client: httpx.AsyncClient) -> None:
    fid = await setup(app_client)
    path = f"forwards/{TARGET}/toggle"
    same = await stage(app_client, fid, [live()], path, enabled=True)
    assert same.status_code == 400 and "already enabled" in same.text
    off = await stage(app_client, fid, [live()], path, enabled=False)
    assert off.status_code == 201 and off.json()["high_risk"] is False
    assert off.json()["proposed"]["enabled"] is False
    busy = await stage(app_client, fid, [live()], f"forwards/{TARGET}/delete")
    assert busy.status_code == 400 and "open request" in busy.text
    cid = off.json()["id"]
    assert (await act(app_client, cid, "cancel")).status_code == 200
    gone = await stage(app_client, fid, [live()], f"forwards/{TARGET}/delete")
    assert gone.status_code == 201 and gone.json()["high_risk"] is True


async def test_automatic_exception_and_bad_ids_are_refused(app_client: httpx.AsyncClient) -> None:
    fid = await setup(app_client)
    path = f"forwards/{TARGET}/delete"
    nordr = await stage(app_client, fid, [live(nordr="1")], path)
    assert nordr.status_code == 400 and "exception" in nordr.text
    auto = await stage(app_client, fid, [live(is_automatic=True)], path)
    assert auto.status_code == 400 and "Automatic" in auto.text
    bad = await stage(app_client, fid, [live()], "forwards/not-a-uuid/delete")
    assert bad.status_code == 422


async def test_only_managers_can_stage(app_client: httpx.AsyncClient) -> None:
    fid = await setup(app_client)
    ok = await stage(app_client, fid, [], forward=forward(description="Fresh"))
    assert ok.status_code == 201
    await switch(app_client, Role.security_admin, "sec")
    denied = await stage(app_client, fid, [], forward=forward(description="Other"))
    assert denied.status_code == 403
    await switch(app_client, Role.admin, "adm")
    cid = ok.json()["id"]
    assert (await act(app_client, cid, "submit")).status_code == 200
    assert (await act(app_client, cid, "approve")).status_code == 200
    with app_client.app.state.sessionmaker() as db:  # type: ignore[attr-defined]
        cr = db.scalar(select(ChangeRequest).where(ChangeRequest.kind == "nat_forward"))
        actions = {a.action for a in db.scalars(select(AuditLog))}
    assert cr is not None and cr.status == "approved"
    assert "change.draft" in actions and "change.approved" in actions
