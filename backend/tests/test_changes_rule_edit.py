"""Rule update and delete requests (ADR-0005 step 6, slice 4). OPNsense is mocked."""

import json
from typing import Any

import httpx
import respx
from sqlalchemy import select

from app.db.models import AuditLog, ChangeRequest, Role
from tests.conftest import csrf_headers
from tests.test_changes_api import act, switch
from tests.test_changes_rule_create import (
    APPLY,
    CHANGES,
    RULES,
    apply,
    approve,
    existing,
    mock_reads,
    proposal,
    setup,
)

TARGET = "0b3a6c1e-1d2f-4a5b-8c7d-9e0f1a2b3c4d"
SET = f"https://fw.example.test/api/firewall/filter/setRule/{TARGET}"
DEL = f"https://fw.example.test/api/firewall/filter/delRule/{TARGET}"


def live(**kw: Any) -> dict[str, Any]:
    return existing(
        protocol="TCP",
        source_net="10.0.0.0/24",
        destination_net="10.0.1.5",
        destination_port="443",
        **kw,
    )


def edit(**kw: Any) -> dict[str, Any]:
    return proposal(**{"description": "Old rule", "destination_port": "8443", **kw})


async def stage_update(client: httpx.AsyncClient, fid: str, **kw: Any) -> httpx.Response:
    return await client.post(
        f"{CHANGES}/rules/{TARGET}/update",
        json={"firewall_id": fid, "rule": edit(**kw)},
        headers=csrf_headers(client),
    )


async def stage_delete(client: httpx.AsyncClient, fid: str) -> httpx.Response:
    return await client.post(
        f"{CHANGES}/rules/{TARGET}/delete",
        json={"firewall_id": fid},
        headers=csrf_headers(client),
    )


async def staged_update(client: httpx.AsyncClient, fid: str, **kw: Any) -> str:
    with respx.mock(assert_all_called=False) as router:
        mock_reads(router, [live()])
        r = await stage_update(client, fid, **kw)
    assert r.status_code == 201, r.text
    return str(r.json()["id"])


async def test_update_saves_then_activates_and_keeps_sequence(
    app_client: httpx.AsyncClient,
) -> None:
    fid = await setup(app_client)
    cid = await staged_update(app_client, fid)
    await approve(app_client, cid)
    after = live()
    after["destination_port"] = "8443"
    with respx.mock() as router:
        router.get(RULES).mock(
            side_effect=[
                httpx.Response(200, json={"rows": [live()]}),
                httpx.Response(200, json={"rows": [after]}),
            ]
        )
        route = router.post(SET).respond(200, json={"result": "saved"})
        act_route = router.post(APPLY).respond(200, json={"status": "ok"})
        done = await apply(app_client, cid)
        order = [c.request.url.path for c in router.calls]
    assert done.json()["status"] == "applied", done.text
    assert order.index(f"/api/firewall/filter/setRule/{TARGET}") < order.index(
        "/api/firewall/filter/apply"
    )
    sent = json.loads(route.calls.last.request.content)["rule"]
    assert sent["sequence"] == "40" and sent["destination_port"] == "8443"
    assert act_route.call_count == 1
    with app_client.app.state.sessionmaker() as db:  # type: ignore[attr-defined]
        actions = {a.action for a in db.scalars(select(AuditLog))}
    assert "firewall.firewall.rules.update" in actions


async def test_update_is_stale_when_rule_changed_or_removed(app_client: httpx.AsyncClient) -> None:
    fid = await setup(app_client)
    cid = await staged_update(app_client, fid)
    await approve(app_client, cid)
    with respx.mock(assert_all_called=False) as router:
        mock_reads(router, [live(enabled="0")])
        write = router.post(SET)
        r = await apply(app_client, cid)
    assert r.json()["status"] == "stale" and write.call_count == 0

    cid2 = await staged_update(app_client, fid)
    await approve(app_client, cid2)
    with respx.mock(assert_all_called=False) as router:
        mock_reads(router, [])
        write = router.post(SET)
        r = await apply(app_client, cid2)
    assert r.json()["status"] == "stale" and write.call_count == 0


async def test_update_stale_when_alias_vanishes(app_client: httpx.AsyncClient) -> None:
    fid = await setup(app_client)
    aliases = [{"uuid": "b" * 8 + "-1111-4222-8333-444444444444", "name": "web", "type": "host"}]
    with respx.mock(assert_all_called=False) as router:
        mock_reads(router, [live()], aliases)
        r = await stage_update(app_client, fid, destination="web")
    assert r.status_code == 201
    cid = r.json()["id"]
    await approve(app_client, cid)
    with respx.mock(assert_all_called=False) as router:
        mock_reads(router, [live()], [])
        write = router.post(SET)
        out = await apply(app_client, cid)
    assert out.json()["status"] == "stale" and write.call_count == 0


async def test_update_staging_refuses_identity_changes_and_system_rules(
    app_client: httpx.AsyncClient,
) -> None:
    fid = await setup(app_client)
    with respx.mock(assert_all_called=False) as router:
        mock_reads(router, [live(), live(uuid="c" * 8 + "-1111-4222-8333-444444444444")])
        assert (await stage_update(app_client, fid, interface="opt1")).status_code == 400
        other = await app_client.post(
            f"{CHANGES}/rules/{TARGET}/update",
            json={"firewall_id": fid, "rule": proposal(description="Renamed")},
            headers=csrf_headers(app_client),
        )
        assert other.status_code == 400
        missing = await app_client.post(
            f"{CHANGES}/rules/{'d' * 8}-1111-4222-8333-444444444444/update",
            json={"firewall_id": fid, "rule": edit()},
            headers=csrf_headers(app_client),
        )
        assert missing.status_code == 400
        bad = await app_client.post(
            f"{CHANGES}/rules/not-a-uuid/update",
            json={"firewall_id": fid, "rule": edit()},
            headers=csrf_headers(app_client),
        )
        assert bad.status_code == 422
    with respx.mock(assert_all_called=False) as router:
        mock_reads(router, [live(sequence=None)])
        assert (await stage_update(app_client, fid)).status_code == 400


async def test_update_blocks_second_open_request_and_flags_risk(
    app_client: httpx.AsyncClient,
) -> None:
    fid = await setup(app_client)
    with respx.mock(assert_all_called=False) as router:
        mock_reads(router, [live()])
        first = await stage_update(app_client, fid)
        second = await stage_update(app_client, fid, log=True)
        assert first.json()["high_risk"] is False
        assert second.status_code == 400
    with respx.mock(assert_all_called=False) as router:
        mock_reads(router, [live(interface="wan")])
        risky = await app_client.post(
            f"{CHANGES}/rules/{TARGET}/update",
            json={"firewall_id": fid, "rule": proposal(description="Old rule", interface="wan")},
            headers=csrf_headers(app_client),
        )
    assert risky.status_code == 400  # first request is still open on this rule


async def test_update_becoming_pass_any_is_high_risk(app_client: httpx.AsyncClient) -> None:
    fid = await setup(app_client)
    with respx.mock(assert_all_called=False) as router:
        mock_reads(router, [live()])
        r = await stage_update(
            app_client, fid, source="any", destination="any", protocol="any", destination_port=""
        )
    assert r.json()["high_risk"] is True


async def test_delete_is_high_risk_and_needs_admin_and_typed_description(
    app_client: httpx.AsyncClient,
) -> None:
    fid = await setup(app_client)
    await switch(app_client, Role.network_admin, "alice")
    with respx.mock(assert_all_called=False) as router:
        mock_reads(router, [live()])
        r = await stage_delete(app_client, fid)
    body = r.json()
    cid = body["id"]
    assert body["high_risk"] is True and body["action"] == "delete"
    await act(app_client, cid, "submit")
    await switch(app_client, Role.network_admin, "bob")
    assert (await act(app_client, cid, "approve")).status_code == 403
    await switch(app_client, Role.admin, "root2")
    assert (await act(app_client, cid, "approve")).status_code == 200
    with respx.mock(assert_all_called=False) as router:
        wrong = await apply(app_client, cid, confirm_name="nope")
        assert not router.calls
    assert wrong.status_code == 400
    with respx.mock(assert_all_called=False) as router:
        mock_reads(router, [live()])
        gone = router.post(DEL).respond(200, json={"result": "deleted"})
        router.post(APPLY).respond(200, json={"status": "ok"})
        done = await apply(app_client, cid, confirm_name="Old rule")
    assert done.json()["status"] == "applied", done.text
    assert gone.call_count == 1
    with app_client.app.state.sessionmaker() as db:  # type: ignore[attr-defined]
        assert db.scalars(select(ChangeRequest)).one().result_snapshot is None


async def test_delete_stale_and_failure_paths(app_client: httpx.AsyncClient) -> None:
    fid = await setup(app_client)
    with respx.mock(assert_all_called=False) as router:
        mock_reads(router, [live()])
        cid = (await stage_delete(app_client, fid)).json()["id"]
    await approve(app_client, cid)
    with respx.mock(assert_all_called=False) as router:
        mock_reads(router, [live(action="block")])
        gone = router.post(DEL)
        r = await apply(app_client, cid, confirm_name="Old rule")
    assert r.json()["status"] == "stale" and gone.call_count == 0

    with respx.mock(assert_all_called=False) as router:
        mock_reads(router, [live()])
        cid2 = (await stage_delete(app_client, fid)).json()["id"]
    await approve(app_client, cid2)
    with respx.mock(assert_all_called=False) as router:
        mock_reads(router, [live()])
        router.post(DEL).respond(200, json={"result": "not found"})
        activate = router.post(APPLY)
        r = await apply(app_client, cid2, confirm_name="Old rule")
    assert r.json()["status"] == "failed" and activate.call_count == 0


async def test_update_and_delete_are_manager_only_and_never_write_at_staging(
    app_client: httpx.AsyncClient,
) -> None:
    fid = await setup(app_client)
    for role in (Role.read_only, Role.security_admin):
        await switch(app_client, role, f"v_{role.value}")
        with respx.mock(assert_all_called=False) as router:
            assert (await stage_update(app_client, fid)).status_code == 403
            assert (await stage_delete(app_client, fid)).status_code == 403
        assert not router.calls
    await switch(app_client, Role.network_admin, "net")
    with respx.mock(assert_all_called=False) as router:
        mock_reads(router, [live()])
        writes = [router.post(SET), router.post(DEL), router.post(APPLY)]
        await stage_update(app_client, fid)
    assert all(w.call_count == 0 for w in writes)
