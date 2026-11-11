"""Alias update and delete requests (ADR-0005 step 5). OPNsense is mocked."""

import json
from typing import Any

import httpx
import pytest
import respx
from sqlalchemy import select

from app.db.models import AuditLog, ChangeRequest, Role
from app.opnsense.registry import get_operation
from tests.conftest import csrf_headers
from tests.test_api import create_fw, login_as
from tests.test_changes_api import act, switch

BASE = "https://fw.example.test"
LIST = f"{BASE}/api/firewall/alias/searchItem"
RECONF = f"{BASE}/api/firewall/alias/reconfigure"
CHANGES = "/api/v1/changes"
UUID = "ec691b46-6d4c-4fa5-88cc-54589859a1c9"
SET = f"{BASE}/api/firewall/alias/setItem/{UUID}"
DEL = f"{BASE}/api/firewall/alias/delItem/{UUID}"


def row(**kw: Any) -> dict[str, Any]:
    base = {
        "uuid": UUID,
        "name": "web",
        "type": "host",
        "enabled": "1",
        "description": "Web",
        "content": "10.0.0.1\n10.0.0.2",
    }
    base.update(kw)
    return base


def proposal(**kw: Any) -> dict[str, Any]:
    body: dict[str, Any] = {
        "name": "web",
        "type": "host",
        "content": ["10.0.0.1", "10.0.0.9"],
        "description": "Web",
        "enabled": True,
    }
    body.update(kw)
    return body


async def stage_update(
    client: httpx.AsyncClient, fid: str, target: str = UUID, **kw: Any
) -> httpx.Response:
    return await client.post(
        f"{CHANGES}/aliases/{target}/update",
        json={"firewall_id": fid, "alias": proposal(**kw)},
        headers=csrf_headers(client),
    )


async def stage_delete(client: httpx.AsyncClient, fid: str, target: str = UUID) -> httpx.Response:
    return await client.post(
        f"{CHANGES}/aliases/{target}/delete",
        json={"firewall_id": fid},
        headers=csrf_headers(client),
    )


async def setup(client: httpx.AsyncClient) -> str:
    await login_as(client, Role.admin)
    fid = await create_fw(client)
    r = await client.patch(
        f"/api/v1/firewalls/{fid}", json={"allow_writes": True}, headers=csrf_headers(client)
    )
    assert r.status_code == 200
    return fid


async def approve(client: httpx.AsyncClient, cid: str) -> None:
    await act(client, cid, "submit")
    assert (await act(client, cid, "approve")).status_code == 200


async def apply(client: httpx.AsyncClient, cid: str, **body: Any) -> httpx.Response:
    return await client.post(f"{CHANGES}/{cid}/apply", json=body, headers=csrf_headers(client))


def test_registry_resolves_only_valid_uuids() -> None:
    op = get_operation("firewall.aliases.delete")
    assert op.resolve_endpoint({"uuid": UUID}).endswith(f"/delItem/{UUID}")
    for bad in ("../x", UUID.upper(), UUID + "/x", "", "1", f"{UUID}?a=b"):
        with pytest.raises(ValueError):
            op.resolve_endpoint({"uuid": bad})
    with pytest.raises(ValueError):
        op.resolve_endpoint({})
    with pytest.raises(ValueError):
        op.resolve_endpoint({"other": UUID})


async def test_update_records_base_and_applies_in_order(app_client: httpx.AsyncClient) -> None:
    fid = await setup(app_client)
    with respx.mock() as router:
        router.get(LIST).respond(200, json={"rows": [row()]})
        staged = await stage_update(app_client, fid)
    assert staged.status_code == 201
    body = staged.json()
    assert body["action"] == "update" and body["target_uuid"] == UUID
    assert body["base_snapshot"]["content"] == ["10.0.0.1", "10.0.0.2"]
    assert body["status"] == "validated" and body["high_risk"] is False
    await approve(app_client, body["id"])
    after = row(content="10.0.0.1\n10.0.0.9")
    with respx.mock() as router:
        lst = router.get(LIST).mock(
            side_effect=[
                httpx.Response(200, json={"rows": [row()]}),
                httpx.Response(200, json={"rows": [after]}),
            ]
        )
        setr = router.post(SET).respond(200, json={"result": "saved"})
        rec = router.post(RECONF).respond(200, json={"status": "ok"})
        done = await apply(app_client, body["id"])
        order = [c.request.url.path for c in router.calls]
    assert done.json()["status"] == "applied"
    assert lst.call_count == 2 and setr.call_count == 1 and rec.call_count == 1
    assert order.index(f"/api/firewall/alias/setItem/{UUID}") < order.index(
        "/api/firewall/alias/reconfigure"
    )
    sent = json.loads(setr.calls.last.request.content)
    assert sent["alias"]["content"] == "10.0.0.1\n10.0.0.9"
    with app_client.app.state.sessionmaker() as db:  # type: ignore[attr-defined]
        snap = db.scalars(select(ChangeRequest)).one().result_snapshot
    assert snap is not None and snap["content"] == ["10.0.0.1", "10.0.0.9"]


async def test_update_is_stale_when_alias_changed_after_staging(
    app_client: httpx.AsyncClient,
) -> None:
    fid = await setup(app_client)
    with respx.mock() as router:
        router.get(LIST).respond(200, json={"rows": [row()]})
        cid = (await stage_update(app_client, fid)).json()["id"]
    await approve(app_client, cid)
    with respx.mock(assert_all_called=False) as router:
        router.get(LIST).respond(200, json={"rows": [row(content="10.9.9.9")]})
        setr = router.post(SET)
        r = await apply(app_client, cid)
    assert (
        r.json()["status"] == "stale" and "changed on the firewall" in r.json()["failure_message"]
    )
    assert setr.call_count == 0


async def test_update_is_stale_when_alias_was_removed(app_client: httpx.AsyncClient) -> None:
    fid = await setup(app_client)
    with respx.mock() as router:
        router.get(LIST).respond(200, json={"rows": [row()]})
        cid = (await stage_update(app_client, fid)).json()["id"]
    await approve(app_client, cid)
    with respx.mock(assert_all_called=False) as router:
        router.get(LIST).respond(200, json={"rows": []})
        setr = router.post(SET)  # setItem would create it again: it must never be called
        r = await apply(app_client, cid)
    assert r.json()["status"] == "stale" and setr.call_count == 0


async def test_update_refuses_rename_type_change_and_unknown_alias(
    app_client: httpx.AsyncClient,
) -> None:
    fid = await setup(app_client)
    with respx.mock() as router:
        router.get(LIST).respond(200, json={"rows": [row()]})
        assert (await stage_update(app_client, fid, name="other")).status_code == 400
        assert (
            await stage_update(app_client, fid, type="network", content=["10.0.0.0/8"])
        ).status_code == 400
        other = "11111111-2222-4333-8444-555555555555"
        assert (await stage_update(app_client, fid, target=other)).status_code == 400
        assert (await stage_update(app_client, fid, target="not-a-uuid")).status_code == 422
        assert (await stage_update(app_client, fid, target=UUID.upper())).status_code == 422


async def test_update_can_disable_an_alias(app_client: httpx.AsyncClient) -> None:
    fid = await setup(app_client)
    with respx.mock() as router:
        router.get(LIST).respond(200, json={"rows": [row()]})
        r = await stage_update(app_client, fid, content=["10.0.0.1", "10.0.0.2"], enabled=False)
    assert r.status_code == 201 and r.json()["proposed"]["enabled"] is False


async def test_duplicate_open_request_for_same_alias_is_refused(
    app_client: httpx.AsyncClient,
) -> None:
    fid = await setup(app_client)
    with respx.mock() as router:
        router.get(LIST).respond(200, json={"rows": [row()]})
        first = await stage_update(app_client, fid)
        assert first.status_code == 201
        assert (await stage_update(app_client, fid)).status_code == 400
        assert (await stage_delete(app_client, fid)).status_code == 400
        await act(app_client, first.json()["id"], "cancel")
        assert (await stage_delete(app_client, fid)).status_code == 201


async def test_staging_reads_the_firewall_but_never_writes(app_client: httpx.AsyncClient) -> None:
    fid = await setup(app_client)
    with respx.mock(assert_all_called=False) as router:
        router.get(LIST).respond(200, json={"rows": [row()]})
        writes = [router.post(SET), router.post(DEL), router.post(RECONF)]
        await stage_update(app_client, fid)
        await stage_delete(app_client, fid)
    assert all(w.call_count == 0 for w in writes)


async def test_staging_fails_cleanly_when_firewall_unreachable(
    app_client: httpx.AsyncClient,
) -> None:
    fid = await setup(app_client)
    with respx.mock() as router:
        router.get(LIST).mock(side_effect=httpx.ConnectError("down"))
        r = await stage_update(app_client, fid)
    assert r.status_code == 400 and "Could not read" in r.json()["detail"]


async def test_delete_is_high_risk_needs_admin_approver_and_typed_name(
    app_client: httpx.AsyncClient,
) -> None:
    fid = await setup(app_client)
    await switch(app_client, Role.network_admin, "alice")
    with respx.mock() as router:
        router.get(LIST).respond(200, json={"rows": [row()]})
        staged = (await stage_delete(app_client, fid)).json()
    cid = staged["id"]
    assert staged["high_risk"] is True and staged["action"] == "delete"
    await act(app_client, cid, "submit")
    await switch(app_client, Role.network_admin, "bob")
    assert (await act(app_client, cid, "approve")).status_code == 403  # high risk: admin only
    await switch(app_client, Role.admin, "root2")
    assert (await act(app_client, cid, "approve")).status_code == 200
    with respx.mock(assert_all_called=False) as router:
        wrong = await apply(app_client, cid, confirm_name="nope")
        assert not router.calls
    assert wrong.status_code == 400 and "Type the alias name" in wrong.json()["detail"]
    with respx.mock() as router:
        router.get(LIST).mock(
            side_effect=[
                httpx.Response(200, json={"rows": [row()]}),
                httpx.Response(200, json={"rows": []}),
            ]
        )
        dele = router.post(DEL).respond(200, json={"result": "deleted"})
        router.post(RECONF).respond(200, json={"status": "ok"})
        done = await apply(app_client, cid, confirm_name="web")
    assert done.json()["status"] == "applied" and dele.call_count == 1


async def test_delete_of_alias_in_use_ends_failed_with_the_firewall_message(
    app_client: httpx.AsyncClient,
) -> None:
    fid = await setup(app_client)
    with respx.mock() as router:
        router.get(LIST).respond(200, json={"rows": [row()]})
        cid = (await stage_delete(app_client, fid)).json()["id"]
    await approve(app_client, cid)
    with respx.mock(assert_all_called=False) as router:
        router.get(LIST).respond(200, json={"rows": [row()]})
        router.post(DEL).respond(
            200, json={"status": 500, "message": "Cannot delete alias web.\nCurrently in use by x"}
        )
        reconf = router.post(RECONF)
        r = await apply(app_client, cid, confirm_name="web")
    body = r.json()
    assert body["status"] == "failed"
    assert "Currently in use by x" in body["failure_message"]
    assert reconf.call_count == 0


async def test_delete_http_500_is_reported_as_possibly_in_use(
    app_client: httpx.AsyncClient,
) -> None:
    fid = await setup(app_client)
    with respx.mock() as router:
        router.get(LIST).respond(200, json={"rows": [row()]})
        cid = (await stage_delete(app_client, fid)).json()["id"]
    await approve(app_client, cid)
    with respx.mock(assert_all_called=False) as router:
        router.get(LIST).respond(200, json={"rows": [row()]})
        dele = router.post(DEL).respond(500)
        r = await apply(app_client, cid, confirm_name="web")
    assert r.json()["status"] == "failed" and "may still be in use" in r.json()["failure_message"]
    assert dele.call_count == 1  # never retried


async def test_view_only_roles_cannot_stage(app_client: httpx.AsyncClient) -> None:
    fid = await setup(app_client)
    for role in (Role.read_only, Role.security_admin):
        await switch(app_client, role, f"v_{role.value}")
        with respx.mock(assert_all_called=False) as router:
            assert (await stage_update(app_client, fid)).status_code == 403
            assert (await stage_delete(app_client, fid)).status_code == 403
        assert not router.calls


async def test_staging_requires_csrf_and_is_audited(app_client: httpx.AsyncClient) -> None:
    fid = await setup(app_client)
    with respx.mock(assert_all_called=False) as router:
        r = await app_client.post(f"{CHANGES}/aliases/{UUID}/delete", json={"firewall_id": fid})
        assert r.status_code == 403 and not router.calls
    with respx.mock() as router:
        router.get(LIST).respond(200, json={"rows": [row()]})
        await stage_delete(app_client, fid)
    with app_client.app.state.sessionmaker() as db:  # type: ignore[attr-defined]
        actions = {a.action for a in db.scalars(select(AuditLog))}
    assert "firewall.firewall.aliases.list" in actions and "change.validated" in actions
