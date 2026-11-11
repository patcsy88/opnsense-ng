"""Applying an approved alias-create request (ADR-0005 step 3). OPNsense is mocked."""

import json
from typing import Any

import httpx
import respx
from sqlalchemy import select

from app.db.models import AuditLog, ChangeRequest, Role
from tests.conftest import csrf_headers
from tests.test_api import create_fw, login_as
from tests.test_changes_api import act, stage, switch

BASE = "https://fw.example.test"
LIST = f"{BASE}/api/firewall/alias/searchItem"
ADD = f"{BASE}/api/firewall/alias/addItem"
RECONF = f"{BASE}/api/firewall/alias/reconfigure"
CHANGES = "/api/v1/changes"


async def approved_change(
    client: httpx.AsyncClient, *, allow_writes: bool = True
) -> tuple[str, str]:
    """Admin creates the firewall; returns (firewall_id, change_id) approved and ready."""
    await login_as(client, Role.admin)
    fid = await create_fw(client)
    if allow_writes:
        r = await client.patch(
            f"/api/v1/firewalls/{fid}", json={"allow_writes": True}, headers=csrf_headers(client)
        )
        assert r.status_code == 200 and r.json()["allow_writes"] is True
    cid = (await stage(client, fid)).json()["id"]
    await act(client, cid, "submit")
    assert (await act(client, cid, "approve")).status_code == 200
    return fid, cid


async def apply(client: httpx.AsyncClient, cid: str, **body: Any) -> httpx.Response:
    return await client.post(f"{CHANGES}/{cid}/apply", json=body, headers=csrf_headers(client))


def mock_firewall(
    router: respx.MockRouter,
    *,
    existing: list[dict[str, Any]] | None = None,
    add: dict[str, Any] | None = None,
    reconf: dict[str, Any] | None = None,
) -> tuple[respx.Route, respx.Route, respx.Route]:
    rows = existing or []
    after = [
        *rows,
        {
            "uuid": "new-1",
            "name": "test_hosts",
            "type": "host",
            "enabled": "1",
            "content": "10.0.0.1\n10.0.0.2",
        },
    ]
    lst = router.get(LIST).mock(
        side_effect=[
            httpx.Response(200, json={"rows": rows}),
            httpx.Response(200, json={"rows": after}),
        ]
    )
    a = router.post(ADD).respond(200, json=add or {"result": "saved", "uuid": "new-1"})
    r = router.post(RECONF).respond(200, json=reconf or {"status": "ok"})
    return lst, a, r


async def test_successful_apply_saves_then_activates_and_audits(
    app_client: httpx.AsyncClient,
) -> None:
    _fid, cid = await approved_change(app_client)
    with respx.mock() as router:
        lst, add, reconf = mock_firewall(router)
        r = await apply(app_client, cid)
        order = [c.request.url.path for c in router.calls]
    assert r.status_code == 200
    body = r.json()
    assert body["status"] == "applied" and body["applier_username"] == "admin"
    assert body["events"][-2]["to_status"] == "applying"
    assert add.call_count == 1 and reconf.call_count == 1 and lst.call_count == 2
    sent = json.loads(add.calls.last.request.content)
    assert sent == {
        "alias": {
            "enabled": "1",
            "name": "test_hosts",
            "type": "host",
            "content": "10.0.0.1\n10.0.0.2",
            "description": "Test",
        }
    }
    assert order.index("/api/firewall/alias/addItem") < order.index(
        "/api/firewall/alias/reconfigure"
    )
    with app_client.app.state.sessionmaker() as db:  # type: ignore[attr-defined]
        actions = [(a.action, a.outcome) for a in db.scalars(select(AuditLog))]
        snap = db.scalars(select(ChangeRequest)).one().result_snapshot
    assert ("firewall.firewall.aliases.add", "success") in actions
    assert ("firewall.firewall.aliases.reconfigure", "success") in actions
    assert ("change.applied", "success") in actions
    assert snap is not None and snap["name"] == "test_hosts"


async def test_apply_refused_when_writes_are_off_and_nothing_is_sent(
    app_client: httpx.AsyncClient,
) -> None:
    _fid, cid = await approved_change(app_client, allow_writes=False)
    with respx.mock(assert_all_called=False) as router:
        r = await apply(app_client, cid)
    assert r.status_code == 403 and "not enabled" in r.json()["detail"]
    assert not router.calls
    assert (await app_client.get(f"{CHANGES}/{cid}")).json()["status"] == "approved"


async def test_only_admin_can_apply(app_client: httpx.AsyncClient) -> None:
    _fid, cid = await approved_change(app_client)
    for role in (Role.network_admin, Role.security_admin, Role.read_only):
        await switch(app_client, role, f"u_{role.value}")
        with respx.mock(assert_all_called=False) as router:
            assert (await apply(app_client, cid)).status_code == 403
        assert not router.calls


async def test_requires_csrf_and_authentication(app_client: httpx.AsyncClient) -> None:
    assert (
        await app_client.post(f"{CHANGES}/{'0' * 8}-0000-0000-0000-{'0' * 12}/apply")
    ).status_code in (401, 403)
    _fid, cid = await approved_change(app_client)
    with respx.mock(assert_all_called=False) as router:
        r = await app_client.post(f"{CHANGES}/{cid}/apply", json={})
    assert r.status_code == 403 and not router.calls


async def test_unapproved_request_cannot_be_applied(app_client: httpx.AsyncClient) -> None:
    await login_as(app_client, Role.admin)
    fid = await create_fw(app_client)
    await app_client.patch(
        f"/api/v1/firewalls/{fid}", json={"allow_writes": True}, headers=csrf_headers(app_client)
    )
    cid = (await stage(app_client, fid)).json()["id"]  # only validated
    with respx.mock(assert_all_called=False) as router:
        r = await apply(app_client, cid)
    assert r.status_code == 409 and not router.calls


async def test_stale_when_name_appeared_on_the_firewall(app_client: httpx.AsyncClient) -> None:
    _fid, cid = await approved_change(app_client)
    with respx.mock(assert_all_called=False) as router:
        router.get(LIST).respond(
            200, json={"rows": [{"uuid": "x", "name": "test_hosts", "type": "host"}]}
        )
        add = router.post(ADD)
        r = await apply(app_client, cid)
    assert r.status_code == 200 and r.json()["status"] == "stale"
    assert "nothing was changed" in r.json()["failure_message"]
    assert add.call_count == 0


async def test_firewall_validation_error_marks_failed_and_does_not_activate(
    app_client: httpx.AsyncClient,
) -> None:
    _fid, cid = await approved_change(app_client)
    with respx.mock(assert_all_called=False) as router:
        _lst, _add, reconf = mock_firewall(
            router, add={"result": "failed", "validations": {"alias.name": "already in use"}}
        )
        r = await apply(app_client, cid)
    body = r.json()
    assert body["status"] == "failed" and "alias.name: already in use" in body["failure_message"]
    assert reconf.call_count == 0


async def test_activation_failure_is_reported_as_saved_but_not_active(
    app_client: httpx.AsyncClient,
) -> None:
    _fid, cid = await approved_change(app_client)
    with respx.mock() as router:
        mock_firewall(router, reconf={"status": "error"})
        r = await apply(app_client, cid)
    body = r.json()
    assert body["status"] == "failed"
    assert "saved on the firewall but NOT active" in body["failure_message"]


async def test_forbidden_privilege_is_reported_and_not_retried(
    app_client: httpx.AsyncClient,
) -> None:
    _fid, cid = await approved_change(app_client)
    with respx.mock() as router:
        router.get(LIST).respond(200, json={"rows": []})
        add = router.post(ADD).respond(403)
        r = await apply(app_client, cid)
    assert r.json()["status"] == "failed" and "privilege" in r.json()["failure_message"]
    assert add.call_count == 1


async def test_applied_request_cannot_be_applied_twice(app_client: httpx.AsyncClient) -> None:
    _fid, cid = await approved_change(app_client)
    with respx.mock() as router:
        mock_firewall(router)
        assert (await apply(app_client, cid)).json()["status"] == "applied"
    with respx.mock(assert_all_called=False) as router:
        again = await apply(app_client, cid)
    assert again.status_code == 409 and not router.calls


async def test_allow_writes_is_admin_only_audited_and_defaults_off(
    app_client: httpx.AsyncClient,
) -> None:
    await login_as(app_client, Role.admin)
    fid = await create_fw(app_client)
    listed = await app_client.get("/api/v1/firewalls")
    assert [f["allow_writes"] for f in listed.json() if f["id"] == fid] == [False]
    await app_client.patch(
        f"/api/v1/firewalls/{fid}", json={"allow_writes": True}, headers=csrf_headers(app_client)
    )
    with app_client.app.state.sessionmaker() as db:  # type: ignore[attr-defined]
        row = db.scalars(select(AuditLog).where(AuditLog.action == "firewall.update")).one()
    assert row.detail is not None and row.detail["allow_writes"] == {"old": False, "new": True}
    await switch(app_client, Role.network_admin, "n1")
    denied = await app_client.patch(
        f"/api/v1/firewalls/{fid}", json={"allow_writes": False}, headers=csrf_headers(app_client)
    )
    assert denied.status_code == 403
