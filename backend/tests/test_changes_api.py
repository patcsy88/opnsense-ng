"""Alias change requests over HTTP (ADR-0005 step 2). No OPNsense calls are made."""

import uuid
from typing import Any

import httpx
import pytest
import respx
from pydantic import ValidationError
from sqlalchemy import select

from app.changes.schemas import AliasProposal
from app.db.models import AuditLog, Firewall, Role
from tests.conftest import csrf_headers
from tests.test_api import create_fw, login_as

URL = "/api/v1/changes"


def alias(**kw: Any) -> dict[str, Any]:
    body: dict[str, Any] = {
        "name": "test_hosts",
        "type": "host",
        "content": ["10.0.0.1", "10.0.0.2"],
        "description": "Test",
    }
    body.update(kw)
    return body


async def stage(client: httpx.AsyncClient, fid: str, **kw: Any) -> httpx.Response:
    return await client.post(
        f"{URL}/aliases",
        json={"firewall_id": fid, "alias": alias(**kw)},
        headers=csrf_headers(client),
    )


async def act(client: httpx.AsyncClient, cid: str, verb: str) -> httpx.Response:
    return await client.post(f"{URL}/{cid}/{verb}", headers=csrf_headers(client))


async def switch(client: httpx.AsyncClient, role: Role, name: str) -> None:
    await client.post("/api/v1/auth/logout", headers=csrf_headers(client))
    await login_as(client, role, name)


@pytest.mark.parametrize(
    ("kw", "ok"),
    [
        ({}, True),
        ({"name": "1bad"}, False),
        ({"name": "has space"}, False),
        ({"name": "any"}, False),
        ({"name": "x" * 33}, False),
        ({"content": []}, False),
        ({"content": ["not an ip!"]}, False),
        ({"content": ["10.0.0.1/24"]}, False),
        ({"content": ["example.com", "fe80::1"]}, True),
        ({"type": "network", "content": ["10.0.0.0/8", "2001:db8::/32"]}, True),
        ({"type": "network", "content": ["10.0.0.1/24"]}, False),
        ({"type": "network", "content": ["10.0.0.1"]}, False),
        ({"type": "port", "content": ["80", "8000:8100"]}, True),
        ({"type": "port", "content": ["0"]}, False),
        ({"type": "port", "content": ["70000"]}, False),
        ({"type": "port", "content": ["9000:8000"]}, False),
        ({"type": "geoip", "content": ["NL"]}, False),
        ({"description": "bad\nline"}, False),
    ],
)
def test_alias_validation(kw: dict[str, Any], ok: bool) -> None:
    if ok:
        AliasProposal(**alias(**kw))
    else:
        with pytest.raises(ValidationError):
            AliasProposal(**alias(**kw))


def test_alias_content_is_trimmed_and_deduplicated() -> None:
    parsed = AliasProposal(**alias(content=[" 10.0.0.1 ", "10.0.0.1", "10.0.0.2"]))
    assert parsed.content == ["10.0.0.1", "10.0.0.2"]


async def test_full_review_flow_between_two_network_admins(app_client: httpx.AsyncClient) -> None:
    await login_as(app_client, Role.admin)
    fid = await create_fw(app_client)
    await switch(app_client, Role.network_admin, "alice")
    with respx.mock(assert_all_called=False) as router:  # any OPNsense call would be unmocked
        created = await stage(app_client, fid)
        assert created.status_code == 201
        body = created.json()
        assert body["status"] == "validated" and body["requester_username"] == "alice"
        cid = body["id"]
        assert (await act(app_client, cid, "submit")).json()["status"] == "in_review"
        own = await act(app_client, cid, "approve")  # four-eyes
        assert own.status_code == 403
        await switch(app_client, Role.network_admin, "bob")
        approved = await act(app_client, cid, "approve")
        assert approved.status_code == 200
        out = approved.json()
        assert out["status"] == "approved" and out["reviewer_username"] == "bob"
        assert out["self_approved"] is False
        assert [e["to_status"] for e in out["events"]] == [
            "draft",
            "validated",
            "in_review",
            "approved",
        ]
        assert not router.calls  # nothing was sent to a firewall


async def test_admin_can_self_approve_and_it_is_flagged(app_client: httpx.AsyncClient) -> None:
    await login_as(app_client, Role.admin)
    fid = await create_fw(app_client)
    cid = (await stage(app_client, fid)).json()["id"]
    await act(app_client, cid, "submit")
    result = await act(app_client, cid, "approve")
    assert result.status_code == 200 and result.json()["self_approved"] is True


async def test_reject_and_cancel(app_client: httpx.AsyncClient) -> None:
    await login_as(app_client, Role.admin)
    fid = await create_fw(app_client)
    first = (await stage(app_client, fid, name="a_one")).json()["id"]
    await act(app_client, first, "submit")
    assert (await act(app_client, first, "reject")).json()["status"] == "rejected"
    second = (await stage(app_client, fid, name="a_two")).json()["id"]
    assert (await act(app_client, second, "cancel")).json()["status"] == "cancelled"
    assert (await act(app_client, second, "submit")).status_code == 409  # terminal


async def test_cannot_approve_before_review_or_skip_steps(app_client: httpx.AsyncClient) -> None:
    await login_as(app_client, Role.admin)
    fid = await create_fw(app_client)
    cid = (await stage(app_client, fid)).json()["id"]
    assert (await act(app_client, cid, "approve")).status_code == 409


async def test_view_only_roles_cannot_stage_or_move(app_client: httpx.AsyncClient) -> None:
    await login_as(app_client, Role.admin)
    fid = await create_fw(app_client)
    cid = (await stage(app_client, fid)).json()["id"]
    for role in (Role.read_only, Role.security_admin):
        await switch(app_client, role, f"v_{role.value}")
        assert (await stage(app_client, fid, name="other")).status_code == 403
        assert (await act(app_client, cid, "submit")).status_code == 403
        assert (await app_client.get(f"{URL}/{cid}")).status_code == 200  # may view
        assert len((await app_client.get(URL)).json()) == 1


async def test_unauthenticated_and_csrf(app_client: httpx.AsyncClient) -> None:
    assert (await app_client.get(URL)).status_code == 401
    assert (await app_client.post(f"{URL}/aliases", json={})).status_code in (401, 403)
    await login_as(app_client, Role.admin)
    fid = await create_fw(app_client)
    no_csrf = await app_client.post(f"{URL}/aliases", json={"firewall_id": fid, "alias": alias()})
    assert no_csrf.status_code == 403


async def test_validation_errors_and_unknown_fields(app_client: httpx.AsyncClient) -> None:
    await login_as(app_client, Role.admin)
    fid = await create_fw(app_client)
    assert (await stage(app_client, fid, name="bad name")).status_code == 422
    extra = await app_client.post(
        f"{URL}/aliases",
        json={"firewall_id": fid, "alias": alias(), "status": "approved"},
        headers=csrf_headers(app_client),
    )
    assert extra.status_code == 422
    unknown_fw = await stage(app_client, str(uuid.uuid4()))
    assert unknown_fw.status_code == 400


async def test_duplicate_open_request_is_refused_until_closed(
    app_client: httpx.AsyncClient,
) -> None:
    await login_as(app_client, Role.admin)
    fid = await create_fw(app_client)
    first = (await stage(app_client, fid)).json()["id"]
    assert (await stage(app_client, fid)).status_code == 400
    await act(app_client, first, "cancel")
    assert (await stage(app_client, fid)).status_code == 201


async def test_unknown_change_and_bad_status_filter(app_client: httpx.AsyncClient) -> None:
    await login_as(app_client, Role.admin)
    assert (await app_client.get(f"{URL}/{uuid.uuid4()}")).status_code == 404
    assert (await app_client.get(f"{URL}?status=bogus")).status_code == 422
    fid = await create_fw(app_client)
    await stage(app_client, fid)
    listed = await app_client.get(f"{URL}?status=validated&firewall_id={fid}")
    assert len(listed.json()) == 1


async def test_denials_and_flow_are_audited_without_content(
    app_client: httpx.AsyncClient,
) -> None:
    await login_as(app_client, Role.admin)
    fid = await create_fw(app_client)
    await switch(app_client, Role.network_admin, "alice")
    cid = (await stage(app_client, fid, description="private note")).json()["id"]
    await act(app_client, cid, "submit")
    await act(app_client, cid, "approve")  # denied: own request
    with app_client.app.state.sessionmaker() as db:  # type: ignore[attr-defined]
        rows = list(db.scalars(select(AuditLog).where(AuditLog.action.like("change.%"))))
        assert db.scalars(select(Firewall)).first() is not None
    actions = [(r.action, r.outcome) for r in rows]
    assert ("change.validated", "success") in actions
    assert ("change.in_review", "success") in actions
    assert ("change.approved", "denied") in actions
    assert "private note" not in " ".join(str(r.detail) for r in rows)
