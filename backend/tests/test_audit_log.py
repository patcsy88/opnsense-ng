"""Audit log viewer and purge (ADR-0011)."""

import uuid
from datetime import timedelta

import httpx
import pytest
from sqlalchemy import func, select

from app.api.audit_log import public_detail
from app.core.config import Settings, get_settings
from app.db.models import AuditLog, Role, utcnow
from tests.conftest import csrf_headers
from tests.test_api import create_fw, login_as
from tests.test_changes_api import switch
from tests.test_security import db_rows, override

pytestmark = pytest.mark.usefixtures("db")


def seed(client: httpx.AsyncClient, rows: list[dict[str, object]]) -> None:
    with client.app.state.sessionmaker() as s:  # type: ignore[attr-defined]
        for r in rows:
            s.add(AuditLog(**r))
        s.commit()


def old(days: int) -> object:
    return utcnow() - timedelta(days=days)


def test_public_detail_keeps_only_flat_scalars() -> None:
    detail = {
        "reason": "x" * 500,
        "n": 3,
        "ok": True,
        "none": None,
        "nested": {"a": 1},
        "list": [1],
        "k" * 65: "long key",
        5: "int key",
    }
    out = public_detail(detail)
    assert out == {"reason": "x" * 200, "n": 3, "ok": True, "none": None}
    assert public_detail(None) == {} and public_detail("x") == {}
    assert len(public_detail({f"k{i}": i for i in range(50)})) == 20


async def test_viewer_roles_filters_paging_and_self_audit(app_client: httpx.AsyncClient) -> None:
    await login_as(app_client, Role.admin)
    fid = await create_fw(app_client)
    seed(
        app_client,
        [
            {"action": "firewall.system.status", "outcome": "success", "username": "alice",
             "detail": {"ok": 1, "nested": {"secret": "no"}}, "user_agent": "u" * 250},
            {"action": "firewall.dns.stats", "outcome": "failure", "username": "bob",
             "firewall_id": uuid.UUID(fid)},
            {"action": "rbac.denied", "outcome": "denied", "username": "bob"},
        ],
    )  # fmt: skip
    r = await app_client.get("/api/v1/audit")
    assert r.status_code == 200
    body = r.json()
    assert body["total"] >= 4 and body["page"] == 1 and body["retention_days"] == 365
    first = next(i for i in body["items"] if i["username"] == "alice")
    assert first["detail"] == {"ok": 1} and len(first["user_agent"]) == 120
    assert "secret" not in r.text

    by_user = (await app_client.get("/api/v1/audit", params={"username": "bob"})).json()
    assert by_user["total"] == 2
    by_action = (await app_client.get("/api/v1/audit", params={"action": "firewall."})).json()
    assert {i["action"] for i in by_action["items"]} >= {
        "firewall.system.status",
        "firewall.dns.stats",
    }
    assert (await app_client.get("/api/v1/audit", params={"action": "%"})).json()["total"] == 0
    by_fw = (
        await app_client.get("/api/v1/audit", params={"firewall_id": fid, "outcome": "failure"})
    ).json()
    assert [i["action"] for i in by_fw["items"]] == ["firewall.dns.stats"]
    paged = (await app_client.get("/api/v1/audit", params={"page_size": 2, "page": 2})).json()
    assert paged["page"] == 2 and len(paged["items"]) <= 2
    stamps = [i["timestamp"] for i in body["items"]]
    assert stamps == sorted(stamps, reverse=True)

    assert (await app_client.get("/api/v1/audit", params={"page_size": 201})).status_code == 422
    assert (await app_client.get("/api/v1/audit", params={"outcome": "weird"})).status_code == 422

    await switch(app_client, Role.security_admin, "sec")
    assert (await app_client.get("/api/v1/audit")).status_code == 200
    for role, name in ((Role.network_admin, "net"), (Role.read_only, "ro")):
        await switch(app_client, role, name)
        assert (await app_client.get("/api/v1/audit")).status_code == 403
    views = db_rows(app_client, select(AuditLog).where(AuditLog.action == "audit.view"))
    assert len(views) >= 3 and all(v.detail is None for v in views)


async def test_purge_is_admin_only_confirmed_and_limited_to_old_records(
    app_client: httpx.AsyncClient,
) -> None:
    await login_as(app_client, Role.admin)
    settings = override(app_client, audit_retention_days=90)
    assert settings.audit_retention_days == 90
    seed(
        app_client,
        [
            {"action": "old.one", "outcome": "success", "timestamp": old(200)},
            {"action": "old.two", "outcome": "success", "timestamp": old(91)},
            {"action": "recent.one", "outcome": "success", "timestamp": old(10)},
        ],
    )
    page = (await app_client.get("/api/v1/audit")).json()
    assert page["purgeable"] == 2

    path = "/api/v1/audit/purge"
    bad = await app_client.post(path, json={"confirm": "yes"}, headers=csrf_headers(app_client))
    assert bad.status_code == 422
    no_csrf = await app_client.post(path, json={"confirm": "PURGE"})
    assert no_csrf.status_code == 403
    assert db_rows(
        app_client, select(func.count()).select_from(AuditLog).where(AuditLog.action.like("old.%"))
    ) == [2]

    ok = await app_client.post(path, json={"confirm": "PURGE"}, headers=csrf_headers(app_client))
    assert ok.status_code == 200 and ok.json()["removed"] == 2
    remaining = {r.action for r in db_rows(app_client, select(AuditLog))}
    assert "recent.one" in remaining and "old.one" not in remaining and "old.two" not in remaining
    purge = db_rows(app_client, select(AuditLog).where(AuditLog.action == "audit.purge"))
    assert len(purge) == 1 and purge[0].detail is not None
    assert purge[0].detail["removed"] == 2 and purge[0].detail["retention_days"] == 90
    assert (await app_client.get("/api/v1/audit")).json()["purgeable"] == 0

    for role, name in (
        (Role.security_admin, "sec"),
        (Role.network_admin, "net"),
        (Role.read_only, "ro"),
    ):
        await switch(app_client, role, name)
        denied = await app_client.post(
            path, json={"confirm": "PURGE"}, headers=csrf_headers(app_client)
        )
        assert denied.status_code == 403


def test_retention_has_a_floor() -> None:
    assert get_settings().audit_retention_days >= 90
    field = Settings.model_fields["audit_retention_days"]
    assert any(getattr(m, "ge", None) == 90 for m in field.metadata)
