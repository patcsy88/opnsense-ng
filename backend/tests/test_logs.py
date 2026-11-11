"""Firewall log viewing. OPNsense is mocked."""

import httpx
import respx
from sqlalchemy import select

from app.db.models import AuditLog, Role
from app.opnsense.normalise import normalise_log
from tests.test_api import create_fw, login_as
from tests.test_changes_api import switch

URL = "https://fw.example.test/api/diagnostics/firewall/log"


def record(**kw: object) -> dict[str, object]:
    base: dict[str, object] = {
        "__timestamp__": "2026-11-12T10:00:00",
        "__digest__": "secretdigest",
        "action": "block",
        "interface": "igb0",
        "dir": "in",
        "ipversion": "4",
        "protoname": "tcp",
        "src": "203.0.113.9",
        "srcport": "51515",
        "dst": "10.0.0.5",
        "dstport": "23",
        "label": "Default deny",
        "reason": "match",
        "tcpopts": "hidden",
    }
    base.update(kw)
    return base


def test_normalise_log_keeps_only_display_fields_and_caps() -> None:
    result = normalise_log([record()] * 250 + ["junk"])
    assert len(result.entries) == 200 and result.truncated is True
    entry = result.entries[0]
    assert entry.destination_port == 23 and entry.source == "203.0.113.9"
    assert "digest" not in entry.model_dump_json() and "hidden" not in entry.model_dump_json()
    assert normalise_log({"unexpected": 1}).entries == []
    assert normalise_log(None).entries == []


async def test_log_is_read_only_audited_and_hides_internals(app_client: httpx.AsyncClient) -> None:
    await login_as(app_client, Role.admin)
    fid = await create_fw(app_client)
    await switch(app_client, Role.security_admin, "sec")
    with respx.mock() as router:
        route = router.get(URL).respond(200, json=[record(), record(action="pass")])
        r = await app_client.get(f"/api/v1/firewalls/{fid}/firewall/logs")
    assert r.status_code == 200 and route.calls.last.request.method == "GET"
    body = r.json()
    assert [e["action"] for e in body["entries"]] == ["block", "pass"]
    assert body["registry_verified"] is False
    assert "secretdigest" not in r.text and "hidden" not in r.text
    with app_client.app.state.sessionmaker() as db:  # type: ignore[attr-defined]
        actions = {a.action for a in db.scalars(select(AuditLog))}
    assert "firewall.firewall.log" in actions


async def test_read_only_and_anonymous_cannot_read_logs(app_client: httpx.AsyncClient) -> None:
    import uuid

    assert (
        await app_client.get(f"/api/v1/firewalls/{uuid.uuid4()}/firewall/logs")
    ).status_code == 401
    await login_as(app_client, Role.admin)
    fid = await create_fw(app_client)
    await switch(app_client, Role.read_only, "ro")
    with respx.mock(assert_all_called=False) as router:
        route = router.get(URL)
        r = await app_client.get(f"/api/v1/firewalls/{fid}/firewall/logs")
    assert r.status_code == 403 and route.call_count == 0
    for role in (Role.admin, Role.network_admin, Role.security_admin):
        await switch(app_client, role, f"u_{role.value}")
        with respx.mock() as router:
            router.get(URL).respond(200, json=[])
            assert (
                await app_client.get(f"/api/v1/firewalls/{fid}/firewall/logs")
            ).status_code == 200


async def test_log_errors_are_collapsed_for_non_admins(app_client: httpx.AsyncClient) -> None:
    await login_as(app_client, Role.admin)
    fid = await create_fw(app_client)
    with respx.mock() as router:
        router.get(URL).respond(403)
        admin = await app_client.get(f"/api/v1/firewalls/{fid}/firewall/logs")
        await switch(app_client, Role.security_admin, "sec")
        other = await app_client.get(f"/api/v1/firewalls/{fid}/firewall/logs")
    assert admin.status_code == 502 and admin.json()["detail"]["status"] == "forbidden"
    assert other.status_code == 502 and other.json()["detail"]["status"] != "forbidden"
