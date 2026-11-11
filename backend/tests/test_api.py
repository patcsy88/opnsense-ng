import io
import json
import uuid

import httpx
import pytest
import respx
from sqlalchemy import select

from app.core.logging import configure_logging
from app.db.models import AuditLog, Firewall, Role
from tests.conftest import PASSWORD, csrf_headers, login, make_user

pytestmark = pytest.mark.usefixtures("db")

API_KEY = "AKEY-1234567890-unique"
API_SECRET = "ASECRET-0987654321-unique"
FW_BODY = {
    "name": "lab-fw",
    "base_url": "https://fw.example.test",
    "api_key": API_KEY,
    "api_secret": API_SECRET,
}


async def audit_rows(client: httpx.AsyncClient) -> list[AuditLog]:
    with client.app.state.sessionmaker() as s:  # type: ignore[attr-defined]
        return list(s.execute(select(AuditLog).order_by(AuditLog.timestamp)).scalars())


async def login_as(client: httpx.AsyncClient, role: Role, name: str | None = None) -> None:
    name = name or role.value
    await make_user(client, name, role)
    assert (await login(client, name)).status_code == 200


async def create_fw(client: httpx.AsyncClient) -> str:
    r = await client.post("/api/v1/firewalls", json=FW_BODY, headers=csrf_headers(client))
    assert r.status_code == 201, r.text
    return str(r.json()["id"])


async def test_health_open(app_client: httpx.AsyncClient) -> None:
    assert (await app_client.get("/health")).json() == {"status": "ok"}


async def test_login_me_logout_and_audit(app_client: httpx.AsyncClient) -> None:
    await make_user(app_client, "alice", Role.admin)
    r = await login(app_client, "alice")
    assert r.status_code == 200 and r.json()["user"]["role"] == "admin"
    cookie = r.headers.get_list("set-cookie")
    session_cookie = next(c for c in cookie if c.startswith("__Host-session="))
    assert all(f in session_cookie for f in ("HttpOnly", "Secure", "SameSite=strict"))
    csrf_cookie = next(c for c in cookie if c.startswith("__Host-csrf_token="))
    assert "Secure" in csrf_cookie and "SameSite=strict" in csrf_cookie
    assert (await app_client.get("/api/v1/auth/me")).json()["username"] == "alice"

    out = await app_client.post("/api/v1/auth/logout", headers=csrf_headers(app_client))
    assert out.status_code == 204
    assert (await app_client.get("/api/v1/auth/me")).status_code == 401
    audited = [(a.action, a.outcome) for a in await audit_rows(app_client)]
    assert audited[:2] == [("auth.login", "success"), ("auth.logout", "success")]


async def test_session_token_stored_hashed(app_client: httpx.AsyncClient) -> None:
    await make_user(app_client, "alice", Role.admin)
    await login(app_client, "alice")
    raw = app_client.cookies.get("__Host-session")
    with app_client.app.state.sessionmaker() as s:  # type: ignore[attr-defined]
        from app.db.models import Session

        rows = list(s.execute(select(Session)).scalars())
    assert len(rows) == 1 and rows[0].token_hash != raw and len(rows[0].token_hash) == 64


async def test_wrong_password_and_unknown_user_are_generic(app_client: httpx.AsyncClient) -> None:
    await make_user(app_client, "alice", Role.admin)
    bad_pw = await login(app_client, "alice", "wrong-password")
    bad_user = await login(app_client, "nobody", "wrong-password")
    assert bad_pw.status_code == bad_user.status_code == 401
    assert bad_pw.json() == bad_user.json() == {"detail": "Invalid username or password"}
    assert "__Host-session" not in bad_pw.cookies
    rows = await audit_rows(app_client)
    assert [a.outcome for a in rows] == ["failure", "failure"]


async def test_login_rate_limit(app_client: httpx.AsyncClient) -> None:
    codes = [(await login(app_client, "nobody", "x")).status_code for _ in range(7)]
    assert codes[:5] == [401] * 5 and codes[5:] == [429, 429]


async def test_expired_session_rejected(app_client: httpx.AsyncClient) -> None:
    from datetime import UTC, datetime, timedelta

    from app.db.models import Session

    await login_as(app_client, Role.admin)
    with app_client.app.state.sessionmaker() as s:  # type: ignore[attr-defined]
        for row in s.execute(select(Session)).scalars():
            row.expires_at = datetime.now(UTC) - timedelta(seconds=1)
        s.commit()
    assert (await app_client.get("/api/v1/auth/me")).status_code == 401


async def test_unauthenticated_denied(app_client: httpx.AsyncClient) -> None:
    assert (await app_client.get("/api/v1/firewalls")).status_code == 401
    fid = uuid.uuid4()
    assert (await app_client.get(f"/api/v1/firewalls/{fid}/system/status")).status_code == 401


async def test_rbac_denies_non_admin_firewall_management(app_client: httpx.AsyncClient) -> None:
    for role in (Role.network_admin, Role.security_admin, Role.read_only):
        await login_as(app_client, role)
        r = await app_client.post(
            "/api/v1/firewalls", json=FW_BODY, headers=csrf_headers(app_client)
        )
        assert r.status_code == 403
        assert (await app_client.get("/api/v1/firewalls")).status_code == 403
    denied = [a for a in await audit_rows(app_client) if a.action == "rbac.denied"]
    assert len(denied) == 6


async def test_csrf_rejected(app_client: httpx.AsyncClient) -> None:
    await login_as(app_client, Role.admin)
    no_header = await app_client.post("/api/v1/firewalls", json=FW_BODY)
    wrong = await app_client.post(
        "/api/v1/firewalls", json=FW_BODY, headers={"X-CSRF-Token": "forged"}
    )
    logout_no = await app_client.post("/api/v1/auth/logout")
    assert no_header.status_code == wrong.status_code == logout_no.status_code == 403
    # a header matching a forged cookie still fails: it must match the server-side session
    app_client.cookies.set("__Host-csrf_token", "forged", domain="test")
    forged = await app_client.post(
        "/api/v1/firewalls", json=FW_BODY, headers={"X-CSRF-Token": "forged"}
    )
    assert forged.status_code == 403
    assert (await app_client.get("/api/v1/auth/me")).status_code == 200  # still logged in


async def test_firewall_create_list_never_returns_or_stores_plain_credentials(
    app_client: httpx.AsyncClient,
) -> None:
    await login_as(app_client, Role.admin)
    fid = await create_fw(app_client)
    listing = await app_client.get("/api/v1/firewalls")
    body = listing.text
    assert fid in body and API_KEY not in body and API_SECRET not in body
    assert "api_key" not in body and "secret" not in body
    with app_client.app.state.sessionmaker() as s:  # type: ignore[attr-defined]
        fw = s.execute(select(Firewall)).scalar_one()
    assert API_KEY not in fw.api_key_encrypted and API_SECRET not in fw.api_secret_encrypted
    assert fw.verify_tls is True
    rows = await audit_rows(app_client)
    assert API_KEY not in json.dumps([r.detail for r in rows])


async def test_firewall_validation(app_client: httpx.AsyncClient) -> None:
    await login_as(app_client, Role.admin)
    for bad in (
        {**FW_BODY, "base_url": "http://plain.test"},
        {**FW_BODY, "extra": 1},
        {**FW_BODY, "name": ""},
    ):
        r = await app_client.post("/api/v1/firewalls", json=bad, headers=csrf_headers(app_client))
        assert r.status_code == 422
    await create_fw(app_client)
    dup = await app_client.post("/api/v1/firewalls", json=FW_BODY, headers=csrf_headers(app_client))
    assert dup.status_code == 409


async def test_system_status_and_connectivity_any_role(app_client: httpx.AsyncClient) -> None:
    await login_as(app_client, Role.admin)
    fid = await create_fw(app_client)
    await app_client.post("/api/v1/auth/logout", headers=csrf_headers(app_client))
    await login_as(app_client, Role.read_only)
    with respx.mock() as router:
        router.get("https://fw.example.test/api/diagnostics/system/system_information").respond(
            200, json={"name": "fw1", "versions": ["OPNsense 26.1"], "secret_extra": "raw"}
        )
        router.get("https://fw.example.test/api/diagnostics/system/system_time").respond(
            200, json={"datetime": "now"}
        )
        router.get("https://fw.example.test/api/diagnostics/system/system_resources").respond(
            200, json={"memory": {"total": "1000", "used": 250}}
        )
        router.get("https://fw.example.test/api/diagnostics/system/system_disk").respond(
            200,
            json={
                "devices": [
                    {"mountpoint": "/boot", "total_bytes": 100, "used_bytes": 50},
                    {"mountpoint": "/", "total_bytes": 2000, "used_bytes": 500, "used_pct": 25},
                ]
            },
        )
        router.get("https://fw.example.test/api/diagnostics/cpu_usage/stream").respond(
            200,
            headers={"content-type": "text/event-stream"},
            content=b'data: {"total": 12, "user": 8}\n\ndata: {"total": 40}\n\n',
        )
        s = await app_client.get(f"/api/v1/firewalls/{fid}/system/status")
        c = await app_client.get(f"/api/v1/firewalls/{fid}/connectivity")
    assert s.status_code == 200 and s.json()["status"]["hostname"] == "fw1"
    assert s.json()["status"]["memory_used_percent"] == 25.0
    assert s.json()["status"]["cpu_used_percent"] == 40.0
    assert s.json()["status"]["disk_used_percent"] == 25.0
    assert "secret_extra" not in s.text  # normalised, raw JSON not passed through
    assert c.json()["ok"] is True
    actions = [(a.action, a.outcome, a.firewall_id) for a in await audit_rows(app_client)]
    uid = uuid.UUID(fid)
    assert ("firewall.system.status", "success", uid) in actions
    assert ("firewall.system.connectivity", "success", uid) in actions


async def test_unknown_firewall_404(app_client: httpx.AsyncClient) -> None:
    await login_as(app_client, Role.read_only)
    r = await app_client.get(f"/api/v1/firewalls/{uuid.uuid4()}/system/status")
    assert r.status_code == 404


async def test_firewall_outage_reported_and_audited(app_client: httpx.AsyncClient) -> None:
    await login_as(app_client, Role.admin)
    fid = await create_fw(app_client)
    with respx.mock() as router:
        router.get("https://fw.example.test/api/diagnostics/system/system_time").mock(
            side_effect=httpx.ConnectError("down")
        )
        router.get("https://fw.example.test/api/diagnostics/system/system_information").mock(
            side_effect=httpx.ReadTimeout("slow")
        )
        c = await app_client.get(f"/api/v1/firewalls/{fid}/connectivity")
        s = await app_client.get(f"/api/v1/firewalls/{fid}/system/status")
    assert c.status_code == 200 and c.json()["ok"] is False
    assert c.json()["status"] == "unreachable"
    assert s.status_code == 504 and s.json()["detail"]["status"] == "timeout"
    failures = [a for a in await audit_rows(app_client) if a.outcome == "failure"]
    assert {a.detail["status"] for a in failures if a.detail} == {"unreachable", "timeout"}


async def test_credentials_never_in_logs_or_errors(app_client: httpx.AsyncClient) -> None:
    stream = io.StringIO()
    configure_logging(stream)
    await login_as(app_client, Role.admin)
    fid = await create_fw(app_client)
    with respx.mock() as router:
        router.get("https://fw.example.test/api/diagnostics/system/system_information").mock(
            side_effect=httpx.ConnectError(f"boom {API_KEY} {API_SECRET}")
        )
        s = await app_client.get(f"/api/v1/firewalls/{fid}/system/status")
    session_cookie = app_client.cookies.get("__Host-session") or ""
    everything = stream.getvalue() + s.text + PASSWORD
    assert API_KEY not in stream.getvalue() and API_SECRET not in stream.getvalue()
    assert API_KEY not in s.text and API_SECRET not in s.text
    assert session_cookie not in stream.getvalue()
    assert everything


async def test_delete_firewall_removes_it_and_keeps_audit(app_client: httpx.AsyncClient) -> None:
    await login_as(app_client, Role.admin)
    fid = await create_fw(app_client)
    r = await app_client.delete(f"/api/v1/firewalls/{fid}", headers=csrf_headers(app_client))
    assert r.status_code == 204
    assert (await app_client.get("/api/v1/firewalls")).json() == []
    again = await app_client.delete(f"/api/v1/firewalls/{fid}", headers=csrf_headers(app_client))
    assert again.status_code == 404
    rows = [(a.action, a.outcome, a.detail) for a in await audit_rows(app_client)]
    assert (
        "firewall.delete",
        "success",
        {"name": FW_BODY["name"], "base_url": FW_BODY["base_url"]},
    ) in rows
    assert ("firewall.delete", "failure", {"reason": "firewall_not_found"}) in rows
    assert API_KEY not in json.dumps([r[2] for r in rows])


async def test_delete_firewall_requires_admin_and_csrf(app_client: httpx.AsyncClient) -> None:
    await login_as(app_client, Role.admin)
    fid = await create_fw(app_client)
    no_csrf = await app_client.delete(f"/api/v1/firewalls/{fid}")
    assert no_csrf.status_code == 403
    await app_client.post("/api/v1/auth/logout", headers=csrf_headers(app_client))
    for role in (Role.read_only, Role.network_admin, Role.security_admin):
        await login_as(app_client, role)
        denied = await app_client.delete(
            f"/api/v1/firewalls/{fid}", headers=csrf_headers(app_client)
        )
        assert denied.status_code == 403
        await app_client.post("/api/v1/auth/logout", headers=csrf_headers(app_client))
    assert (await login(app_client, Role.admin.value)).status_code == 200
    assert len((await app_client.get("/api/v1/firewalls")).json()) == 1


async def test_firewall_options_for_every_role_expose_only_id_and_name(
    app_client: httpx.AsyncClient,
) -> None:
    await login_as(app_client, Role.admin)
    fid = await create_fw(app_client)
    await app_client.post("/api/v1/auth/logout", headers=csrf_headers(app_client))
    for role in (Role.read_only, Role.network_admin, Role.security_admin, Role.admin):
        if role is Role.admin:
            assert (await login(app_client, role.value)).status_code == 200
        else:
            await login_as(app_client, role)
        r = await app_client.get("/api/v1/firewalls/options")
        assert r.status_code == 200
        assert r.json() == [{"id": fid, "name": FW_BODY["name"]}]
        for leaked in (FW_BODY["base_url"], "verify_tls", "ca_bundle", "api_key", API_KEY):
            assert str(leaked) not in r.text
        await app_client.post("/api/v1/auth/logout", headers=csrf_headers(app_client))


async def test_firewall_options_requires_login_and_detailed_list_stays_admin_only(
    app_client: httpx.AsyncClient,
) -> None:
    assert (await app_client.get("/api/v1/firewalls/options")).status_code == 401
    await login_as(app_client, Role.read_only)
    assert (await app_client.get("/api/v1/firewalls/options")).status_code == 200
    assert (await app_client.get("/api/v1/firewalls")).status_code == 403


async def test_interfaces_any_role_normalised_and_audited(app_client: httpx.AsyncClient) -> None:
    await login_as(app_client, Role.admin)
    fid = await create_fw(app_client)
    await app_client.post("/api/v1/auth/logout", headers=csrf_headers(app_client))
    await login_as(app_client, Role.read_only)
    url = "https://fw.example.test/api/interfaces/overview/interfacesInfo"
    with respx.mock() as router:
        router.get(url).respond(
            200,
            json={
                "rows": [
                    {
                        "identifier": "wan",
                        "description": "WAN",
                        "device": "vtnet0",
                        "status": "up",
                        "ipv4": [{"ipaddr": "10.0.0.2/24"}],
                        "macaddr": "aa:bb:cc:dd:ee:ff",
                        "secret_extra": "raw",
                    }
                ]
            },
        )
        r = await app_client.get(f"/api/v1/firewalls/{fid}/interfaces")
    assert r.status_code == 200
    body = r.json()
    assert body["interfaces"][0]["ipv4"] == ["10.0.0.2/24"]
    assert "aa:bb" not in r.text and "secret_extra" not in r.text
    actions = [(a.action, a.outcome) for a in await audit_rows(app_client)]
    assert ("firewall.interfaces.overview", "success") in actions


async def test_interfaces_errors_are_collapsed_for_non_admins(
    app_client: httpx.AsyncClient,
) -> None:
    await login_as(app_client, Role.admin)
    fid = await create_fw(app_client)
    url = "https://fw.example.test/api/interfaces/overview/interfacesInfo"
    with respx.mock() as router:
        router.get(url).respond(403)
        admin = await app_client.get(f"/api/v1/firewalls/{fid}/interfaces")
        await app_client.post("/api/v1/auth/logout", headers=csrf_headers(app_client))
        await login_as(app_client, Role.read_only)
        other = await app_client.get(f"/api/v1/firewalls/{fid}/interfaces")
    assert admin.status_code == 502 and admin.json()["detail"]["status"] == "forbidden"
    assert other.status_code == 502 and other.json()["detail"]["status"] != "forbidden"
    assert (await app_client.get(f"/api/v1/firewalls/{uuid.uuid4()}/interfaces")).status_code == 404


async def test_firewall_rules_any_role_normalised_and_audited(
    app_client: httpx.AsyncClient,
) -> None:
    await login_as(app_client, Role.admin)
    fid = await create_fw(app_client)
    await app_client.post("/api/v1/auth/logout", headers=csrf_headers(app_client))
    await login_as(app_client, Role.read_only)
    url = "https://fw.example.test/api/firewall/filter/searchRule"
    with respx.mock() as router:
        route = router.get(url).respond(
            200,
            json={
                "rows": [
                    {
                        "uuid": "u1",
                        "enabled": "1",
                        "action": "block",
                        "interface": "wan",
                        "source_net": "any",
                        "destination_net": "any",
                        "description": "Block all",
                        "categories": "hidden",
                    }
                ]
            },
        )
        r = await app_client.get(f"/api/v1/firewalls/{fid}/firewall/rules")
    assert r.status_code == 200 and route.calls.last.request.method == "GET"
    rule = r.json()["rules"][0]
    assert rule["action"] == "block" and rule["enabled"] is True
    assert "hidden" not in r.text
    actions = [(a.action, a.outcome) for a in await audit_rows(app_client)]
    assert ("firewall.firewall.rules.list", "success") in actions


async def test_firewall_rules_errors_collapsed_and_unauthenticated_blocked(
    app_client: httpx.AsyncClient,
) -> None:
    assert (
        await app_client.get(f"/api/v1/firewalls/{uuid.uuid4()}/firewall/rules")
    ).status_code == 401
    await login_as(app_client, Role.admin)
    fid = await create_fw(app_client)
    with respx.mock() as router:
        router.get("https://fw.example.test/api/firewall/filter/searchRule").respond(403)
        admin = await app_client.get(f"/api/v1/firewalls/{fid}/firewall/rules")
        await app_client.post("/api/v1/auth/logout", headers=csrf_headers(app_client))
        await login_as(app_client, Role.read_only)
        other = await app_client.get(f"/api/v1/firewalls/{fid}/firewall/rules")
    assert admin.status_code == 502 and admin.json()["detail"]["status"] == "forbidden"
    assert other.status_code == 502 and other.json()["detail"]["status"] != "forbidden"


async def test_firewall_aliases_any_role_normalised_and_audited(
    app_client: httpx.AsyncClient,
) -> None:
    await login_as(app_client, Role.admin)
    fid = await create_fw(app_client)
    await app_client.post("/api/v1/auth/logout", headers=csrf_headers(app_client))
    await login_as(app_client, Role.read_only)
    url = "https://fw.example.test/api/firewall/alias/searchItem"
    with respx.mock() as router:
        route = router.get(url).respond(
            200,
            json={
                "rows": [
                    {
                        "uuid": "a1",
                        "name": "lan_hosts",
                        "type": "host",
                        "enabled": "1",
                        "content": "10.0.0.1,10.0.0.2",
                        "categories": "hidden",
                    }
                ]
            },
        )
        r = await app_client.get(f"/api/v1/firewalls/{fid}/firewall/aliases")
    assert r.status_code == 200 and route.calls.last.request.method == "GET"
    alias = r.json()["aliases"][0]
    assert alias["name"] == "lan_hosts" and alias["content"] == ["10.0.0.1", "10.0.0.2"]
    assert "hidden" not in r.text
    actions = [(a.action, a.outcome) for a in await audit_rows(app_client)]
    assert ("firewall.firewall.aliases.list", "success") in actions


async def test_firewall_aliases_errors_collapsed_and_unauthenticated_blocked(
    app_client: httpx.AsyncClient,
) -> None:
    assert (
        await app_client.get(f"/api/v1/firewalls/{uuid.uuid4()}/firewall/aliases")
    ).status_code == 401
    await login_as(app_client, Role.admin)
    fid = await create_fw(app_client)
    with respx.mock() as router:
        router.get("https://fw.example.test/api/firewall/alias/searchItem").respond(403)
        admin = await app_client.get(f"/api/v1/firewalls/{fid}/firewall/aliases")
        await app_client.post("/api/v1/auth/logout", headers=csrf_headers(app_client))
        await login_as(app_client, Role.read_only)
        other = await app_client.get(f"/api/v1/firewalls/{fid}/firewall/aliases")
    assert admin.status_code == 502 and admin.json()["detail"]["status"] == "forbidden"
    assert other.status_code == 502 and other.json()["detail"]["status"] != "forbidden"
