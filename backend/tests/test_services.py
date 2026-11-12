"""Service status list. OPNsense is mocked."""

import httpx
import respx
from sqlalchemy import select

from app.db.models import AuditLog, Role
from app.opnsense.normalise import normalise_services
from tests.test_api import create_fw, login_as
from tests.test_changes_api import switch

URL = "https://fw.example.test/api/core/service/search"

ROWS = {
    "rows": [
        {
            "id": "unbound",
            "locked": 0,
            "running": 1,
            "description": "Unbound DNS",
            "name": "unbound",
        },
        {
            "id": "openvpn/1",
            "locked": 1,
            "running": "0",
            "description": "OpenVPN",
            "name": "openvpn",
        },
        {"id": "x", "locked": 0, "running": "maybe", "name": "bad"},
        {"running": 1},
        "junk",
    ],
    "rowCount": 5,
    "total": 5,
}


def test_mapping_skips_unusable_rows() -> None:
    r = normalise_services(ROWS).services
    assert [(s.id, s.running, s.locked) for s in r] == [
        ("unbound", True, False),
        ("openvpn/1", False, True),
    ]
    assert r[0].description == "Unbound DNS"


def test_bad_shapes_and_cap() -> None:
    cases: list[object] = [None, [], {"rows": "x"}, "x"]
    for raw in cases:
        assert normalise_services(raw).services == []
    row = {"id": "a", "name": "a", "running": 1, "locked": 0}
    capped = normalise_services({"rows": [row] * 800})
    assert len(capped.services) == 500 and capped.truncated is True


async def test_services_endpoint_is_read_only_audited_for_every_role(
    app_client: httpx.AsyncClient,
) -> None:
    await login_as(app_client, Role.admin)
    fid = await create_fw(app_client)
    with respx.mock() as router:
        route = router.get(URL).respond(200, json=ROWS)
        r = await app_client.get(f"/api/v1/firewalls/{fid}/services")
        await switch(app_client, Role.read_only, "ro")
        ro = await app_client.get(f"/api/v1/firewalls/{fid}/services")
        post = await app_client.post(f"/api/v1/firewalls/{fid}/services")
    assert r.status_code == 200 and ro.status_code == 200
    assert r.json()["registry_verified"] is False and len(r.json()["services"]) == 2
    assert route.call_count == 2 and post.status_code in (404, 405)
    with app_client.app.state.sessionmaker() as db:  # type: ignore[attr-defined]
        actions = [a.action for a in db.scalars(select(AuditLog))]
    assert actions.count("firewall.services.list") == 2


async def test_services_failure_is_collapsed_for_non_admins(app_client: httpx.AsyncClient) -> None:
    await login_as(app_client, Role.admin)
    fid = await create_fw(app_client)
    await switch(app_client, Role.read_only, "ro")
    with respx.mock() as router:
        router.get(URL).respond(403, json={"status": 403})
        r = await app_client.get(f"/api/v1/firewalls/{fid}/services")
    assert r.status_code == 502 and r.json()["detail"]["message"] == "Firewall is unreachable"
