"""Interface traffic counters (ADR-0007). OPNsense is mocked."""

import httpx
import respx
from sqlalchemy import select

from app.db.models import AuditLog, Role
from app.opnsense.normalise import normalise_traffic
from tests.test_api import create_fw, login_as
from tests.test_changes_api import switch

URL = "https://fw.example.test/api/diagnostics/traffic/interface"

RAW = {
    "time": 1762950000.5,
    "interfaces": {
        "wan": {
            "bytes received": "1000",
            "bytes transmitted": 2000,
            "packets received": "10",
            "packets transmitted": "20",
            "name": "WAN",
            "input errors": "0",
            "mac": "aa:bb:cc:dd:ee:ff",
        },
        "lan": {"bytes received": "5", "bytes transmitted": "6", "packets received": "1"},
    },
}


def test_mapping_keeps_only_complete_interfaces_and_drops_extras() -> None:
    r = normalise_traffic(RAW)
    assert r.time == 1762950000.5
    assert [i.interface for i in r.interfaces] == ["wan"]
    wan = r.interfaces[0]
    assert (wan.in_bytes, wan.out_bytes, wan.in_packets, wan.out_packets) == (1000, 2000, 10, 20)
    assert wan.name == "WAN" and "aa:bb" not in wan.model_dump_json()


def test_bad_shapes_give_empty_results() -> None:
    cases: list[object] = [None, [], {"interfaces": []}, {"interfaces": {"a": "x"}}, "x"]
    for raw in cases:
        assert normalise_traffic(raw).interfaces == []
    bad = {"interfaces": {"a": {k: -1 for k in ("bytes received",)}}}
    assert normalise_traffic(bad).interfaces == []
    negative = {
        "interfaces": {
            "a": {
                "bytes received": -1,
                "bytes transmitted": 1,
                "packets received": 1,
                "packets transmitted": 1,
            }
        }
    }
    assert normalise_traffic(negative).interfaces == []


def test_interface_count_is_capped() -> None:
    row = {
        k: 1
        for k in ("bytes received", "bytes transmitted", "packets received", "packets transmitted")
    }
    raw = {"interfaces": {f"i{n}": row for n in range(200)}}
    assert len(normalise_traffic(raw).interfaces) == 64


async def test_traffic_endpoint_roles_audit_and_cache(app_client: httpx.AsyncClient) -> None:
    await login_as(app_client, Role.admin)
    fid = await create_fw(app_client)
    with respx.mock() as router:
        route = router.get(URL).respond(200, json=RAW)
        first = await app_client.get(f"/api/v1/firewalls/{fid}/traffic")
        second = await app_client.get(f"/api/v1/firewalls/{fid}/traffic")
    assert first.status_code == 200 and second.status_code == 200
    body = first.json()
    assert body["registry_verified"] is False and body["time"] == 1762950000.5
    assert body["interfaces"][0]["in_bytes"] == 1000
    assert route.call_count == 1  # the second answer came from the cache
    with app_client.app.state.sessionmaker() as db:  # type: ignore[attr-defined]
        actions = [a.action for a in db.scalars(select(AuditLog))]
    assert actions.count("firewall.traffic.interfaces") == 1

    for role, name in ((Role.network_admin, "net"), (Role.security_admin, "sec")):
        await switch(app_client, role, name)
        assert (await app_client.get(f"/api/v1/firewalls/{fid}/traffic")).status_code == 200
    await switch(app_client, Role.read_only, "ro")
    denied = await app_client.get(f"/api/v1/firewalls/{fid}/traffic")
    assert denied.status_code == 403


async def test_traffic_failure_is_collapsed_for_non_admins(app_client: httpx.AsyncClient) -> None:
    await login_as(app_client, Role.admin)
    fid = await create_fw(app_client)
    await switch(app_client, Role.network_admin, "net")
    with respx.mock() as router:
        router.get(URL).respond(403, json={"status": 403})
        r = await app_client.get(f"/api/v1/firewalls/{fid}/traffic")
    assert r.status_code == 502
    assert r.json()["detail"]["message"] == "Firewall is unreachable"
