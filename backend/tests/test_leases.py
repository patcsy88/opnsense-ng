"""DHCP lease listing (ADR-0008). OPNsense is mocked."""

import httpx
import respx
from sqlalchemy import select

from app.db.models import AuditLog, Role
from app.opnsense.normalise import normalise_leases
from tests.test_api import create_fw, login_as
from tests.test_changes_api import switch

URL = "https://fw.example.test/api/dnsmasq/leases/search"

ROWS = {
    "rows": [
        {
            "address": "192.168.1.50",
            "hostname": "laptop",
            "hwaddr": "aa:bb:cc:dd:ee:ff",
            "mac_info": "Apple, Inc.",
            "client_id": "01:aa:bb:cc:dd:ee:ff",
            "iaid": "",
            "expire": 1762950000,
            "if_descr": "LAN",
            "if_name": "lan",
            "lease_type": "dynamic",
        },
        {
            "address": "fd00::5",
            "hostname": "*",
            "hwaddr": "11:22:33:44:55:66",
            "iaid": "1234",
            "expire": 0,
            "if_name": "lan",
            "lease_type": "static",
        },
        {"address": "not-an-ip", "hostname": "bad"},
        {"hostname": "noaddr"},
        "junk",
    ]
}


def test_mapping_drops_macs_and_identifiers() -> None:
    result = normalise_leases(ROWS)
    a, b = result.leases
    assert (a.address, a.ip_version, a.hostname, a.interface) == (
        "192.168.1.50",
        4,
        "laptop",
        "LAN",
    )
    assert a.vendor == "Apple, Inc." and a.lease_type == "dynamic"
    assert a.expires is not None and a.expires.startswith("2025-")
    assert (b.ip_version, b.hostname, b.interface, b.expires) == (6, None, "lan", None)
    dumped = result.model_dump_json()
    for secret in ("aa:bb:cc", "11:22:33", "client_id", "iaid", "1234"):
        assert secret not in dumped


def test_bad_shapes_and_cap() -> None:
    cases: list[object] = [None, [], {"rows": "x"}, "x"]
    for raw in cases:
        assert normalise_leases(raw).leases == []
    capped = normalise_leases({"rows": [{"address": "10.0.0.1"}] * 1500})
    assert len(capped.leases) == 1000 and capped.truncated is True


async def test_leases_endpoint_roles_audit_and_no_macs(app_client: httpx.AsyncClient) -> None:
    await login_as(app_client, Role.admin)
    fid = await create_fw(app_client)
    with respx.mock() as router:
        router.get(URL).respond(200, json=ROWS)
        r = await app_client.get(f"/api/v1/firewalls/{fid}/dhcp/leases")
        for role, name in ((Role.network_admin, "net"), (Role.security_admin, "sec")):
            await switch(app_client, role, name)
            assert (await app_client.get(f"/api/v1/firewalls/{fid}/dhcp/leases")).status_code == 200
        await switch(app_client, Role.read_only, "ro")
        denied = await app_client.get(f"/api/v1/firewalls/{fid}/dhcp/leases")
    assert r.status_code == 200 and len(r.json()["leases"]) == 2
    assert "aa:bb:cc" not in r.text and r.json()["registry_verified"] is False
    assert denied.status_code == 403
    with app_client.app.state.sessionmaker() as db:  # type: ignore[attr-defined]
        actions = [a.action for a in db.scalars(select(AuditLog))]
    assert actions.count("firewall.dhcp.leases") == 3


async def test_leases_failure_is_collapsed_for_non_admins(app_client: httpx.AsyncClient) -> None:
    await login_as(app_client, Role.admin)
    fid = await create_fw(app_client)
    await switch(app_client, Role.network_admin, "net")
    with respx.mock() as router:
        router.get(URL).respond(403, json={"status": 403})
        r = await app_client.get(f"/api/v1/firewalls/{fid}/dhcp/leases")
    assert r.status_code == 502 and r.json()["detail"]["message"] == "Firewall is unreachable"
