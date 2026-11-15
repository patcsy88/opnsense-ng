"""Kea DHCPv4 read-only views (ADR-0020). OPNsense is mocked."""

import httpx
import respx
from sqlalchemy import select

from app.db.models import AuditLog, Role
from app.opnsense.normalise import (
    normalise_kea_leases,
    normalise_kea_reservations,
    normalise_kea_subnets,
)
from tests.test_api import create_fw, login_as
from tests.test_changes_api import switch

BASE = "https://fw.example.test/api/kea"
LEASES = {
    "rows": [
        {
            "address": "192.168.1.50",
            "hostname": "laptop",
            "hwaddr": "aa:bb:cc:dd:ee:ff",
            "client_id": "01:aa:bb",
            "if_name": "lan",
            "state": 0,
            "expire": 1762950000,
        },
        {"address": "fd00::5"},
        {"address": "bad"},
        "junk",
    ]
}
RESERVATIONS = {
    "rows": [
        {
            "uuid": "u1",
            "subnet": "uuid-s1",
            "%subnet": "192.168.1.0/24",
            "ip_address": "192.168.1.10",
            "hw_address": "aa:bb:cc:dd:ee:01",
            "hostname": "printer",
        },
        {"uuid": "u2", "ip_address": "nope"},
        {"ip_address": "192.168.1.11"},
    ]
}
SUBNETS = {
    "rows": [
        {"uuid": "s1", "subnet": "192.168.1.0/24", "pools": "192.168.1.100-192.168.1.200"},
        {"uuid": "s2", "subnet": "10.0.0.0/24", "pools": None},
        {"subnet": "10.1.0.0/24"},
    ]
}


def test_lease_mapping_is_ipv4_only_and_drops_macs() -> None:
    result = normalise_kea_leases(LEASES)
    assert [lease.address for lease in result.leases] == ["192.168.1.50"]
    assert result.leases[0].state == "active"
    dumped = result.model_dump_json()
    for secret in ("aa:bb:cc", "client_id", "01:aa:bb"):
        assert secret not in dumped


def test_reservation_and_subnet_mapping_skip_bad_rows() -> None:
    res = normalise_kea_reservations(RESERVATIONS).reservations
    assert (
        [r.uuid for r in res] == ["u1"]
        and res[0].subnet == "192.168.1.0/24"
        and res[0].hw_address == "aa:bb:cc:dd:ee:01"
    )
    subnets = normalise_kea_subnets(SUBNETS).subnets
    assert [s.uuid for s in subnets] == ["s1", "s2"]
    assert subnets[0].pools == ["192.168.1.100-192.168.1.200"] and subnets[1].pools == []


def test_bad_shapes_and_cap() -> None:
    cases: list[object] = [None, [], {"rows": "x"}, "x"]
    for raw in cases:
        assert normalise_kea_leases(raw).leases == []
        assert normalise_kea_reservations(raw).reservations == []
        assert normalise_kea_subnets(raw).subnets == []
    capped = normalise_kea_leases({"rows": [{"address": "10.0.0.1"}] * 1500})
    assert len(capped.leases) == 1000 and capped.truncated is True


async def test_endpoints_roles_audit_and_unverified(app_client: httpx.AsyncClient) -> None:
    await login_as(app_client, Role.admin)
    fid = await create_fw(app_client)
    root = f"/api/v1/firewalls/{fid}/kea"
    with respx.mock() as router:
        router.get(f"{BASE}/leases4/search").respond(200, json=LEASES)
        router.get(f"{BASE}/dhcpv4/searchReservation").respond(200, json=RESERVATIONS)
        router.get(f"{BASE}/dhcpv4/searchSubnet").respond(200, json=SUBNETS)
        leases = await app_client.get(f"{root}/leases")
        reservations = await app_client.get(f"{root}/reservations")
        subnets = await app_client.get(f"{root}/subnets")
        await switch(app_client, Role.security_admin, "sec")
        sec_leases = await app_client.get(f"{root}/leases")
        sec_reservations = await app_client.get(f"{root}/reservations")
        await switch(app_client, Role.read_only, "ro")
        ro_leases = await app_client.get(f"{root}/leases")
    assert leases.status_code == 200 and leases.json()["registry_verified"] is True
    assert reservations.json()["registry_verified"] is True
    assert "aa:bb:cc" not in leases.text and len(leases.json()["leases"]) == 1
    assert len(reservations.json()["reservations"]) == 1
    assert len(subnets.json()["subnets"]) == 2
    assert sec_leases.status_code == 200
    assert sec_reservations.status_code == 403 and ro_leases.status_code == 403
    with app_client.app.state.sessionmaker() as db:  # type: ignore[attr-defined]
        actions = [a.action for a in db.scalars(select(AuditLog))]
    assert actions.count("firewall.kea.reservations4.list") == 1
    assert actions.count("firewall.kea.leases4.list") == 2


async def test_failure_is_collapsed_for_non_admins(app_client: httpx.AsyncClient) -> None:
    await login_as(app_client, Role.admin)
    fid = await create_fw(app_client)
    await switch(app_client, Role.network_admin, "net")
    with respx.mock() as router:
        router.get(f"{BASE}/leases4/search").respond(403, json={"status": 403})
        r = await app_client.get(f"/api/v1/firewalls/{fid}/kea/leases")
    assert r.status_code == 502 and r.json()["detail"]["message"] == "Firewall is unreachable"
