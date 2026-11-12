"""NAT listing (port forwards and outbound). OPNsense is mocked."""

import httpx
import respx
from sqlalchemy import select

from app.db.models import AuditLog, Role
from app.opnsense.normalise import normalise_nat
from tests.test_api import create_fw, login_as
from tests.test_changes_api import switch

BASE = "https://fw.example.test/api/firewall"
DNAT = f"{BASE}/d_nat/searchRule"
SNAT = f"{BASE}/source_nat/searchRule"

PF_ROW = {
    "uuid": "11111111-1111-1111-1111-111111111111",
    "disabled": "0",
    "nordr": "0",
    "interface": "wan",
    "ipprotocol": "inet",
    "protocol": "TCP",
    "source.network": "any",
    "destination.network": "wanip",
    "destination.port": "443",
    "target": "10.0.0.5",
    "local-port": "8443",
    "descr": "Web",
    "log": "1",
    "sequence": "3",
    "categories": "secret-cat",
    "audit": "hidden",
}
OB_ROW = {
    "uuid": "22222222-2222-2222-2222-222222222222",
    "enabled": "1",
    "nonat": "0",
    "interface": "wan",
    "protocol": "any",
    "source_net": "10.0.0.0/24",
    "target": "wanip",
    "description": "LAN out",
    "sequence": "1",
    "audit": "hidden",
}


def test_port_forward_mapping_and_inversion_of_disabled() -> None:
    rows = {"rows": [PF_ROW, {**PF_ROW, "disabled": "1", "nordr": "1"}, "junk"]}
    r = normalise_nat(rows, "port_forward").rules
    assert len(r) == 2
    assert (r[0].enabled, r[0].excluded) == (True, False)
    assert (r[1].enabled, r[1].excluded) == (False, True)
    assert r[0].destination_port == "443" and r[0].target_port == "8443"
    assert r[0].description == "Web" and r[0].log is True and r[0].sequence == 3
    assert "secret-cat" not in r[0].model_dump_json() and "hidden" not in r[0].model_dump_json()


def test_outbound_mapping_and_automatic_flag() -> None:
    auto = {**OB_ROW, "uuid": "automatic_vtnet0", "is_automatic": True}
    r = normalise_nat({"rows": [OB_ROW, auto]}, "outbound").rules
    assert r[0].enabled is True and r[0].source == "10.0.0.0/24" and r[0].automatic is False
    assert r[1].automatic is True
    assert normalise_nat(None, "outbound").rules == []
    assert normalise_nat({"rows": "x"}, "port_forward").rules == []


def test_nat_is_capped() -> None:
    assert len(normalise_nat({"rows": [PF_ROW] * 2500}, "port_forward").rules) == 2000


async def test_nat_endpoints_are_read_only_audited_and_hide_internals(
    app_client: httpx.AsyncClient,
) -> None:
    await login_as(app_client, Role.admin)
    fid = await create_fw(app_client)
    await switch(app_client, Role.read_only, "ro")
    with respx.mock() as router:
        pf = router.get(DNAT).respond(200, json={"rows": [PF_ROW]})
        ob = router.get(SNAT).respond(200, json={"rows": [OB_ROW]})
        a = await app_client.get(f"/api/v1/firewalls/{fid}/firewall/nat/port-forwards")
        b = await app_client.get(f"/api/v1/firewalls/{fid}/firewall/nat/outbound")
    assert a.status_code == 200 and b.status_code == 200
    assert a.json()["rules"][0]["target"] == "10.0.0.5" and a.json()["registry_verified"] is True
    assert b.json()["rules"][0]["description"] == "LAN out"
    assert pf.calls.last.request.method == "GET" and ob.calls.last.request.method == "GET"
    assert "secret-cat" not in a.text and "hidden" not in a.text + b.text
    with app_client.app.state.sessionmaker() as db:  # type: ignore[attr-defined]
        actions = {x.action for x in db.scalars(select(AuditLog))}
    assert "firewall.firewall.nat.port_forwards.list" in actions
    assert "firewall.firewall.nat.outbound.list" in actions


async def test_nat_requires_login_and_collapses_errors_for_non_admins(
    app_client: httpx.AsyncClient,
) -> None:
    import uuid

    url = f"/api/v1/firewalls/{uuid.uuid4()}/firewall/nat/outbound"
    assert (await app_client.get(url)).status_code == 401
    await login_as(app_client, Role.admin)
    fid = await create_fw(app_client)
    with respx.mock() as router:
        router.get(SNAT).respond(403)
        admin = await app_client.get(f"/api/v1/firewalls/{fid}/firewall/nat/outbound")
        await switch(app_client, Role.read_only, "ro")
        other = await app_client.get(f"/api/v1/firewalls/{fid}/firewall/nat/outbound")
    assert admin.status_code == 502 and admin.json()["detail"]["status"] == "forbidden"
    assert other.status_code == 502 and other.json()["detail"]["status"] != "forbidden"
