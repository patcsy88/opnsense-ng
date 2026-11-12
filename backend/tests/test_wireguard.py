"""WireGuard status (ADR-0009). OPNsense is mocked."""

import httpx
import respx
from sqlalchemy import select

from app.db.models import AuditLog, Role
from app.opnsense.normalise import normalise_wireguard
from tests.test_api import create_fw, login_as
from tests.test_changes_api import switch

URL = "https://fw.example.test/api/wireguard/service/show"

ROWS = {
    "rows": [
        {
            "if": "wg0",
            "type": "interface",
            "name": "road-warrior",
            "ifname": "road-warrior",
            "public-key": "PUBKEYINTERFACE=",
            "private-key": "PRIVATEKEYSECRET=",
            "listen-port": "51820",
            "endpoint": "51820",
            "status": "up",
        },
        {
            "if": "wg0",
            "type": "peer",
            "name": "phone",
            "ifname": "road-warrior",
            "public-key": "PUBKEYPEER=",
            "preshared-key": "PSKSECRET=",
            "endpoint": "203.0.113.7:40000",
            "allowed-ips": "10.10.0.2/32,fd00::2/128",
            "latest-handshake": 1762950000,
            "transfer-rx": 1000,
            "transfer-tx": "2000",
            "persistent-keepalive": "25",
            "peer-status": "online",
        },
        {
            "if": "wg0",
            "type": "peer",
            "name": "",
            "endpoint": "(none)",
            "allowed-ips": "(none)",
            "latest-handshake": 0,
            "persistent-keepalive": "off",
            "peer-status": "offline",
        },
        {"if": "wg0", "type": "weird"},
        {"type": "peer"},
        "junk",
    ]
}


def test_mapping_uses_whitelist_and_drops_keys() -> None:
    result = normalise_wireguard(ROWS)
    iface, peer, idle = result.records
    assert (iface.type, iface.status, iface.listen_port, iface.tunnel_name) == (
        "interface",
        "up",
        51820,
        "road-warrior",
    )
    assert iface.endpoint is None
    assert (peer.name, peer.status, peer.endpoint) == ("phone", "online", "203.0.113.7:40000")
    assert peer.allowed_ips == ["10.10.0.2/32", "fd00::2/128"]
    assert (peer.rx_bytes, peer.tx_bytes, peer.keepalive) == (1000, 2000, 25)
    assert peer.latest_handshake is not None and peer.latest_handshake.startswith("2025-")
    assert (idle.endpoint, idle.allowed_ips, idle.latest_handshake, idle.keepalive) == (
        None,
        [],
        None,
        None,
    )
    dumped = result.model_dump_json()
    for secret in ("PUBKEY", "PRIVATEKEY", "PSKSECRET", "public-key", "private"):
        assert secret not in dumped


def test_bad_shapes_and_cap() -> None:
    cases: list[object] = [None, [], {"rows": "x"}, "x"]
    for raw in cases:
        assert normalise_wireguard(raw).records == []
    capped = normalise_wireguard({"rows": [{"if": "wg0", "type": "peer"}] * 800})
    assert len(capped.records) == 500 and capped.truncated is True


async def test_endpoint_roles_audit_and_no_keys(app_client: httpx.AsyncClient) -> None:
    await login_as(app_client, Role.admin)
    fid = await create_fw(app_client)
    path = f"/api/v1/firewalls/{fid}/vpn/wireguard"
    with respx.mock() as router:
        router.get(URL).respond(200, json=ROWS)
        r = await app_client.get(path)
        for role, name in ((Role.network_admin, "net"), (Role.security_admin, "sec")):
            await switch(app_client, role, name)
            assert (await app_client.get(path)).status_code == 200
        await switch(app_client, Role.read_only, "ro")
        denied = await app_client.get(path)
        post = await app_client.post(path)
    assert r.status_code == 200 and len(r.json()["records"]) == 3
    assert r.json()["registry_verified"] is True and denied.status_code == 403
    assert post.status_code in (404, 405)
    for secret in ("PUBKEY", "PRIVATEKEY", "PSKSECRET"):
        assert secret not in r.text
    with app_client.app.state.sessionmaker() as db:  # type: ignore[attr-defined]
        actions = [a.action for a in db.scalars(select(AuditLog))]
    assert actions.count("firewall.wireguard.status") == 3


async def test_failure_is_collapsed_for_non_admins(app_client: httpx.AsyncClient) -> None:
    await login_as(app_client, Role.admin)
    fid = await create_fw(app_client)
    await switch(app_client, Role.network_admin, "net")
    with respx.mock() as router:
        router.get(URL).respond(403, json={"status": 403})
        r = await app_client.get(f"/api/v1/firewalls/{fid}/vpn/wireguard")
    assert r.status_code == 502 and r.json()["detail"]["message"] == "Firewall is unreachable"
