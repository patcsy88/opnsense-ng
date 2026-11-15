"""WireGuard tunnels (ADR-0019): validation, staging, apply. OPNsense is mocked."""

import json
from typing import Any

import httpx
import pytest
import respx
from pydantic import ValidationError
from sqlalchemy import select

from app.changes.wireguard_schemas import WireguardTunnelProposal
from app.db.models import AuditLog, ChangeRequest, Role
from app.opnsense.registry.entries import get_operation
from tests.conftest import csrf_headers
from tests.test_changes_api import act, switch
from tests.test_changes_rule_create import CHANGES, apply, approve, setup
from tests.test_security import db_rows
from tests.test_wireguard_peers import (
    BASE,
    NEW_UUID,
    OK,
    PEERS,
    RECONFIGURE,
    SECRET,
    TARGET,
    TUN,
    TUNNELS,
    live,
    tunnel,
)

pytestmark = pytest.mark.usefixtures("db")

OTHER = "9c8b7a6d-5e4f-4a3b-8c2d-1e0f9a8b7c6d"


def tun(**kw: Any) -> dict[str, Any]:
    body: dict[str, Any] = {
        "name": "wg1",
        "port": 51821,
        "tunneladdress": ["10.20.0.1/24"],
        "peers": [TARGET],
    }
    body.update(kw)
    return body


async def stage(
    client: httpx.AsyncClient,
    fid: str,
    rows: list[Any],
    path: str = "wireguard-tunnels",
    peers: list[Any] | None = None,
    **body: Any,
) -> httpx.Response:
    with respx.mock(assert_all_called=False) as router:
        router.get(TUNNELS).respond(200, json={"rows": rows})
        router.get(PEERS).respond(200, json={"rows": [live()] if peers is None else peers})
        return await client.post(
            f"{CHANGES}/{path}", json={"firewall_id": fid, **body}, headers=csrf_headers(client)
        )


async def staged(
    client: httpx.AsyncClient,
    fid: str,
    rows: list[Any],
    path: str = "wireguard-tunnels",
    **body: Any,
) -> str:
    r = await stage(client, fid, rows, path, **body)
    assert r.status_code == 201, r.text
    cid = str(r.json()["id"])
    await approve(client, cid)
    return cid


@pytest.mark.parametrize(
    "kw",
    [
        {"name": ""},
        {"name": "bad name"},
        {"port": 0},
        {"port": 70000},
        {"tunneladdress": []},
        {"tunneladdress": ["10.20.0.1"]},
        {"tunneladdress": ["10.20.0.1/32"]},
        {"tunneladdress": ["nope/24"]},
        {"mtu": 100},
        {"peers": ["not-a-uuid"]},
        {"privkey": "x"},
        {"private_key": "x"},
    ],
)
def test_invalid_tunnels_are_refused(kw: dict[str, Any]) -> None:
    with pytest.raises(ValidationError):
        WireguardTunnelProposal.model_validate(tun(**kw))


def test_registry_entries() -> None:
    for op_id in ("add", "update", "delete", "enable", "disable"):
        assert get_operation(f"wireguard.tunnels.{op_id}").read_only is False
    off = get_operation("wireguard.tunnels.disable")
    assert off.resolve_endpoint({"uuid": TUN}).endswith(f"/toggleServer/{TUN}/0")
    with pytest.raises(ValueError):
        off.resolve_endpoint({"uuid": "../x"})


async def test_every_tunnel_change_is_high_risk_and_only_reads(
    app_client: httpx.AsyncClient,
) -> None:
    fid = await setup(app_client)
    with respx.mock(assert_all_called=False) as router:
        router.get(TUNNELS).respond(200, json={"rows": [tunnel()]})
        router.get(PEERS).respond(200, json={"rows": [live()]})
        writes = router.post(url__startswith=BASE)
        r = await app_client.post(
            f"{CHANGES}/wireguard-tunnels",
            json={"firewall_id": fid, "tunnel": tun()},
            headers=csrf_headers(app_client),
        )
    assert r.status_code == 201, r.text
    body = r.json()
    assert body["kind"] == "wireguard_tunnel" and body["high_risk"] is True
    assert writes.call_count == 0
    assert SECRET not in json.dumps(body) and "privkey" not in json.dumps(body)

    cases: list[tuple[str, dict[str, Any]]] = [
        (f"wireguard-tunnels/{TUN}/update", {"tunnel": tun(name="wg0", port=51820)}),
        (f"wireguard-tunnels/{TUN}/toggle", {"enabled": False}),
        (f"wireguard-tunnels/{TUN}/toggle", {"enabled": True}),
        (f"wireguard-tunnels/{TUN}/delete", {}),
    ]
    for path, extra in cases:
        rows = [tunnel(enabled="0")] if extra.get("enabled") is True else [tunnel()]
        r = await stage(app_client, fid, rows, path, **extra)
        assert r.status_code == 201, (path, r.text)
        assert r.json()["high_risk"] is True, path
        await act(app_client, r.json()["id"], "cancel")


async def test_conflicts_and_unknown_peers_are_refused(app_client: httpx.AsyncClient) -> None:
    fid = await setup(app_client)
    rows = [tunnel()]
    dup_name = await stage(app_client, fid, rows, tunnel=tun(name="WG0"))
    assert dup_name.status_code == 400 and "name already exists" in dup_name.text
    dup_port = await stage(app_client, fid, rows, tunnel=tun(port=51820))
    assert dup_port.status_code == 400 and "port" in dup_port.text
    overlap = await stage(app_client, fid, rows, tunnel=tun(tunneladdress=["10.10.0.9/25"]))
    assert overlap.status_code == 400 and "overlaps" in overlap.text
    unknown = await stage(app_client, fid, rows, tunnel=tun(peers=[OTHER]))
    assert unknown.status_code == 400 and "does not exist" in unknown.text
    assert (await stage(app_client, fid, rows, tunnel=tun())).status_code == 201
    again = await stage(
        app_client, fid, rows, tunnel=tun(port=51830, tunneladdress=["10.30.0.1/24"])
    )
    assert again.status_code == 400 and "open request" in again.text
    gone = await stage(app_client, fid, [], f"wireguard-tunnels/{TUN}/delete")
    bad = await stage(app_client, fid, [], "wireguard-tunnels/not-a-uuid/delete")
    assert gone.status_code == 400 and bad.status_code == 422


@pytest.mark.parametrize("role", [Role.security_admin, Role.read_only])
async def test_view_only_roles_cannot_stage(app_client: httpx.AsyncClient, role: Role) -> None:
    fid = await setup(app_client)
    await switch(app_client, role, "viewer")
    assert (await stage(app_client, fid, [], tunnel=tun())).status_code == 403


async def test_network_admin_cannot_approve_own_tunnel_request(
    app_client: httpx.AsyncClient,
) -> None:
    fid = await setup(app_client)
    await switch(app_client, Role.network_admin, "netadmin")
    cid = str((await stage(app_client, fid, [], tunnel=tun())).json()["id"])
    await act(app_client, cid, "submit")
    assert (await act(app_client, cid, "approve")).status_code == 403


GEN_PRIV = "SENTINEL-GENERATED-PRIVATE-KEY-0000000000000="
GEN_PUB = "SENTINEL-GENERATED-PUBLIC-KEY-00000000000000="


async def test_create_uses_a_firewall_made_key_pair_and_never_keeps_it(
    app_client: httpx.AsyncClient,
) -> None:
    fid = await setup(app_client)
    cid = await staged(app_client, fid, [tunnel()], tunnel=tun())
    created = tunnel(uuid=NEW_UUID, name="wg1", port="51821", tunneladdress="10.20.0.1/24")
    with respx.mock() as router:
        router.get(f"{BASE}/server/keyPair").respond(
            200, json={"status": "ok", "privkey": GEN_PRIV, "pubkey": GEN_PUB}
        )
        router.get(TUNNELS).mock(
            side_effect=[
                httpx.Response(200, json={"rows": [tunnel()]}),
                httpx.Response(200, json={"rows": [tunnel(), created]}),
            ]
        )
        add = router.post(f"{BASE}/server/addServer").respond(
            200, json={"result": "saved", "uuid": NEW_UUID}
        )
        reconf = router.post(RECONFIGURE).respond(200, json=OK)
        done = await apply(app_client, cid, confirm_name="wg1")
    assert done.json()["status"] == "applied", done.text
    sent = json.loads(add.calls.last.request.content)
    assert sent["server"] == {
        "enabled": "1",
        "name": "wg1",
        "port": "51821",
        "tunneladdress": "10.20.0.1/24",
        "mtu": "",
        "disableroutes": "0",
        "peers": TARGET,
        "privkey": GEN_PRIV,
        "pubkey": GEN_PUB,
    }
    assert reconf.call_count == 1
    actions = {a.action for a in db_rows(app_client, select(AuditLog))}
    assert {
        "firewall.wireguard.tunnels.keypair",
        "firewall.wireguard.tunnels.add",
        "firewall.wireguard.reconfigure",
    } <= actions
    [cr] = db_rows(app_client, select(ChangeRequest))
    assert cr.result_snapshot is not None and cr.result_snapshot["uuid"] == NEW_UUID
    stored = json.dumps(
        {
            "snap": cr.result_snapshot,
            "proposed": cr.proposed,
            "base": cr.base_snapshot,
            "fail": cr.failure_message,
            "audit": [a.detail for a in db_rows(app_client, select(AuditLog))],
            "resp": done.json(),
        },
        default=str,
    )
    assert GEN_PRIV not in stored and SECRET not in stored


async def test_create_fails_cleanly_without_a_key_pair(app_client: httpx.AsyncClient) -> None:
    fid = await setup(app_client)
    cid = await staged(app_client, fid, [tunnel()], tunnel=tun())
    with respx.mock(assert_all_called=False) as router:
        router.get(TUNNELS).respond(200, json={"rows": [tunnel()]})
        router.get(f"{BASE}/server/keyPair").respond(200, json={"status": "ok"})
        add = router.post(f"{BASE}/server/addServer")
        done = await apply(app_client, cid, confirm_name="wg1")
    assert done.json()["status"] == "failed" and add.call_count == 0


async def test_high_risk_apply_needs_the_typed_name(app_client: httpx.AsyncClient) -> None:
    fid = await setup(app_client)
    cid = await staged(app_client, fid, [tunnel()], f"wireguard-tunnels/{TUN}/delete")
    with respx.mock(assert_all_called=False) as router:
        delete = router.post(f"{BASE}/server/delServer/{TUN}")
        missing = await apply(app_client, cid)
        wrong = await apply(app_client, cid, confirm_name="nope")
        assert delete.call_count == 0
    assert missing.status_code == 400 and wrong.status_code == 400


async def test_update_toggle_and_delete_use_the_uuid_endpoints(
    app_client: httpx.AsyncClient,
) -> None:
    fid = await setup(app_client)
    cid = await staged(
        app_client, fid, [tunnel()], f"wireguard-tunnels/{TUN}/update",
        tunnel=tun(name="wg0", port=51820, tunneladdress=["10.10.0.1/24"], mtu=1380),
    )  # fmt: skip
    with respx.mock() as router:
        router.get(TUNNELS).respond(200, json={"rows": [tunnel()]})
        route = router.post(f"{BASE}/server/setServer/{TUN}").respond(200, json={"result": "saved"})
        router.post(RECONFIGURE).respond(200, json=OK)
        done = await apply(app_client, cid, confirm_name="wg0")
    assert done.json()["status"] == "applied"
    sent = json.loads(route.calls.last.request.content)["server"]
    assert sent["mtu"] == "1380" and "privkey" not in sent

    cid = await staged(
        app_client, fid, [tunnel()], f"wireguard-tunnels/{TUN}/toggle", enabled=False
    )
    with respx.mock() as router:
        router.get(TUNNELS).respond(200, json={"rows": [tunnel()]})
        off = router.post(f"{BASE}/server/toggleServer/{TUN}/0").respond(
            200, json={"result": "Disabled"}
        )
        router.post(RECONFIGURE).respond(200, json=OK)
        done = await apply(app_client, cid, confirm_name="wg0")
    assert done.json()["status"] == "applied" and off.call_count == 1

    cid = await staged(app_client, fid, [tunnel()], f"wireguard-tunnels/{TUN}/delete")
    with respx.mock() as router:
        router.get(TUNNELS).respond(200, json={"rows": [tunnel()]})
        gone = router.post(f"{BASE}/server/delServer/{TUN}").respond(
            200, json={"result": "deleted"}
        )
        router.post(RECONFIGURE).respond(200, json=OK)
        done = await apply(app_client, cid, confirm_name="wg0")
    assert done.json()["status"] == "applied" and gone.call_count == 1


async def test_stale_when_the_tunnel_changed(app_client: httpx.AsyncClient) -> None:
    fid = await setup(app_client)
    cid = await staged(app_client, fid, [tunnel()], f"wireguard-tunnels/{TUN}/delete")
    with respx.mock(assert_all_called=False) as router:
        router.get(TUNNELS).respond(200, json={"rows": [tunnel(port="51999")]})
        delete = router.post(url__startswith=f"{BASE}/server")
        r = await apply(app_client, cid, confirm_name="wg0")
    assert r.json()["status"] == "stale" and delete.call_count == 0


async def test_reconfigure_failure_says_saved_but_not_active(
    app_client: httpx.AsyncClient,
) -> None:
    fid = await setup(app_client)
    cid = await staged(app_client, fid, [tunnel()], tunnel=tun())
    with respx.mock() as router:
        router.get(TUNNELS).respond(200, json={"rows": [tunnel()]})
        router.get(f"{BASE}/server/keyPair").respond(
            200, json={"status": "ok", "privkey": GEN_PRIV, "pubkey": GEN_PUB}
        )
        router.post(f"{BASE}/server/addServer").respond(
            200, json={"result": "saved", "uuid": NEW_UUID}
        )
        router.post(RECONFIGURE).respond(500, json={})
        done = await apply(app_client, cid, confirm_name="wg1")
    assert done.json()["status"] == "failed"
    assert "saved on the firewall but NOT active" in done.json()["failure_message"]
