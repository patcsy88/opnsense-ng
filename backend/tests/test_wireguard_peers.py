"""WireGuard peers (ADR-0019): validation, staging, apply. OPNsense is mocked."""

import base64
import json
from typing import Any

import httpx
import pytest
import respx
from pydantic import ValidationError
from sqlalchemy import select

from app.changes.wireguard_schemas import WireguardPeerProposal
from app.db.models import AuditLog, ChangeRequest, Role
from app.opnsense.normalise.wireguard_config import (
    normalise_wireguard_peers,
    normalise_wireguard_tunnels,
)
from app.opnsense.registry.entries import get_operation
from tests.conftest import csrf_headers
from tests.test_changes_api import act, switch
from tests.test_changes_rule_create import CHANGES, apply, approve, setup
from tests.test_security import db_rows

pytestmark = pytest.mark.usefixtures("db")

BASE = "https://fw.example.test/api/wireguard"
PEERS = f"{BASE}/client/searchClient"
TUNNELS = f"{BASE}/server/searchServer"
RECONFIGURE = f"{BASE}/service/reconfigure"
TARGET = "0b3a6c1e-1d2f-4a5b-8c7d-9e0f1a2b3c4d"
NEW_UUID = "5d6e7f80-1a2b-4c3d-8e4f-5a6b7c8d9e0f"
TUN = "7a1b2c3d-4e5f-4a6b-8c7d-9e0f1a2b3c4d"
OK = {"result": "ok"}
SECRET = "SHOULD-NEVER-APPEAR"


def key(n: int) -> str:
    return base64.b64encode(bytes([n]) * 32).decode()


def tunnel(**kw: Any) -> dict[str, Any]:
    base = {
        "uuid": TUN,
        "enabled": "1",
        "name": "wg0",
        "pubkey": key(9),
        "privkey": SECRET,
        "port": "51820",
        "tunneladdress": "10.10.0.1/24",
        "peers": TARGET,
    }
    base.update(kw)
    return base


def live(**kw: Any) -> dict[str, Any]:
    base = {
        "uuid": TARGET,
        "enabled": "1",
        "name": "alice",
        "pubkey": key(1),
        "psk": SECRET,
        "tunneladdress": "10.10.0.2/32",
        "servers": TUN,
        "serveraddress": "",
        "serverport": "",
        "keepalive": "",
    }
    base.update(kw)
    return base


def peer(**kw: Any) -> dict[str, Any]:
    body: dict[str, Any] = {
        "name": "bob",
        "pubkey": key(2),
        "tunneladdress": ["10.10.0.3/32"],
        "servers": [TUN],
        "keepalive": 25,
    }
    body.update(kw)
    return body


async def stage(
    client: httpx.AsyncClient,
    fid: str,
    rows: list[Any],
    path: str = "wireguard-peers",
    tunnels: list[Any] | None = None,
    **body: Any,
) -> httpx.Response:
    with respx.mock(assert_all_called=False) as router:
        router.get(PEERS).respond(200, json={"rows": rows})
        router.get(TUNNELS).respond(200, json={"rows": [tunnel()] if tunnels is None else tunnels})
        return await client.post(
            f"{CHANGES}/{path}", json={"firewall_id": fid, **body}, headers=csrf_headers(client)
        )


async def staged(
    client: httpx.AsyncClient,
    fid: str,
    rows: list[Any],
    path: str = "wireguard-peers",
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
        {"pubkey": "short"},
        {"pubkey": "!" * 43 + "="},
        {"pubkey": base64.b64encode(b"x" * 33).decode()[:44]},
        {"tunneladdress": []},
        {"tunneladdress": ["10.10.0.0/24"]},
        {"tunneladdress": ["not-an-ip"]},
        {"tunneladdress": ["10.10.0.3/32", "10.10.0.3"]},
        {"servers": []},
        {"servers": ["not-a-uuid"]},
        {"serveraddress": "bad host!"},
        {"serverport": 0},
        {"keepalive": 70000},
        {"psk": "x"},
        {"privkey": "x"},
    ],
)
def test_invalid_peers_are_refused(kw: dict[str, Any]) -> None:
    with pytest.raises(ValidationError):
        WireguardPeerProposal.model_validate(peer(**kw))


def test_values_are_normalised() -> None:
    p = WireguardPeerProposal.model_validate(
        peer(tunneladdress=["10.10.0.3", "FD00:0::5"], serveraddress="Vpn.Example.")
    )
    assert p.tunneladdress == ["10.10.0.3/32", "fd00::5/128"]
    assert p.serveraddress == "vpn.example"


def test_normaliser_never_keeps_secrets() -> None:
    [p] = normalise_wireguard_peers({"rows": [live(), {"name": "no-uuid"}, "junk"]}).peers
    assert p.has_psk is True and p.pubkey == key(1) and p.servers == [TUN]
    assert SECRET not in p.model_dump_json()
    [t] = normalise_wireguard_tunnels({"rows": [tunnel()]}).tunnels
    assert SECRET not in t.model_dump_json() and t.tunneladdress == ["10.10.0.1/24"]
    assert normalise_wireguard_peers(None).peers == []


def test_normaliser_reads_selected_option_dicts() -> None:
    row = live(servers={TUN: {"value": "wg0", "selected": 1}, "x": {"selected": 0}})
    assert normalise_wireguard_peers({"rows": [row]}).peers[0].servers == [TUN]


def test_registry_entries() -> None:
    assert get_operation("wireguard.peers.list").read_only is True
    assert get_operation("wireguard.tunnels.list").read_only is True
    for op_id in ("add", "update", "delete", "enable", "disable"):
        assert get_operation(f"wireguard.peers.{op_id}").read_only is False
    on = get_operation("wireguard.peers.enable")
    assert on.resolve_endpoint({"uuid": TARGET}).endswith(f"/toggleClient/{TARGET}/1")
    with pytest.raises(ValueError):
        on.resolve_endpoint({"uuid": "../x"})


async def test_creating_a_peer_is_normal_risk_and_only_reads(
    app_client: httpx.AsyncClient,
) -> None:
    fid = await setup(app_client)
    with respx.mock(assert_all_called=False) as router:
        router.get(PEERS).respond(200, json={"rows": [live()]})
        router.get(TUNNELS).respond(200, json={"rows": [tunnel()]})
        writes = router.post(url__startswith=BASE)
        r = await app_client.post(
            f"{CHANGES}/wireguard-peers",
            json={"firewall_id": fid, "peer": peer()},
            headers=csrf_headers(app_client),
        )
    assert r.status_code == 201, r.text
    body = r.json()
    assert body["kind"] == "wireguard_peer" and body["status"] == "validated"
    assert body["high_risk"] is False and writes.call_count == 0
    assert "psk" not in json.dumps(body) and "privkey" not in json.dumps(body)


async def test_risk_rules_for_update_toggle_and_delete(app_client: httpx.AsyncClient) -> None:
    fid = await setup(app_client)
    upd = f"wireguard-peers/{TARGET}/update"
    cases = [
        (
            upd,
            {
                "peer": peer(
                    name="alice", pubkey=key(1), tunneladdress=["10.10.0.2/32"], keepalive=10
                )
            },
            False,
        ),
        (upd, {"peer": peer(name="alice", pubkey=key(5), tunneladdress=["10.10.0.2/32"])}, True),
        (upd, {"peer": peer(name="alice", pubkey=key(1), tunneladdress=["10.10.0.9/32"])}, True),
        (
            upd,
            {
                "peer": peer(
                    name="alice", pubkey=key(1), tunneladdress=["10.10.0.2/32"], enabled=False
                )
            },
            True,
        ),
        (f"wireguard-peers/{TARGET}/toggle", {"enabled": False}, True),
        (f"wireguard-peers/{TARGET}/delete", {}, True),
    ]
    for path, extra, high in cases:
        r = await stage(app_client, fid, [live()], path, **extra)
        assert r.status_code == 201, (path, r.text)
        assert r.json()["high_risk"] is high, (path, extra)
        await act(app_client, r.json()["id"], "cancel")
    r = await stage(
        app_client, fid, [live(enabled="0")], f"wireguard-peers/{TARGET}/toggle", enabled=True
    )
    assert r.status_code == 201 and r.json()["high_risk"] is False


async def test_duplicate_key_address_tunnel_and_open_request_are_refused(
    app_client: httpx.AsyncClient,
) -> None:
    fid = await setup(app_client)
    dup_key = await stage(app_client, fid, [live()], peer=peer(pubkey=key(1)))
    assert dup_key.status_code == 400 and "public key" in dup_key.text
    dup_ip = await stage(app_client, fid, [live()], peer=peer(tunneladdress=["10.10.0.2/32"]))
    assert dup_ip.status_code == 400 and "tunnel addresses" in dup_ip.text
    outside = await stage(app_client, fid, [], peer=peer(tunneladdress=["192.168.9.9/32"]))
    assert outside.status_code == 400 and "not inside" in outside.text
    unknown = await stage(app_client, fid, [], peer=peer(servers=[NEW_UUID]))
    assert unknown.status_code == 400 and "does not exist" in unknown.text
    assert (await stage(app_client, fid, [], peer=peer())).status_code == 201
    again = await stage(app_client, fid, [], peer=peer(pubkey=key(4), tunneladdress=["10.10.0.8"]))
    assert again.status_code == 400 and "open request" in again.text


async def test_already_in_that_state_unknown_and_bad_target(
    app_client: httpx.AsyncClient,
) -> None:
    fid = await setup(app_client)
    same = await stage(app_client, fid, [live()], f"wireguard-peers/{TARGET}/toggle", enabled=True)
    assert same.status_code == 400 and "already enabled" in same.text
    gone = await stage(app_client, fid, [], f"wireguard-peers/{TARGET}/delete")
    bad = await stage(app_client, fid, [], "wireguard-peers/not-a-uuid/delete")
    assert gone.status_code == 400 and bad.status_code == 422
    with respx.mock() as router:
        router.get(PEERS).mock(side_effect=httpx.ConnectError("down"))
        r = await app_client.post(
            f"{CHANGES}/wireguard-peers",
            json={"firewall_id": fid, "peer": peer()},
            headers=csrf_headers(app_client),
        )
    assert r.status_code == 400


@pytest.mark.parametrize("role", [Role.security_admin, Role.read_only])
async def test_view_only_roles_cannot_stage_or_list(
    app_client: httpx.AsyncClient, role: Role
) -> None:
    fid = await setup(app_client)
    await switch(app_client, role, "viewer")
    assert (await stage(app_client, fid, [], peer=peer())).status_code == 403
    with respx.mock(assert_all_called=False) as router:
        call = router.route().respond(200, json={})
        peers = await app_client.get(f"/api/v1/firewalls/{fid}/wireguard/peers")
        tunnels = await app_client.get(f"/api/v1/firewalls/{fid}/wireguard/tunnels")
        assert not call.called
    assert peers.status_code == 403 and tunnels.status_code == 403


async def test_network_admin_lists_without_secrets_and_cannot_approve_own_request(
    app_client: httpx.AsyncClient,
) -> None:
    fid = await setup(app_client)
    await switch(app_client, Role.network_admin, "netadmin")
    with respx.mock(assert_all_called=False) as router:
        router.get(PEERS).respond(200, json={"rows": [live()]})
        router.get(TUNNELS).respond(200, json={"rows": [tunnel()]})
        peers = await app_client.get(f"/api/v1/firewalls/{fid}/wireguard/peers")
        tunnels = await app_client.get(f"/api/v1/firewalls/{fid}/wireguard/tunnels")
    assert peers.status_code == 200 and tunnels.status_code == 200
    assert peers.json()["peers"][0]["pubkey"] == key(1) and peers.json()["peers"][0]["has_psk"]
    assert tunnels.json()["tunnels"][0]["name"] == "wg0"
    assert SECRET not in peers.text and SECRET not in tunnels.text
    assert peers.json()["registry_verified"] is True
    unknown = "5d6e7f80-1a2b-4c3d-8e4f-5a6b7c8d9e0f"
    assert (await app_client.get(f"/api/v1/firewalls/{unknown}/wireguard/peers")).status_code == 404
    cid = str((await stage(app_client, fid, [], peer=peer())).json()["id"])
    await act(app_client, cid, "submit")
    assert (await act(app_client, cid, "approve")).status_code == 403


async def test_create_saves_then_reconfigures_and_reads_back(
    app_client: httpx.AsyncClient,
) -> None:
    fid = await setup(app_client)
    cid = await staged(app_client, fid, [live()], peer=peer())
    created = live(uuid=NEW_UUID, name="bob", pubkey=key(2), tunneladdress="10.10.0.3/32",
                   keepalive="25")  # fmt: skip
    with respx.mock() as router:
        router.get(PEERS).mock(
            side_effect=[
                httpx.Response(200, json={"rows": [live()]}),
                httpx.Response(200, json={"rows": [live(), created]}),
            ]
        )
        add = router.post(f"{BASE}/client/addClient").respond(
            200, json={"result": "saved", "uuid": NEW_UUID}
        )
        reconf = router.post(RECONFIGURE).respond(200, json=OK)
        done = await apply(app_client, cid)
        order = [c.request.url.path for c in router.calls]
    assert done.json()["status"] == "applied", done.text
    assert order.index("/api/wireguard/client/addClient") < order.index(
        "/api/wireguard/service/reconfigure"
    )
    sent = json.loads(add.calls.last.request.content)
    assert sent["client"] == {
        "enabled": "1",
        "name": "bob",
        "pubkey": key(2),
        "tunneladdress": "10.10.0.3/32",
        "servers": TUN,
        "serveraddress": "",
        "serverport": "",
        "keepalive": "25",
    }
    assert "psk" not in sent["client"] and "privkey" not in sent["client"]
    assert reconf.call_count == 1
    actions = {a.action for a in db_rows(app_client, select(AuditLog))}
    assert {"firewall.wireguard.peers.add", "firewall.wireguard.reconfigure"} <= actions
    [cr] = db_rows(app_client, select(ChangeRequest))
    assert cr.result_snapshot is not None and cr.result_snapshot["uuid"] == NEW_UUID
    assert SECRET not in json.dumps(cr.result_snapshot) and "psk" not in cr.result_snapshot


async def test_create_is_stale_when_the_key_appears(app_client: httpx.AsyncClient) -> None:
    fid = await setup(app_client)
    cid = await staged(app_client, fid, [], peer=peer())
    with respx.mock(assert_all_called=False) as router:
        router.get(PEERS).respond(200, json={"rows": [live(pubkey=key(2))]})
        add = router.post(f"{BASE}/client/addClient")
        r = await apply(app_client, cid)
    assert r.json()["status"] == "stale" and add.call_count == 0


async def test_update_targets_the_uuid_and_checks_the_fingerprint(
    app_client: httpx.AsyncClient,
) -> None:
    fid = await setup(app_client)
    path = f"wireguard-peers/{TARGET}/update"
    body = peer(name="alice", pubkey=key(1), tunneladdress=["10.10.0.9/32"])
    cid = await staged(app_client, fid, [live()], path, peer=body)
    with respx.mock(assert_all_called=False) as router:
        router.get(PEERS).respond(200, json={"rows": [live(name="changed")]})
        write = router.post(url__startswith=f"{BASE}/client")
        stale = await apply(app_client, cid, confirm_name="alice")
    assert stale.json()["status"] == "stale" and write.call_count == 0

    cid = await staged(app_client, fid, [live()], path, peer=body)
    with respx.mock() as router:
        router.get(PEERS).respond(200, json={"rows": [live()]})
        route = router.post(f"{BASE}/client/setClient/{TARGET}").respond(
            200, json={"result": "saved"}
        )
        router.post(RECONFIGURE).respond(200, json=OK)
        done = await apply(app_client, cid, confirm_name="alice")
    assert done.json()["status"] == "applied" and route.call_count == 1
    assert json.loads(route.calls.last.request.content)["client"]["tunneladdress"] == "10.10.0.9/32"


async def test_high_risk_apply_needs_the_typed_name(app_client: httpx.AsyncClient) -> None:
    fid = await setup(app_client)
    cid = await staged(app_client, fid, [live()], f"wireguard-peers/{TARGET}/delete")
    with respx.mock(assert_all_called=False) as router:
        delete = router.post(f"{BASE}/client/delClient/{TARGET}")
        missing = await apply(app_client, cid)
        wrong = await apply(app_client, cid, confirm_name="nope")
        assert delete.call_count == 0
    assert missing.status_code == 400 and wrong.status_code == 400


async def test_toggle_uses_the_explicit_state_endpoint(app_client: httpx.AsyncClient) -> None:
    fid = await setup(app_client)
    cid = await staged(app_client, fid, [live()], f"wireguard-peers/{TARGET}/toggle", enabled=False)
    with respx.mock() as router:
        router.get(PEERS).respond(200, json={"rows": [live()]})
        route = router.post(f"{BASE}/client/toggleClient/{TARGET}/0").respond(
            200, json={"result": "Disabled"}
        )
        router.post(RECONFIGURE).respond(200, json=OK)
        done = await apply(app_client, cid, confirm_name="alice")
    assert done.json()["status"] == "applied" and route.call_count == 1


async def test_delete_applies_with_the_typed_name(app_client: httpx.AsyncClient) -> None:
    fid = await setup(app_client)
    cid = await staged(app_client, fid, [live()], f"wireguard-peers/{TARGET}/delete")
    with respx.mock() as router:
        router.get(PEERS).respond(200, json={"rows": [live()]})
        route = router.post(f"{BASE}/client/delClient/{TARGET}").respond(
            200, json={"result": "deleted"}
        )
        router.post(RECONFIGURE).respond(200, json=OK)
        done = await apply(app_client, cid, confirm_name="alice")
    assert done.json()["status"] == "applied" and route.call_count == 1


async def test_reconfigure_failure_says_saved_but_not_active(
    app_client: httpx.AsyncClient,
) -> None:
    fid = await setup(app_client)
    cid = await staged(app_client, fid, [], peer=peer())
    with respx.mock() as router:
        router.get(PEERS).respond(200, json={"rows": []})
        router.post(f"{BASE}/client/addClient").respond(
            200, json={"result": "saved", "uuid": NEW_UUID}
        )
        router.post(RECONFIGURE).respond(500, json={})
        done = await apply(app_client, cid)
    assert done.json()["status"] == "failed"
    assert "saved on the firewall but NOT active" in done.json()["failure_message"]


async def test_unconfirmed_reconfigure_is_not_active(app_client: httpx.AsyncClient) -> None:
    fid = await setup(app_client)
    cid = await staged(app_client, fid, [], peer=peer())
    with respx.mock() as router:
        router.get(PEERS).respond(200, json={"rows": []})
        router.post(f"{BASE}/client/addClient").respond(
            200, json={"result": "saved", "uuid": NEW_UUID}
        )
        router.post(RECONFIGURE).respond(200, json={"result": "failed"})
        done = await apply(app_client, cid)
    assert done.json()["status"] == "failed"
    assert "NOT active" in done.json()["failure_message"]


async def test_rejected_save_skips_reconfigure(app_client: httpx.AsyncClient) -> None:
    fid = await setup(app_client)
    cid = await staged(app_client, fid, [], peer=peer())
    with respx.mock(assert_all_called=False) as router:
        router.get(PEERS).respond(200, json={"rows": []})
        router.post(f"{BASE}/client/addClient").respond(
            200, json={"result": "failed", "validations": {"client.pubkey": "Invalid"}}
        )
        reconf = router.post(RECONFIGURE).respond(200, json=OK)
        done = await apply(app_client, cid)
    assert done.json()["status"] == "failed" and reconf.call_count == 0
