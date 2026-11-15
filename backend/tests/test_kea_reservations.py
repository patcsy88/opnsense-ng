"""Kea DHCPv4 reservations (ADR-0021): validation, staging, apply. OPNsense is mocked."""

import json
from typing import Any

import httpx
import pytest
import respx
from pydantic import ValidationError
from sqlalchemy import select

from app.changes.kea_schemas import KeaReservationProposal
from app.db.models import AuditLog, ChangeRequest, Role
from app.opnsense.registry.entries import get_operation
from tests.conftest import csrf_headers
from tests.test_changes_api import act, switch
from tests.test_changes_rule_create import CHANGES, apply, approve, setup
from tests.test_security import db_rows

pytestmark = pytest.mark.usefixtures("db")

BASE = "https://fw.example.test/api/kea"
RESERVATIONS = f"{BASE}/dhcpv4/searchReservation"
SUBNETS = f"{BASE}/dhcpv4/searchSubnet"
RECONFIGURE = f"{BASE}/service/reconfigure"
TARGET = "0b3a6c1e-1d2f-4a5b-8c7d-9e0f1a2b3c4d"
NEW_UUID = "5d6e7f80-1a2b-4c3d-8e4f-5a6b7c8d9e0f"
SUB = "7a1b2c3d-4e5f-4a6b-8c7d-9e0f1a2b3c4d"
OK = {"status": "ok"}


def subnet(**kw: Any) -> dict[str, Any]:
    base = {
        "uuid": SUB,
        "subnet": "192.168.1.0/24",
        "pools": "192.168.1.100-192.168.1.199\n",
        "description": "",
    }
    base.update(kw)
    return base


def live(**kw: Any) -> dict[str, Any]:
    base = {
        "uuid": TARGET,
        "subnet": SUB,
        "%subnet": "192.168.1.0/24",
        "ip_address": "192.168.1.10",
        "hw_address": "02:00:00:00:00:01",
        "hostname": "alice",
        "description": "",
    }
    base.update(kw)
    return base


def res(**kw: Any) -> dict[str, Any]:
    body: dict[str, Any] = {
        "subnet": SUB,
        "ip_address": "192.168.1.20",
        "hw_address": "02:00:00:00:00:02",
        "hostname": "bob",
    }
    body.update(kw)
    return body


async def stage(
    client: httpx.AsyncClient,
    fid: str,
    rows: list[Any],
    path: str = "kea-reservations",
    subnets: list[Any] | None = None,
    **body: Any,
) -> httpx.Response:
    with respx.mock(assert_all_called=False) as router:
        router.get(RESERVATIONS).respond(200, json={"rows": rows})
        router.get(SUBNETS).respond(200, json={"rows": [subnet()] if subnets is None else subnets})
        return await client.post(
            f"{CHANGES}/{path}", json={"firewall_id": fid, **body}, headers=csrf_headers(client)
        )


async def staged(
    client: httpx.AsyncClient,
    fid: str,
    rows: list[Any],
    path: str = "kea-reservations",
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
        {"subnet": "not-a-uuid"},
        {"ip_address": "999.1.1.1"},
        {"ip_address": "fd00::1"},
        {"hw_address": "nope"},
        {"hw_address": "02:00:00:00:00"},
        {"hostname": "bad name!"},
        {"client_id": "x"},
    ],
)
def test_invalid_reservations_are_refused(kw: dict[str, Any]) -> None:
    with pytest.raises(ValidationError):
        KeaReservationProposal.model_validate(res(**kw))


def test_values_are_normalised() -> None:
    p = KeaReservationProposal.model_validate(res(hw_address="02-AA-BB-CC-DD-EE", hostname="Bob."))
    assert p.hw_address == "02:aa:bb:cc:dd:ee" and p.hostname == "bob"


def test_registry_entries() -> None:
    for op_id in ("add", "update", "delete"):
        assert get_operation(f"kea.reservations4.{op_id}").read_only is False
    assert get_operation("kea.reconfigure").read_only is False
    upd = get_operation("kea.reservations4.update")
    assert upd.resolve_endpoint({"uuid": TARGET}).endswith(f"/setReservation/{TARGET}")
    with pytest.raises(ValueError):
        upd.resolve_endpoint({"uuid": "../x"})


async def test_creating_is_normal_risk_and_only_reads(app_client: httpx.AsyncClient) -> None:
    fid = await setup(app_client)
    with respx.mock(assert_all_called=False) as router:
        router.get(RESERVATIONS).respond(200, json={"rows": [live()]})
        router.get(SUBNETS).respond(200, json={"rows": [subnet()]})
        writes = router.post(url__startswith=BASE)
        r = await app_client.post(
            f"{CHANGES}/kea-reservations",
            json={"firewall_id": fid, "reservation": res()},
            headers=csrf_headers(app_client),
        )
    assert r.status_code == 201, r.text
    body = r.json()
    assert body["kind"] == "kea_reservation" and body["status"] == "validated"
    assert body["high_risk"] is False and writes.call_count == 0


async def test_risk_rules_for_update_and_delete(app_client: httpx.AsyncClient) -> None:
    fid = await setup(app_client)
    upd = f"kea-reservations/{TARGET}/update"
    same = {"ip_address": "192.168.1.10", "hw_address": "02:00:00:00:00:01"}
    cases = [
        (upd, {"reservation": res(**same, hostname="renamed", description="d")}, False),
        (upd, {"reservation": res(**{**same, "hw_address": "02:00:00:00:00:09"})}, True),
        (upd, {"reservation": res(**{**same, "ip_address": "192.168.1.11"})}, True),
        (f"kea-reservations/{TARGET}/delete", {}, True),
    ]
    for path, extra, high in cases:
        r = await stage(app_client, fid, [live()], path, **extra)
        assert r.status_code == 201, (path, r.text)
        assert r.json()["high_risk"] is high, (path, extra)
        await act(app_client, r.json()["id"], "cancel")


async def test_conflicts_pool_subnet_and_open_request_are_refused(
    app_client: httpx.AsyncClient,
) -> None:
    fid = await setup(app_client)
    dup_ip = await stage(app_client, fid, [live()], reservation=res(ip_address="192.168.1.10"))
    assert dup_ip.status_code == 400 and "IP address already exists" in dup_ip.text
    dup_mac = await stage(
        app_client, fid, [live()], reservation=res(hw_address="02:00:00:00:00:01")
    )
    assert dup_mac.status_code == 400 and "MAC" in dup_mac.text
    pool = await stage(app_client, fid, [], reservation=res(ip_address="192.168.1.150"))
    assert pool.status_code == 400 and "dynamic pool" in pool.text
    outside = await stage(app_client, fid, [], reservation=res(ip_address="10.0.0.5"))
    assert outside.status_code == 400 and "outside the subnet" in outside.text
    unknown = await stage(app_client, fid, [], reservation=res(subnet=NEW_UUID))
    assert unknown.status_code == 400 and "does not exist" in unknown.text
    assert (await stage(app_client, fid, [], reservation=res())).status_code == 201
    again = await stage(app_client, fid, [], reservation=res(hw_address="02:00:00:00:00:03"))
    assert again.status_code == 400 and "open request" in again.text


async def test_unknown_target_bad_id_and_firewall_down(app_client: httpx.AsyncClient) -> None:
    fid = await setup(app_client)
    gone = await stage(app_client, fid, [], f"kea-reservations/{TARGET}/delete")
    bad = await stage(app_client, fid, [], "kea-reservations/not-a-uuid/delete")
    assert gone.status_code == 400 and bad.status_code == 422
    with respx.mock() as router:
        router.get(RESERVATIONS).mock(side_effect=httpx.ConnectError("down"))
        r = await app_client.post(
            f"{CHANGES}/kea-reservations",
            json={"firewall_id": fid, "reservation": res()},
            headers=csrf_headers(app_client),
        )
    assert r.status_code == 400


@pytest.mark.parametrize("role", [Role.security_admin, Role.read_only])
async def test_view_only_roles_cannot_stage(app_client: httpx.AsyncClient, role: Role) -> None:
    fid = await setup(app_client)
    await switch(app_client, role, "viewer")
    assert (await stage(app_client, fid, [], reservation=res())).status_code == 403


async def test_network_admin_cannot_approve_own_request(app_client: httpx.AsyncClient) -> None:
    fid = await setup(app_client)
    await switch(app_client, Role.network_admin, "netadmin")
    cid = str((await stage(app_client, fid, [], reservation=res())).json()["id"])
    await act(app_client, cid, "submit")
    assert (await act(app_client, cid, "approve")).status_code == 403


async def test_create_saves_then_reconfigures_and_reads_back(
    app_client: httpx.AsyncClient,
) -> None:
    fid = await setup(app_client)
    cid = await staged(app_client, fid, [live()], reservation=res())
    created = live(uuid=NEW_UUID, ip_address="192.168.1.20", hw_address="02:00:00:00:00:02",
                   hostname="bob")  # fmt: skip
    with respx.mock() as router:
        router.get(RESERVATIONS).mock(
            side_effect=[
                httpx.Response(200, json={"rows": [live()]}),
                httpx.Response(200, json={"rows": [live(), created]}),
            ]
        )
        add = router.post(f"{BASE}/dhcpv4/addReservation").respond(
            200, json={"result": "saved", "uuid": NEW_UUID}
        )
        reconf = router.post(RECONFIGURE).respond(200, json=OK)
        done = await apply(app_client, cid)
        order = [c.request.url.path for c in router.calls]
    assert done.json()["status"] == "applied", done.text
    assert order.index("/api/kea/dhcpv4/addReservation") < order.index(
        "/api/kea/service/reconfigure"
    )
    sent = json.loads(add.calls.last.request.content)
    assert sent["reservation"] == {
        "subnet": SUB,
        "ip_address": "192.168.1.20",
        "hw_address": "02:00:00:00:00:02",
        "hostname": "bob",
        "description": "",
    }
    assert reconf.call_count == 1
    actions = {a.action for a in db_rows(app_client, select(AuditLog))}
    assert {"firewall.kea.reservations4.add", "firewall.kea.reconfigure"} <= actions
    [cr] = db_rows(app_client, select(ChangeRequest))
    assert cr.result_snapshot is not None and cr.result_snapshot["uuid"] == NEW_UUID


async def test_create_is_stale_when_the_ip_appears(app_client: httpx.AsyncClient) -> None:
    fid = await setup(app_client)
    cid = await staged(app_client, fid, [], reservation=res())
    with respx.mock(assert_all_called=False) as router:
        router.get(RESERVATIONS).respond(200, json={"rows": [live(ip_address="192.168.1.20")]})
        add = router.post(f"{BASE}/dhcpv4/addReservation")
        r = await apply(app_client, cid)
    assert r.json()["status"] == "stale" and add.call_count == 0


async def test_update_checks_the_fingerprint_and_targets_the_uuid(
    app_client: httpx.AsyncClient,
) -> None:
    fid = await setup(app_client)
    path = f"kea-reservations/{TARGET}/update"
    body = res(ip_address="192.168.1.11", hw_address="02:00:00:00:00:01")
    cid = await staged(app_client, fid, [live()], path, reservation=body)
    with respx.mock(assert_all_called=False) as router:
        router.get(RESERVATIONS).respond(200, json={"rows": [live(hostname="changed")]})
        write = router.post(url__startswith=f"{BASE}/dhcpv4")
        stale = await apply(app_client, cid, confirm_name="192.168.1.10")
    assert stale.json()["status"] == "stale" and write.call_count == 0

    cid = await staged(app_client, fid, [live()], path, reservation=body)
    with respx.mock() as router:
        router.get(RESERVATIONS).respond(200, json={"rows": [live()]})
        route = router.post(f"{BASE}/dhcpv4/setReservation/{TARGET}").respond(
            200, json={"result": "saved"}
        )
        router.post(RECONFIGURE).respond(200, json=OK)
        done = await apply(app_client, cid, confirm_name="192.168.1.10")
    assert done.json()["status"] == "applied" and route.call_count == 1
    assert json.loads(route.calls.last.request.content)["reservation"]["ip_address"] == (
        "192.168.1.11"
    )


async def test_high_risk_apply_needs_the_typed_ip(app_client: httpx.AsyncClient) -> None:
    fid = await setup(app_client)
    cid = await staged(app_client, fid, [live()], f"kea-reservations/{TARGET}/delete")
    with respx.mock(assert_all_called=False) as router:
        delete = router.post(f"{BASE}/dhcpv4/delReservation/{TARGET}")
        missing = await apply(app_client, cid)
        wrong = await apply(app_client, cid, confirm_name="nope")
        assert delete.call_count == 0
    assert missing.status_code == 400 and wrong.status_code == 400


async def test_delete_applies_with_the_typed_ip(app_client: httpx.AsyncClient) -> None:
    fid = await setup(app_client)
    cid = await staged(app_client, fid, [live()], f"kea-reservations/{TARGET}/delete")
    with respx.mock() as router:
        router.get(RESERVATIONS).respond(200, json={"rows": [live()]})
        route = router.post(f"{BASE}/dhcpv4/delReservation/{TARGET}").respond(
            200, json={"result": "deleted"}
        )
        router.post(RECONFIGURE).respond(200, json=OK)
        done = await apply(app_client, cid, confirm_name="192.168.1.10")
    assert done.json()["status"] == "applied" and route.call_count == 1


async def test_failed_reconfigure_is_reported_as_not_active(
    app_client: httpx.AsyncClient,
) -> None:
    fid = await setup(app_client)
    cid = await staged(app_client, fid, [], reservation=res())
    with respx.mock() as router:
        router.get(RESERVATIONS).respond(200, json={"rows": []})
        router.post(f"{BASE}/dhcpv4/addReservation").respond(
            200, json={"result": "saved", "uuid": NEW_UUID}
        )
        router.post(RECONFIGURE).respond(200, json={"status": "failed"})
        done = await apply(app_client, cid)
    assert done.json()["status"] == "failed" and "NOT active" in json.dumps(done.json())


async def test_rejected_save_does_not_reconfigure(app_client: httpx.AsyncClient) -> None:
    fid = await setup(app_client)
    cid = await staged(app_client, fid, [], reservation=res())
    with respx.mock(assert_all_called=False) as router:
        router.get(RESERVATIONS).respond(200, json={"rows": []})
        router.post(f"{BASE}/dhcpv4/addReservation").respond(
            200, json={"result": "failed", "validations": {"reservation.ip_address": "bad"}}
        )
        reconf = router.post(RECONFIGURE)
        done = await apply(app_client, cid)
    assert done.json()["status"] == "failed" and reconf.call_count == 0


async def test_mac_is_hidden_from_view_only_roles(app_client: httpx.AsyncClient) -> None:
    fid = await setup(app_client)
    cid = str((await stage(app_client, fid, [], reservation=res())).json()["id"])
    await switch(app_client, Role.read_only, "viewer")
    r = await app_client.get(f"{CHANGES}/{cid}")
    assert r.status_code == 200 and "02:00:00:00:00:02" not in r.text
