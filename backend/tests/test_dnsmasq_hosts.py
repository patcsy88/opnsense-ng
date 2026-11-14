"""Dnsmasq static hosts (ADR-0017): validation, staging, apply and MAC visibility. OPNsense is
mocked."""

import json
from typing import Any

import httpx
import pytest
import respx
from pydantic import ValidationError
from sqlalchemy import select

from app.changes.dnsmasq_schemas import HostProposal
from app.db.models import AuditLog, ChangeRequest, Role
from app.opnsense.normalise.dnsmasq import normalise_hosts
from app.opnsense.registry.entries import get_operation
from tests.conftest import csrf_headers
from tests.test_api import login_as
from tests.test_changes_api import act, switch
from tests.test_changes_rule_create import CHANGES, apply, approve, setup
from tests.test_security import db_rows

pytestmark = pytest.mark.usefixtures("db")

BASE = "https://fw.example.test/api/dnsmasq"
SEARCH = f"{BASE}/settings/searchHost"
RECONFIGURE = f"{BASE}/service/reconfigure"
TARGET = "0b3a6c1e-1d2f-4a5b-8c7d-9e0f1a2b3c4d"
NEW_UUID = "5d6e7f80-1a2b-4c3d-8e4f-5a6b7c8d9e0f"
OK = {"status": "ok"}


def live(**kw: Any) -> dict[str, Any]:
    base = {
        "uuid": TARGET,
        "host": "printer",
        "domain": "lan.test",
        "ip": "10.0.0.20",
        "hwaddr": "AA:BB:CC:DD:EE:01",
        "cnames": "",
        "ignore": "0",
        "descr": "Office printer",
    }
    base.update(kw)
    return base


def host(**kw: Any) -> dict[str, Any]:
    body: dict[str, Any] = {
        "host": "scanner",
        "domain": "lan.test",
        "ips": ["10.0.0.21"],
        "hwaddrs": ["aa:bb:cc:dd:ee:02"],
        "description": "Office scanner",
    }
    body.update(kw)
    return body


async def stage(
    client: httpx.AsyncClient, fid: str, rows: list[Any], path: str = "dnsmasq-hosts", **body: Any
) -> httpx.Response:
    with respx.mock(assert_all_called=False) as router:
        router.get(SEARCH).respond(200, json={"rows": rows})
        return await client.post(
            f"{CHANGES}/{path}", json={"firewall_id": fid, **body}, headers=csrf_headers(client)
        )


async def staged(
    client: httpx.AsyncClient, fid: str, rows: list[Any], path: str = "dnsmasq-hosts", **body: Any
) -> str:
    r = await stage(client, fid, rows, path, **body)
    assert r.status_code == 201, r.text
    cid = str(r.json()["id"])
    await approve(client, cid)
    return cid


# ---- validation -------------------------------------------------------------------------------


@pytest.mark.parametrize(
    "kw",
    [
        {"host": "*"},
        {"host": "*.lan"},
        {"host": "a.b"},
        {"host": "-bad"},
        {"domain": "*.lan.test"},
        {"ips": []},
        {"ips": ["10.0.0.0/24"]},
        {"ips": ["nope"]},
        {"ips": ["10.0.0.1", "10.0.0.1"]},
        {"ips": [f"10.0.0.{i}" for i in range(1, 10)]},
        {"hwaddrs": ["zz:zz"]},
        {"hwaddrs": ["aa:bb:cc:dd:ee:02", "AA:BB:CC:DD:EE:02"]},
        {"cnames": ["*.x"]},
        {"description": ""},
        {"description": "   "},
        {"description": "bad\nline"},
        {"ignore": True, "hwaddrs": []},
        {"client_id": "x"},
        {"local": True},
    ],
)
def test_invalid_hosts_are_refused(kw: dict[str, Any]) -> None:
    with pytest.raises(ValidationError):
        HostProposal.model_validate(host(**kw))


def test_values_are_normalised() -> None:
    p = HostProposal.model_validate(
        host(
            host="Scanner", hwaddrs=["AA-BB-CC-DD-EE-02"], domain="LAN.test.", cnames=["Alias.lan"]
        )
    )
    assert p.host == "scanner" and p.hwaddrs == ["aa:bb:cc:dd:ee:02"]
    assert p.domain == "lan.test" and p.cnames == ["alias.lan"]


def test_normaliser_is_tolerant_and_lowercases_macs() -> None:
    res = normalise_hosts(
        {"rows": [live(ip="10.0.0.1,10.0.0.2", ignore="1"), {"host": "no-uuid"}, "junk"]}
    )
    [h] = res.hosts
    assert h.ips == ["10.0.0.1", "10.0.0.2"] and h.hwaddrs == ["aa:bb:cc:dd:ee:01"] and h.ignore
    assert normalise_hosts(None).hosts == []


def test_registry_entries_are_verified_and_writes_are_not_read_only() -> None:
    for op_id in ("dnsmasq.hosts.add", "dnsmasq.hosts.update", "dnsmasq.hosts.delete"):
        op = get_operation(op_id)
        assert op.read_only is False and op.verified is True
    assert get_operation("dnsmasq.hosts.list").read_only is True
    assert get_operation("dnsmasq.reconfigure").read_only is False
    update = get_operation("dnsmasq.hosts.update")
    assert update.resolve_endpoint({"uuid": TARGET}).endswith(f"/setHost/{TARGET}")
    with pytest.raises(ValueError):
        update.resolve_endpoint({"uuid": "../x"})


# ---- staging ----------------------------------------------------------------------------------


async def test_create_is_validated_and_only_reads(app_client: httpx.AsyncClient) -> None:
    fid = await setup(app_client)
    with respx.mock(assert_all_called=False) as router:
        router.get(SEARCH).respond(200, json={"rows": [live()]})
        writes = router.post(url__startswith=BASE)
        r = await app_client.post(
            f"{CHANGES}/dnsmasq-hosts",
            json={"firewall_id": fid, "host": host()},
            headers=csrf_headers(app_client),
        )
    assert r.status_code == 201, r.text
    body = r.json()
    assert body["status"] == "validated" and body["kind"] == "dnsmasq_host"
    assert body["high_risk"] is False and body["proposed"]["label"] == "Office scanner"
    assert writes.call_count == 0


async def test_duplicate_name_and_mac_are_refused(app_client: httpx.AsyncClient) -> None:
    fid = await setup(app_client)
    same_name = await stage(
        app_client, fid, [live()], host=host(host="printer", description="Another")
    )
    same_mac = await stage(
        app_client, fid, [live()], host=host(hwaddrs=["aa:bb:cc:dd:ee:01"], description="Mac")
    )
    assert same_name.status_code == 400 and "name and domain" in same_name.text
    assert same_mac.status_code == 400 and "MAC" in same_mac.text


async def test_duplicate_open_request_is_refused(app_client: httpx.AsyncClient) -> None:
    fid = await setup(app_client)
    assert (await stage(app_client, fid, [], host=host())).status_code == 201
    again = await stage(app_client, fid, [], host=host())
    assert again.status_code == 400 and "open request" in again.text


@pytest.mark.parametrize(
    ("kw", "reason"),
    [
        ({"ignore": True}, "ignore"),
        ({"host": "localhost"}, "firewall itself"),
        ({"host": "fw"}, "firewall itself"),
    ],
)
async def test_risky_hosts_are_high_risk(
    app_client: httpx.AsyncClient, kw: dict[str, Any], reason: str
) -> None:
    fid = await setup(app_client)
    r = await stage(app_client, fid, [], host=host(**kw))
    assert r.status_code == 201, r.text
    assert r.json()["high_risk"] is True and reason in " ".join(r.json()["proposed"]["risk"])


async def test_update_and_delete_stage_with_a_base_snapshot(
    app_client: httpx.AsyncClient,
) -> None:
    fid = await setup(app_client)
    upd = await stage(
        app_client,
        fid,
        [live()],
        f"dnsmasq-hosts/{TARGET}/update",
        host=host(host="printer", ips=["10.0.0.22"], hwaddrs=["aa:bb:cc:dd:ee:01"]),
    )
    assert upd.status_code == 201, upd.text
    assert upd.json()["base_snapshot"]["ips"] == ["10.0.0.20"]
    assert upd.json()["high_risk"] is False
    await act(app_client, upd.json()["id"], "cancel")
    dele = await stage(app_client, fid, [live()], f"dnsmasq-hosts/{TARGET}/delete")
    assert dele.status_code == 201 and dele.json()["high_risk"] is True


async def test_unknown_or_bad_target_is_refused(app_client: httpx.AsyncClient) -> None:
    fid = await setup(app_client)
    gone = await stage(app_client, fid, [], f"dnsmasq-hosts/{TARGET}/delete")
    bad = await stage(app_client, fid, [], "dnsmasq-hosts/not-a-uuid/delete")
    assert gone.status_code == 400 and bad.status_code == 422


async def test_unreadable_firewall_refuses_staging(app_client: httpx.AsyncClient) -> None:
    fid = await setup(app_client)
    with respx.mock() as router:
        router.get(SEARCH).mock(side_effect=httpx.ConnectError("down"))
        r = await app_client.post(
            f"{CHANGES}/dnsmasq-hosts",
            json={"firewall_id": fid, "host": host()},
            headers=csrf_headers(app_client),
        )
    assert r.status_code == 400


@pytest.mark.parametrize("role", [Role.security_admin, Role.read_only])
async def test_view_only_roles_cannot_stage(app_client: httpx.AsyncClient, role: Role) -> None:
    fid = await setup(app_client)
    await switch(app_client, role, "viewer")
    r = await stage(app_client, fid, [], host=host())
    assert r.status_code == 403


# ---- MAC visibility ---------------------------------------------------------------------------


async def test_macs_are_hidden_from_view_only_roles(app_client: httpx.AsyncClient) -> None:
    fid = await setup(app_client)
    cid = str((await stage(app_client, fid, [], host=host())).json()["id"])
    own = await app_client.get(f"{CHANGES}/{cid}")
    assert own.json()["proposed"]["hwaddrs"] == ["aa:bb:cc:dd:ee:02"]
    for role in (Role.security_admin, Role.read_only):
        await switch(app_client, role, f"v-{role.value}")
        detail = await app_client.get(f"{CHANGES}/{cid}")
        listing = await app_client.get(CHANGES)
        assert "hwaddrs" not in detail.json()["proposed"]
        assert all(
            "hwaddrs" not in (c["proposed"] or {}) and "hwaddrs" not in (c["base_snapshot"] or {})
            for c in listing.json()
        )
        assert "aa:bb:cc:dd:ee:02" not in detail.text + listing.text


async def test_network_admin_sees_macs_and_the_host_list(app_client: httpx.AsyncClient) -> None:
    fid = await setup(app_client)
    await switch(app_client, Role.network_admin, "netadmin")
    with respx.mock(assert_all_called=False) as router:
        router.get(SEARCH).respond(200, json={"rows": [live()]})
        r = await app_client.get(f"/api/v1/firewalls/{fid}/dnsmasq/hosts")
    assert r.status_code == 200
    body = r.json()
    assert (
        body["hosts"][0]["hwaddrs"] == ["aa:bb:cc:dd:ee:01"] and body["registry_verified"] is True
    )


@pytest.mark.parametrize("role", [Role.security_admin, Role.read_only])
async def test_host_list_is_closed_to_view_only_roles(
    app_client: httpx.AsyncClient, role: Role
) -> None:
    fid = await setup(app_client)
    await switch(app_client, role, "viewer")
    with respx.mock(assert_all_called=False) as router:
        call = router.route().respond(200, json={})
        r = await app_client.get(f"/api/v1/firewalls/{fid}/dnsmasq/hosts")
        assert not call.called
    assert r.status_code == 403


async def test_host_list_needs_login_and_a_known_firewall(app_client: httpx.AsyncClient) -> None:
    anon = await app_client.get(
        "/api/v1/firewalls/5d6e7f80-1a2b-4c3d-8e4f-5a6b7c8d9e0f/dnsmasq/hosts"
    )
    assert anon.status_code == 401
    await login_as(app_client, Role.admin)
    unknown = await app_client.get(
        "/api/v1/firewalls/5d6e7f80-1a2b-4c3d-8e4f-5a6b7c8d9e0f/dnsmasq/hosts"
    )
    assert unknown.status_code == 404


# ---- apply ------------------------------------------------------------------------------------


async def test_create_saves_reconfigures_and_reads_back(app_client: httpx.AsyncClient) -> None:
    fid = await setup(app_client)
    cid = await staged(app_client, fid, [live()], host=host())
    created = live(uuid=NEW_UUID, host="scanner", ip="10.0.0.21", hwaddr="aa:bb:cc:dd:ee:02")
    with respx.mock() as router:
        router.get(SEARCH).mock(
            side_effect=[
                httpx.Response(200, json={"rows": [live()]}),
                httpx.Response(200, json={"rows": [live(), created]}),
            ]
        )
        add = router.post(f"{BASE}/settings/addHost").respond(
            200, json={"result": "saved", "uuid": NEW_UUID}
        )
        act_ = router.post(RECONFIGURE).respond(200, json=OK)
        done = await apply(app_client, cid)
        order = [c.request.url.path for c in router.calls]
    assert done.status_code == 200 and done.json()["status"] == "applied", done.text
    assert order.index("/api/dnsmasq/settings/addHost") < order.index(
        "/api/dnsmasq/service/reconfigure"
    )
    sent = json.loads(add.calls.last.request.content)["host"]
    assert sent["ip"] == "10.0.0.21" and sent["hwaddr"] == "aa:bb:cc:dd:ee:02"
    assert sent["host"] == "scanner" and sent["ignore"] == "0" and sent["descr"] == "Office scanner"
    assert set(sent) == {"host", "domain", "ip", "hwaddr", "cnames", "ignore", "descr"}
    assert act_.call_count == 1
    actions = {a.action for a in db_rows(app_client, select(AuditLog))}
    assert {"firewall.dnsmasq.hosts.add", "firewall.dnsmasq.reconfigure"} <= actions
    [cr] = db_rows(app_client, select(ChangeRequest))
    assert cr.result_snapshot is not None and cr.result_snapshot["uuid"] == NEW_UUID


async def test_high_risk_create_needs_the_typed_description(
    app_client: httpx.AsyncClient,
) -> None:
    fid = await setup(app_client)
    cid = await staged(app_client, fid, [], host=host(ignore=True))
    with respx.mock(assert_all_called=False) as router:
        add = router.post(f"{BASE}/settings/addHost")
        missing = await apply(app_client, cid)
        wrong = await apply(app_client, cid, confirm_name="nope")
    assert missing.status_code == 400 and wrong.status_code == 400 and add.call_count == 0
    with respx.mock() as router:
        router.get(SEARCH).respond(200, json={"rows": []})
        router.post(f"{BASE}/settings/addHost").respond(
            200, json={"result": "saved", "uuid": NEW_UUID}
        )
        router.post(RECONFIGURE).respond(200, json=OK)
        done = await apply(app_client, cid, confirm_name="Office scanner")
    assert done.json()["status"] == "applied"


async def test_create_is_stale_when_name_or_mac_appears(app_client: httpx.AsyncClient) -> None:
    fid = await setup(app_client)
    cid = await staged(app_client, fid, [], host=host())
    with respx.mock(assert_all_called=False) as router:
        router.get(SEARCH).respond(200, json={"rows": [live(host="scanner")]})
        add = router.post(f"{BASE}/settings/addHost")
        r = await apply(app_client, cid)
    assert r.json()["status"] == "stale" and add.call_count == 0


async def test_update_sends_to_the_target_and_checks_the_fingerprint(
    app_client: httpx.AsyncClient,
) -> None:
    fid = await setup(app_client)
    path = f"dnsmasq-hosts/{TARGET}/update"
    body = host(host="printer", ips=["10.0.0.22"], hwaddrs=["aa:bb:cc:dd:ee:01"])
    cid = await staged(app_client, fid, [live()], path, host=body)
    with respx.mock() as router:
        router.get(SEARCH).respond(200, json={"rows": [live()]})
        route = router.post(f"{BASE}/settings/setHost/{TARGET}").respond(
            200, json={"result": "saved"}
        )
        router.post(RECONFIGURE).respond(200, json=OK)
        done = await apply(app_client, cid)
    assert done.json()["status"] == "applied" and route.call_count == 1
    assert json.loads(route.calls.last.request.content)["host"]["ip"] == "10.0.0.22"


async def test_update_is_stale_when_the_host_changed_or_vanished(
    app_client: httpx.AsyncClient,
) -> None:
    fid = await setup(app_client)
    path = f"dnsmasq-hosts/{TARGET}/update"
    body = host(host="printer", ips=["10.0.0.22"], hwaddrs=["aa:bb:cc:dd:ee:01"])
    cid = await staged(app_client, fid, [live()], path, host=body)
    with respx.mock(assert_all_called=False) as router:
        router.get(SEARCH).respond(200, json={"rows": [live(ip="10.0.0.99")]})
        write = router.post(url__startswith=f"{BASE}/settings")
        changed = await apply(app_client, cid)
    assert changed.json()["status"] == "stale" and write.call_count == 0
    fid2 = await setup(app_client) if False else fid
    cid2 = await staged(
        app_client,
        fid2,
        [live()],
        path,
        host=host(
            host="printer", ips=["10.0.0.23"], hwaddrs=["aa:bb:cc:dd:ee:01"], description="Second"
        ),
    )
    with respx.mock(assert_all_called=False) as router:
        router.get(SEARCH).respond(200, json={"rows": []})
        write = router.post(url__startswith=f"{BASE}/settings")
        gone = await apply(app_client, cid2)
    assert gone.json()["status"] == "stale" and write.call_count == 0


async def test_delete_removes_the_host_after_typed_confirmation(
    app_client: httpx.AsyncClient,
) -> None:
    fid = await setup(app_client)
    cid = await staged(app_client, fid, [live()], f"dnsmasq-hosts/{TARGET}/delete")
    with respx.mock(assert_all_called=False) as router:
        refused = await apply(app_client, cid)
    assert refused.status_code == 400
    with respx.mock() as router:
        router.get(SEARCH).respond(200, json={"rows": [live()]})
        route = router.post(f"{BASE}/settings/delHost/{TARGET}").respond(
            200, json={"result": "deleted"}
        )
        router.post(RECONFIGURE).respond(200, json=OK)
        done = await apply(app_client, cid, confirm_name="Office printer")
    assert done.json()["status"] == "applied" and route.call_count == 1


async def test_reconfigure_failure_says_saved_but_not_active(
    app_client: httpx.AsyncClient,
) -> None:
    fid = await setup(app_client)
    cid = await staged(app_client, fid, [], host=host())
    with respx.mock() as router:
        router.get(SEARCH).respond(200, json={"rows": []})
        router.post(f"{BASE}/settings/addHost").respond(
            200, json={"result": "saved", "uuid": NEW_UUID}
        )
        router.post(RECONFIGURE).respond(500, json={})
        done = await apply(app_client, cid)
    assert done.json()["status"] == "failed"
    assert "saved on the firewall but NOT active" in done.json()["failure_message"]


async def test_reconfigure_without_ok_is_not_active(app_client: httpx.AsyncClient) -> None:
    fid = await setup(app_client)
    cid = await staged(app_client, fid, [], host=host())
    with respx.mock() as router:
        router.get(SEARCH).respond(200, json={"rows": []})
        router.post(f"{BASE}/settings/addHost").respond(
            200, json={"result": "saved", "uuid": NEW_UUID}
        )
        router.post(RECONFIGURE).respond(200, json={"status": "failed"})
        done = await apply(app_client, cid)
    assert done.json()["status"] == "failed" and "NOT active" in done.json()["failure_message"]


async def test_rejected_save_reports_the_validation_and_skips_reconfigure(
    app_client: httpx.AsyncClient,
) -> None:
    fid = await setup(app_client)
    cid = await staged(app_client, fid, [], host=host())
    with respx.mock(assert_all_called=False) as router:
        router.get(SEARCH).respond(200, json={"rows": []})
        router.post(f"{BASE}/settings/addHost").respond(
            200, json={"result": "failed", "validations": {"host.ip": "Invalid"}}
        )
        reconf = router.post(RECONFIGURE).respond(200, json=OK)
        done = await apply(app_client, cid)
    assert done.json()["status"] == "failed" and reconf.call_count == 0


async def test_apply_refused_when_writes_are_off_or_role_is_not_admin(
    app_client: httpx.AsyncClient,
) -> None:
    fid = await setup(app_client)
    cid = await staged(app_client, fid, [], host=host())
    await app_client.patch(
        f"/api/v1/firewalls/{fid}", json={"allow_writes": False}, headers=csrf_headers(app_client)
    )
    with respx.mock(assert_all_called=False) as router:
        add = router.post(f"{BASE}/settings/addHost")
        off = await apply(app_client, cid)
        assert add.call_count == 0
    assert off.status_code in (400, 403)
    await switch(app_client, Role.network_admin, "netadmin")
    assert (await apply(app_client, cid)).status_code == 403


async def test_network_admin_cannot_approve_their_own_high_risk_request(
    app_client: httpx.AsyncClient,
) -> None:
    fid = await setup(app_client)
    await switch(app_client, Role.network_admin, "netadmin")
    r = await stage(app_client, fid, [], host=host(ignore=True))
    cid = str(r.json()["id"])
    await act(app_client, cid, "submit")
    assert (await act(app_client, cid, "approve")).status_code == 403


def test_own_address_is_high_risk_when_the_firewall_url_is_an_ip() -> None:
    from types import SimpleNamespace

    from app.api.changes import firewall_identity
    from app.changes.dnsmasq_schemas import host_risk

    addresses, hostname = firewall_identity(SimpleNamespace(base_url="https://192.0.2.1:8443"))  # type: ignore[arg-type]
    assert addresses == {"192.0.2.1"} and hostname is None
    reasons = host_risk(host="x", ips=["192.0.2.1"], ignore=False, firewall_addresses=addresses)
    assert "own address" in reasons[0]
    named, short = firewall_identity(SimpleNamespace(base_url="https://OPNsense.internal"))  # type: ignore[arg-type]
    assert named == frozenset() and short == "opnsense"
