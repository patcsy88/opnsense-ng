"""Unbound host overrides (ADR-0018 step 1): validation, staging, apply. OPNsense is mocked."""

import json
from typing import Any

import httpx
import pytest
import respx
from pydantic import ValidationError
from sqlalchemy import select

from app.changes.unbound_schemas import UnboundHostProposal
from app.db.models import AuditLog, ChangeRequest, Role
from app.opnsense.normalise.unbound import normalise_unbound_hosts
from app.opnsense.registry.entries import get_operation
from tests.conftest import csrf_headers
from tests.test_changes_api import act, switch
from tests.test_changes_rule_create import CHANGES, apply, approve, setup
from tests.test_security import db_rows

pytestmark = pytest.mark.usefixtures("db")

BASE = "https://fw.example.test/api/unbound"
SEARCH = f"{BASE}/settings/searchHostOverride"
RECONFIGURE = f"{BASE}/service/reconfigure"
TARGET = "0b3a6c1e-1d2f-4a5b-8c7d-9e0f1a2b3c4d"
NEW_UUID = "5d6e7f80-1a2b-4c3d-8e4f-5a6b7c8d9e0f"
OK = {"status": "ok"}


def live(**kw: Any) -> dict[str, Any]:
    base = {
        "uuid": TARGET,
        "enabled": "1",
        "hostname": "nas",
        "domain": "home.test",
        "rr": "A",
        "server": "10.0.0.20",
        "ttl": "",
        "description": "NAS",
    }
    base.update(kw)
    return base


def host(**kw: Any) -> dict[str, Any]:
    body: dict[str, Any] = {
        "hostname": "printer",
        "domain": "home.test",
        "rr": "A",
        "server": "10.0.0.30",
        "description": "Printer",
    }
    body.update(kw)
    return body


async def stage(
    client: httpx.AsyncClient, fid: str, rows: list[Any], path: str = "unbound-hosts", **body: Any
) -> httpx.Response:
    with respx.mock(assert_all_called=False) as router:
        router.get(SEARCH).respond(200, json={"rows": rows})
        return await client.post(
            f"{CHANGES}/{path}", json={"firewall_id": fid, **body}, headers=csrf_headers(client)
        )


async def staged(
    client: httpx.AsyncClient, fid: str, rows: list[Any], path: str = "unbound-hosts", **body: Any
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
        {"hostname": "*"},
        {"hostname": "*.x"},
        {"hostname": "a.b"},
        {"hostname": ""},
        {"domain": ""},
        {"domain": "bad_name.test"},
        {"server": "nas.example"},
        {"server": "10.0.0.0/24"},
        {"server": "fd00::1"},
        {"rr": "AAAA"},
        {"rr": "MX"},
        {"rr": "TXT"},
        {"ttl": -1},
        {"description": ""},
        {"description": "bad\nline"},
        {"mx": "mail.test"},
    ],
)
def test_invalid_hosts_are_refused(kw: dict[str, Any]) -> None:
    with pytest.raises(ValidationError):
        UnboundHostProposal.model_validate(host(**kw))


def test_aaaa_needs_an_ipv6_address_and_values_are_normalised() -> None:
    p = UnboundHostProposal.model_validate(
        host(hostname="NAS", domain="Home.Test.", rr="AAAA", server="FD00:0:0::1")
    )
    assert (p.hostname, p.domain, p.server) == ("nas", "home.test", "fd00::1")
    with pytest.raises(ValidationError):
        UnboundHostProposal.model_validate(host(rr="AAAA", server="10.0.0.1"))


def test_normaliser_flags_non_editable_and_skips_aliases() -> None:
    res = normalise_unbound_hosts(
        {
            "rows": [
                live(),
                live(uuid="1" * 8 + "-1111-4111-8111-" + "1" * 12, rr="MX", enabled="0"),
                {"uuid": "x", "isAlias": True, "hostname": "al"},
                {"hostname": "no-uuid"},
                "junk",
            ]
        }
    )
    assert [h.rr for h in res.hosts] == ["A", "MX"]
    assert res.hosts[0].editable is True and res.hosts[1].editable is False
    assert res.hosts[1].enabled is False
    assert normalise_unbound_hosts(None).hosts == []


def test_registry_entries() -> None:
    assert get_operation("unbound.hosts.list").read_only is True
    for op_id in ("add", "update", "delete", "enable", "disable"):
        assert get_operation(f"unbound.hosts.{op_id}").read_only is False
    assert get_operation("unbound.reconfigure").read_only is False
    off = get_operation("unbound.hosts.disable")
    assert off.resolve_endpoint({"uuid": TARGET}).endswith(f"/toggleHostOverride/{TARGET}/0")
    with pytest.raises(ValueError):
        off.resolve_endpoint({"uuid": "../x"})


# ---- staging ----------------------------------------------------------------------------------


async def test_create_only_reads_and_is_normal_risk(app_client: httpx.AsyncClient) -> None:
    fid = await setup(app_client)
    with respx.mock(assert_all_called=False) as router:
        router.get(SEARCH).respond(200, json={"rows": [live()]})
        writes = router.post(url__startswith=BASE)
        r = await app_client.post(
            f"{CHANGES}/unbound-hosts",
            json={"firewall_id": fid, "host": host()},
            headers=csrf_headers(app_client),
        )
    assert r.status_code == 201, r.text
    body = r.json()
    assert body["status"] == "validated" and body["kind"] == "unbound_host"
    assert body["high_risk"] is False and writes.call_count == 0


async def test_firewall_name_and_localhost_are_high_risk(app_client: httpx.AsyncClient) -> None:
    fid = await setup(app_client)
    r = await stage(app_client, fid, [], host=host(hostname="fw"))
    assert r.json()["high_risk"] is True and "firewall itself" in r.json()["proposed"]["risk"][0]
    again = await stage(app_client, fid, [], host=host(hostname="localhost", description="L"))
    assert again.status_code == 201 and again.json()["high_risk"] is True


async def test_duplicate_and_open_request_are_refused(app_client: httpx.AsyncClient) -> None:
    fid = await setup(app_client)
    dup = await stage(app_client, fid, [live()], host=host(hostname="nas"))
    assert dup.status_code == 400 and "already exists" in dup.text
    assert (await stage(app_client, fid, [], host=host())).status_code == 201
    again = await stage(app_client, fid, [], host=host(hostname="other"))
    assert again.status_code == 400 and "open request" in again.text


async def test_same_name_with_other_record_type_is_allowed(app_client: httpx.AsyncClient) -> None:
    fid = await setup(app_client)
    r = await stage(
        app_client, fid, [live()], host=host(hostname="nas", rr="AAAA", server="fd00::20")
    )
    assert r.status_code == 201, r.text


async def test_update_toggle_delete_stage_with_a_snapshot(app_client: httpx.AsyncClient) -> None:
    fid = await setup(app_client)
    upd = await stage(
        app_client,
        fid,
        [live()],
        f"unbound-hosts/{TARGET}/update",
        host=host(hostname="nas", server="10.0.0.99", description="NAS"),
    )
    assert upd.status_code == 201, upd.text
    assert upd.json()["base_snapshot"]["server"] == "10.0.0.20"
    await act(app_client, upd.json()["id"], "cancel")
    off = await stage(app_client, fid, [live()], f"unbound-hosts/{TARGET}/toggle", enabled=False)
    assert off.status_code == 201 and off.json()["high_risk"] is False
    assert off.json()["proposed"]["enabled"] is False
    await act(app_client, off.json()["id"], "cancel")
    already = await stage(app_client, fid, [live()], f"unbound-hosts/{TARGET}/toggle", enabled=True)
    assert already.status_code == 400 and "already enabled" in already.text
    dele = await stage(app_client, fid, [live()], f"unbound-hosts/{TARGET}/delete")
    assert dele.status_code == 201 and dele.json()["high_risk"] is True


async def test_other_record_types_cannot_be_changed(app_client: httpx.AsyncClient) -> None:
    fid = await setup(app_client)
    rows = [live(rr="MX")]
    for path, body in (
        (f"unbound-hosts/{TARGET}/delete", {}),
        (f"unbound-hosts/{TARGET}/toggle", {"enabled": False}),
        (f"unbound-hosts/{TARGET}/update", {"host": host()}),
    ):
        r = await stage(app_client, fid, rows, path, **body)
        assert r.status_code == 400 and "cannot be changed here" in r.text


async def test_unknown_or_bad_target_and_unreadable_firewall(
    app_client: httpx.AsyncClient,
) -> None:
    fid = await setup(app_client)
    gone = await stage(app_client, fid, [], f"unbound-hosts/{TARGET}/delete")
    bad = await stage(app_client, fid, [], "unbound-hosts/not-a-uuid/delete")
    assert gone.status_code == 400 and bad.status_code == 422
    with respx.mock() as router:
        router.get(SEARCH).mock(side_effect=httpx.ConnectError("down"))
        r = await app_client.post(
            f"{CHANGES}/unbound-hosts",
            json={"firewall_id": fid, "host": host()},
            headers=csrf_headers(app_client),
        )
    assert r.status_code == 400


@pytest.mark.parametrize("role", [Role.security_admin, Role.read_only])
async def test_view_only_roles_cannot_stage_or_list(
    app_client: httpx.AsyncClient, role: Role
) -> None:
    fid = await setup(app_client)
    await switch(app_client, role, "viewer")
    assert (await stage(app_client, fid, [], host=host())).status_code == 403
    with respx.mock(assert_all_called=False) as router:
        call = router.route().respond(200, json={})
        r = await app_client.get(f"/api/v1/firewalls/{fid}/unbound/hosts")
        assert not call.called
    assert r.status_code == 403


async def test_network_admin_lists_but_cannot_approve_own_request(
    app_client: httpx.AsyncClient,
) -> None:
    fid = await setup(app_client)
    await switch(app_client, Role.network_admin, "netadmin")
    with respx.mock(assert_all_called=False) as router:
        router.get(SEARCH).respond(200, json={"rows": [live(rr="MX")]})
        r = await app_client.get(f"/api/v1/firewalls/{fid}/unbound/hosts")
    assert r.status_code == 200
    [h] = r.json()["hosts"]
    assert h["server"] == "10.0.0.20" and h["editable"] is False
    assert r.json()["registry_verified"] is True
    unknown = "5d6e7f80-1a2b-4c3d-8e4f-5a6b7c8d9e0f"
    assert (await app_client.get(f"/api/v1/firewalls/{unknown}/unbound/hosts")).status_code == 404
    cid = str((await stage(app_client, fid, [], host=host())).json()["id"])
    await act(app_client, cid, "submit")
    assert (await act(app_client, cid, "approve")).status_code == 403


# ---- apply ------------------------------------------------------------------------------------


async def test_create_saves_then_restarts_unbound_and_reads_back(
    app_client: httpx.AsyncClient,
) -> None:
    fid = await setup(app_client)
    cid = await staged(app_client, fid, [live()], host=host(ttl=300))
    created = live(uuid=NEW_UUID, hostname="printer", server="10.0.0.30", ttl="300",
                   description="Printer")  # fmt: skip
    with respx.mock() as router:
        router.get(SEARCH).mock(
            side_effect=[
                httpx.Response(200, json={"rows": [live()]}),
                httpx.Response(200, json={"rows": [live(), created]}),
            ]
        )
        add = router.post(f"{BASE}/settings/addHostOverride").respond(
            200, json={"result": "saved", "uuid": NEW_UUID}
        )
        reconf = router.post(RECONFIGURE).respond(200, json=OK)
        done = await apply(app_client, cid)
        order = [c.request.url.path for c in router.calls]
    assert done.json()["status"] == "applied", done.text
    assert order.index("/api/unbound/settings/addHostOverride") < order.index(
        "/api/unbound/service/reconfigure"
    )
    sent = json.loads(add.calls.last.request.content)["host"]
    assert sent == {
        "enabled": "1",
        "hostname": "printer",
        "domain": "home.test",
        "rr": "A",
        "server": "10.0.0.30",
        "ttl": "300",
        "description": "Printer",
    }
    assert reconf.call_count == 1
    actions = {a.action for a in db_rows(app_client, select(AuditLog))}
    assert {"firewall.unbound.hosts.add", "firewall.unbound.reconfigure"} <= actions
    [cr] = db_rows(app_client, select(ChangeRequest))
    assert cr.result_snapshot is not None and cr.result_snapshot["uuid"] == NEW_UUID


async def test_create_is_stale_when_the_host_appears(app_client: httpx.AsyncClient) -> None:
    fid = await setup(app_client)
    cid = await staged(app_client, fid, [], host=host())
    with respx.mock(assert_all_called=False) as router:
        router.get(SEARCH).respond(200, json={"rows": [live(hostname="printer")]})
        add = router.post(f"{BASE}/settings/addHostOverride")
        r = await apply(app_client, cid)
    assert r.json()["status"] == "stale" and add.call_count == 0


async def test_update_targets_the_uuid_and_checks_the_fingerprint(
    app_client: httpx.AsyncClient,
) -> None:
    fid = await setup(app_client)
    path = f"unbound-hosts/{TARGET}/update"
    body = host(hostname="nas", server="10.0.0.99", description="NAS")
    cid = await staged(app_client, fid, [live()], path, host=body)
    with respx.mock(assert_all_called=False) as router:
        router.get(SEARCH).respond(200, json={"rows": [live(server="10.0.0.1")]})
        write = router.post(url__startswith=f"{BASE}/settings")
        stale = await apply(app_client, cid)
    assert stale.json()["status"] == "stale" and write.call_count == 0

    cid = await staged(app_client, fid, [live()], path, host=body)
    with respx.mock() as router:
        router.get(SEARCH).respond(200, json={"rows": [live()]})
        route = router.post(f"{BASE}/settings/setHostOverride/{TARGET}").respond(
            200, json={"result": "saved"}
        )
        router.post(RECONFIGURE).respond(200, json=OK)
        done = await apply(app_client, cid)
    assert done.json()["status"] == "applied" and route.call_count == 1
    assert json.loads(route.calls.last.request.content)["host"]["server"] == "10.0.0.99"


async def test_toggle_uses_the_explicit_state_endpoint(app_client: httpx.AsyncClient) -> None:
    fid = await setup(app_client)
    cid = await staged(app_client, fid, [live()], f"unbound-hosts/{TARGET}/toggle", enabled=False)
    with respx.mock() as router:
        router.get(SEARCH).respond(200, json={"rows": [live()]})
        route = router.post(f"{BASE}/settings/toggleHostOverride/{TARGET}/0").respond(
            200, json={"result": "Disabled"}
        )
        router.post(RECONFIGURE).respond(200, json=OK)
        done = await apply(app_client, cid)
    assert done.json()["status"] == "applied" and route.call_count == 1


async def test_delete_needs_the_typed_description(app_client: httpx.AsyncClient) -> None:
    fid = await setup(app_client)
    cid = await staged(app_client, fid, [live()], f"unbound-hosts/{TARGET}/delete")
    with respx.mock(assert_all_called=False) as router:
        route = router.post(f"{BASE}/settings/delHostOverride/{TARGET}")
        missing = await apply(app_client, cid)
        assert route.call_count == 0
    assert missing.status_code == 400
    with respx.mock() as router:
        router.get(SEARCH).respond(200, json={"rows": [live()]})
        route = router.post(f"{BASE}/settings/delHostOverride/{TARGET}").respond(
            200, json={"result": "deleted"}
        )
        router.post(RECONFIGURE).respond(200, json=OK)
        done = await apply(app_client, cid, confirm_name="NAS")
    assert done.json()["status"] == "applied" and route.call_count == 1


async def test_reconfigure_failure_says_saved_but_not_active(
    app_client: httpx.AsyncClient,
) -> None:
    fid = await setup(app_client)
    cid = await staged(app_client, fid, [], host=host())
    with respx.mock() as router:
        router.get(SEARCH).respond(200, json={"rows": []})
        router.post(f"{BASE}/settings/addHostOverride").respond(
            200, json={"result": "saved", "uuid": NEW_UUID}
        )
        router.post(RECONFIGURE).respond(500, json={})
        done = await apply(app_client, cid)
    assert done.json()["status"] == "failed"
    assert "saved on the firewall but NOT active" in done.json()["failure_message"]


async def test_rejected_save_skips_reconfigure(app_client: httpx.AsyncClient) -> None:
    fid = await setup(app_client)
    cid = await staged(app_client, fid, [], host=host())
    with respx.mock(assert_all_called=False) as router:
        router.get(SEARCH).respond(200, json={"rows": []})
        router.post(f"{BASE}/settings/addHostOverride").respond(
            200, json={"result": "failed", "validations": {"host.server": "Invalid"}}
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
        add = router.post(f"{BASE}/settings/addHostOverride")
        off = await apply(app_client, cid)
        assert add.call_count == 0
    assert off.status_code in (400, 403)
