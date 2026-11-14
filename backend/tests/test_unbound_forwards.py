"""Unbound domain forwards (ADR-0018 step 3): validation, staging, apply. OPNsense is mocked."""

import json
from typing import Any

import httpx
import pytest
import respx
from pydantic import ValidationError
from sqlalchemy import select

from app.changes.unbound_schemas import UnboundForwardProposal, inside_forward
from app.db.models import AuditLog, ChangeRequest, Role
from app.opnsense.normalise.unbound import normalise_unbound_forwards
from app.opnsense.registry.entries import get_operation
from tests.conftest import csrf_headers
from tests.test_changes_api import act, switch
from tests.test_changes_rule_create import CHANGES, apply, approve, setup
from tests.test_security import db_rows

pytestmark = pytest.mark.usefixtures("db")

BASE = "https://fw.example.test/api/unbound"
FWD = f"{BASE}/settings/searchForward"
HOSTS = f"{BASE}/settings/searchHostOverride"
RECONFIGURE = f"{BASE}/service/reconfigure"
TARGET = "0b3a6c1e-1d2f-4a5b-8c7d-9e0f1a2b3c4d"
NEW_UUID = "5d6e7f80-1a2b-4c3d-8e4f-5a6b7c8d9e0f"
OK = {"status": "ok"}


def live(**kw: Any) -> dict[str, Any]:
    base = {
        "uuid": TARGET,
        "enabled": "1",
        "type": "forward",
        "domain": "corp.example",
        "server": "10.0.0.53",
        "port": "",
        "description": "Corporate DNS",
    }
    base.update(kw)
    return base


def fwd(**kw: Any) -> dict[str, Any]:
    body: dict[str, Any] = {
        "domain": "lab.example",
        "server": "10.0.0.54",
        "port": 5353,
        "description": "Lab DNS",
    }
    body.update(kw)
    return body


async def stage(
    client: httpx.AsyncClient,
    fid: str,
    rows: list[Any],
    path: str = "unbound-forwards",
    **body: Any,
) -> httpx.Response:
    with respx.mock(assert_all_called=False) as router:
        router.get(FWD).respond(200, json={"rows": rows})
        return await client.post(
            f"{CHANGES}/{path}", json={"firewall_id": fid, **body}, headers=csrf_headers(client)
        )


async def staged(
    client: httpx.AsyncClient,
    fid: str,
    rows: list[Any],
    path: str = "unbound-forwards",
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
        {"domain": ""},
        {"domain": "."},
        {"domain": "corp"},
        {"domain": "com"},
        {"domain": "co.uk"},
        {"domain": "*.example.com"},
        {"domain": "bad_name.test"},
        {"server": "dns.example"},
        {"server": "10.0.0.0/24"},
        {"port": 0},
        {"port": 70000},
        {"description": ""},
        {"description": "bad\nline"},
        {"tcp": True},
    ],
)
def test_invalid_forwards_are_refused(kw: dict[str, Any]) -> None:
    with pytest.raises(ValidationError):
        UnboundForwardProposal.model_validate(fwd(**kw))


def test_values_are_normalised_and_always_high_risk() -> None:
    p = UnboundForwardProposal.model_validate(fwd(domain="Lab.Example.", server="FD00:0:0::53"))
    assert (p.domain, p.server) == ("lab.example", "fd00::53")
    assert "lab.example" in p.risk_reasons()[0]


def test_normaliser_keeps_only_forwards() -> None:
    res = normalise_unbound_forwards(
        {
            "rows": [
                live(),
                live(uuid="1" * 8 + "-1111-4111-8111-" + "1" * 12, type="dot", domain=""),
                live(uuid="2" * 8 + "-2222-4222-8222-" + "2" * 12, type=None, enabled="0"),
                {"type": "forward", "domain": "no-uuid.example"},
                "junk",
            ]
        }
    )
    assert [f.domain for f in res.forwards] == ["corp.example", "corp.example"]
    assert res.forwards[1].enabled is False
    assert normalise_unbound_forwards(None).forwards == []


def test_inside_forward() -> None:
    assert inside_forward("a.corp.example", ["corp.example"]) == "corp.example"
    assert inside_forward("corp.example", ["Corp.Example."]) == "corp.example"
    assert inside_forward("notcorp.example", ["corp.example"]) is None
    assert inside_forward("corp.example", ["", "other.example"]) is None


def test_registry_entries() -> None:
    assert get_operation("unbound.forwards.list").read_only is True
    for op_id in ("add", "update", "delete", "enable", "disable"):
        assert get_operation(f"unbound.forwards.{op_id}").read_only is False
    on = get_operation("unbound.forwards.enable")
    assert on.resolve_endpoint({"uuid": TARGET}).endswith(f"/toggleForward/{TARGET}/1")
    with pytest.raises(ValueError):
        on.resolve_endpoint({"uuid": "../x"})


async def test_every_forward_change_is_high_risk_and_only_reads(
    app_client: httpx.AsyncClient,
) -> None:
    fid = await setup(app_client)
    with respx.mock(assert_all_called=False) as router:
        router.get(FWD).respond(200, json={"rows": [live()]})
        writes = router.post(url__startswith=BASE)
        r = await app_client.post(
            f"{CHANGES}/unbound-forwards",
            json={"firewall_id": fid, "forward": fwd()},
            headers=csrf_headers(app_client),
        )
    assert r.status_code == 201, r.text
    body = r.json()
    assert body["kind"] == "unbound_forward" and body["status"] == "validated"
    assert body["high_risk"] is True and writes.call_count == 0
    await act(app_client, body["id"], "cancel")
    for path, extra in (
        (f"unbound-forwards/{TARGET}/update", {"forward": fwd(domain="corp.example")}),
        (f"unbound-forwards/{TARGET}/toggle", {"enabled": False}),
        (f"unbound-forwards/{TARGET}/delete", {}),
    ):
        r = await stage(app_client, fid, [live()], path, **extra)
        assert r.status_code == 201 and r.json()["high_risk"] is True, path
        await act(app_client, r.json()["id"], "cancel")


async def test_duplicate_domain_and_open_request_are_refused(
    app_client: httpx.AsyncClient,
) -> None:
    fid = await setup(app_client)
    dup = await stage(app_client, fid, [live()], forward=fwd(domain="Corp.Example"))
    assert dup.status_code == 400 and "already exists" in dup.text
    assert (await stage(app_client, fid, [], forward=fwd())).status_code == 201
    again = await stage(app_client, fid, [], forward=fwd(domain="other.example"))
    assert again.status_code == 400 and "open request" in again.text


async def test_already_in_that_state_unknown_and_bad_target(
    app_client: httpx.AsyncClient,
) -> None:
    fid = await setup(app_client)
    same = await stage(app_client, fid, [live()], f"unbound-forwards/{TARGET}/toggle", enabled=True)
    assert same.status_code == 400 and "already enabled" in same.text
    gone = await stage(app_client, fid, [], f"unbound-forwards/{TARGET}/delete")
    bad = await stage(app_client, fid, [], "unbound-forwards/not-a-uuid/delete")
    assert gone.status_code == 400 and bad.status_code == 422
    with respx.mock() as router:
        router.get(FWD).mock(side_effect=httpx.ConnectError("down"))
        r = await app_client.post(
            f"{CHANGES}/unbound-forwards",
            json={"firewall_id": fid, "forward": fwd()},
            headers=csrf_headers(app_client),
        )
    assert r.status_code == 400


async def test_host_inside_a_forwarded_domain_is_high_risk(
    app_client: httpx.AsyncClient,
) -> None:
    fid = await setup(app_client)
    host = {
        "hostname": "app",
        "domain": "sub.corp.example",
        "rr": "A",
        "server": "10.0.0.30",
        "description": "App",
    }
    with respx.mock(assert_all_called=False) as router:
        router.get(HOSTS).respond(200, json={"rows": []})
        router.get(FWD).respond(200, json={"rows": [live()]})
        r = await app_client.post(
            f"{CHANGES}/unbound-hosts",
            json={"firewall_id": fid, "host": host},
            headers=csrf_headers(app_client),
        )
        assert r.status_code == 201, r.text
        assert r.json()["high_risk"] is True
        assert "forwarded" in r.json()["proposed"]["risk"][0]
        await act(app_client, r.json()["id"], "cancel")
        router.get(FWD).respond(200, json={"rows": [live(enabled="0")]})
        off = await app_client.post(
            f"{CHANGES}/unbound-hosts",
            json={"firewall_id": fid, "host": host},
            headers=csrf_headers(app_client),
        )
    assert off.status_code == 201 and off.json()["high_risk"] is False


@pytest.mark.parametrize("role", [Role.security_admin, Role.read_only])
async def test_view_only_roles_cannot_stage_or_list(
    app_client: httpx.AsyncClient, role: Role
) -> None:
    fid = await setup(app_client)
    await switch(app_client, role, "viewer")
    assert (await stage(app_client, fid, [], forward=fwd())).status_code == 403
    with respx.mock(assert_all_called=False) as router:
        call = router.route().respond(200, json={})
        r = await app_client.get(f"/api/v1/firewalls/{fid}/unbound/forwards")
        assert not call.called
    assert r.status_code == 403


async def test_network_admin_lists_and_cannot_approve_own_request(
    app_client: httpx.AsyncClient,
) -> None:
    fid = await setup(app_client)
    await switch(app_client, Role.network_admin, "netadmin")
    with respx.mock(assert_all_called=False) as router:
        router.get(FWD).respond(200, json={"rows": [live(), live(type="dot")]})
        r = await app_client.get(f"/api/v1/firewalls/{fid}/unbound/forwards")
    assert r.status_code == 200
    [f] = r.json()["forwards"]
    assert f["server"] == "10.0.0.53" and r.json()["registry_verified"] is False
    unknown = "5d6e7f80-1a2b-4c3d-8e4f-5a6b7c8d9e0f"
    assert (
        await app_client.get(f"/api/v1/firewalls/{unknown}/unbound/forwards")
    ).status_code == 404
    cid = str((await stage(app_client, fid, [], forward=fwd())).json()["id"])
    await act(app_client, cid, "submit")
    assert (await act(app_client, cid, "approve")).status_code == 403


async def test_create_saves_then_restarts_unbound_and_reads_back(
    app_client: httpx.AsyncClient,
) -> None:
    fid = await setup(app_client)
    cid = await staged(app_client, fid, [live()], forward=fwd())
    created = live(uuid=NEW_UUID, domain="lab.example", server="10.0.0.54", port="5353",
                   description="Lab DNS")  # fmt: skip
    with respx.mock() as router:
        router.get(FWD).mock(
            side_effect=[
                httpx.Response(200, json={"rows": [live()]}),
                httpx.Response(200, json={"rows": [live(), created]}),
            ]
        )
        add = router.post(f"{BASE}/settings/addForward").respond(
            200, json={"result": "saved", "uuid": NEW_UUID}
        )
        reconf = router.post(RECONFIGURE).respond(200, json=OK)
        done = await apply(app_client, cid, confirm_name="Lab DNS")
        order = [c.request.url.path for c in router.calls]
    assert done.json()["status"] == "applied", done.text
    assert order.index("/api/unbound/settings/addForward") < order.index(
        "/api/unbound/service/reconfigure"
    )
    assert json.loads(add.calls.last.request.content)["dot"] == {
        "enabled": "1",
        "type": "forward",
        "domain": "lab.example",
        "server": "10.0.0.54",
        "port": "5353",
        "description": "Lab DNS",
    }
    assert reconf.call_count == 1
    actions = {a.action for a in db_rows(app_client, select(AuditLog))}
    assert {"firewall.unbound.forwards.add", "firewall.unbound.reconfigure"} <= actions
    [cr] = db_rows(app_client, select(ChangeRequest))
    assert cr.result_snapshot is not None and cr.result_snapshot["uuid"] == NEW_UUID


async def test_apply_needs_the_typed_description(app_client: httpx.AsyncClient) -> None:
    fid = await setup(app_client)
    cid = await staged(app_client, fid, [], forward=fwd())
    with respx.mock(assert_all_called=False) as router:
        add = router.post(f"{BASE}/settings/addForward")
        missing = await apply(app_client, cid)
        wrong = await apply(app_client, cid, confirm_name="nope")
        assert add.call_count == 0
    assert missing.status_code == 400 and wrong.status_code == 400


async def test_create_is_stale_when_the_domain_appears(app_client: httpx.AsyncClient) -> None:
    fid = await setup(app_client)
    cid = await staged(app_client, fid, [], forward=fwd())
    with respx.mock(assert_all_called=False) as router:
        router.get(FWD).respond(200, json={"rows": [live(domain="lab.example")]})
        add = router.post(f"{BASE}/settings/addForward")
        r = await apply(app_client, cid, confirm_name="Lab DNS")
    assert r.json()["status"] == "stale" and add.call_count == 0


async def test_update_targets_the_uuid_and_checks_the_fingerprint(
    app_client: httpx.AsyncClient,
) -> None:
    fid = await setup(app_client)
    path = f"unbound-forwards/{TARGET}/update"
    body = fwd(domain="corp.example", server="10.0.0.99", port=None, description="Corporate DNS")
    cid = await staged(app_client, fid, [live()], path, forward=body)
    with respx.mock(assert_all_called=False) as router:
        router.get(FWD).respond(200, json={"rows": [live(server="10.0.0.1")]})
        write = router.post(url__startswith=f"{BASE}/settings")
        stale = await apply(app_client, cid, confirm_name="Corporate DNS")
    assert stale.json()["status"] == "stale" and write.call_count == 0

    cid = await staged(app_client, fid, [live()], path, forward=body)
    with respx.mock() as router:
        router.get(FWD).respond(200, json={"rows": [live()]})
        route = router.post(f"{BASE}/settings/setForward/{TARGET}").respond(
            200, json={"result": "saved"}
        )
        router.post(RECONFIGURE).respond(200, json=OK)
        done = await apply(app_client, cid, confirm_name="Corporate DNS")
    assert done.json()["status"] == "applied" and route.call_count == 1
    assert json.loads(route.calls.last.request.content)["dot"]["server"] == "10.0.0.99"


async def test_toggle_uses_the_explicit_state_endpoint(app_client: httpx.AsyncClient) -> None:
    fid = await setup(app_client)
    cid = await staged(
        app_client, fid, [live()], f"unbound-forwards/{TARGET}/toggle", enabled=False
    )
    with respx.mock() as router:
        router.get(FWD).respond(200, json={"rows": [live()]})
        route = router.post(f"{BASE}/settings/toggleForward/{TARGET}/0").respond(
            200, json={"result": "Disabled"}
        )
        router.post(RECONFIGURE).respond(200, json=OK)
        done = await apply(app_client, cid, confirm_name="Corporate DNS")
    assert done.json()["status"] == "applied" and route.call_count == 1


async def test_delete_applies_with_the_typed_description(app_client: httpx.AsyncClient) -> None:
    fid = await setup(app_client)
    cid = await staged(app_client, fid, [live()], f"unbound-forwards/{TARGET}/delete")
    with respx.mock() as router:
        router.get(FWD).respond(200, json={"rows": [live()]})
        route = router.post(f"{BASE}/settings/delForward/{TARGET}").respond(
            200, json={"result": "deleted"}
        )
        router.post(RECONFIGURE).respond(200, json=OK)
        done = await apply(app_client, cid, confirm_name="Corporate DNS")
    assert done.json()["status"] == "applied" and route.call_count == 1


async def test_reconfigure_failure_says_saved_but_not_active(
    app_client: httpx.AsyncClient,
) -> None:
    fid = await setup(app_client)
    cid = await staged(app_client, fid, [], forward=fwd())
    with respx.mock() as router:
        router.get(FWD).respond(200, json={"rows": []})
        router.post(f"{BASE}/settings/addForward").respond(
            200, json={"result": "saved", "uuid": NEW_UUID}
        )
        router.post(RECONFIGURE).respond(500, json={})
        done = await apply(app_client, cid, confirm_name="Lab DNS")
    assert done.json()["status"] == "failed"
    assert "saved on the firewall but NOT active" in done.json()["failure_message"]


async def test_rejected_save_skips_reconfigure(app_client: httpx.AsyncClient) -> None:
    fid = await setup(app_client)
    cid = await staged(app_client, fid, [], forward=fwd())
    with respx.mock(assert_all_called=False) as router:
        router.get(FWD).respond(200, json={"rows": []})
        router.post(f"{BASE}/settings/addForward").respond(
            200, json={"result": "failed", "validations": {"dot.server": "Invalid"}}
        )
        reconf = router.post(RECONFIGURE).respond(200, json=OK)
        done = await apply(app_client, cid, confirm_name="Lab DNS")
    assert done.json()["status"] == "failed" and reconf.call_count == 0
