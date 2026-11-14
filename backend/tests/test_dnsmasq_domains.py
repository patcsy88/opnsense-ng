"""Dnsmasq domain overrides (ADR-0017 step 2): validation, staging, apply. OPNsense is mocked."""

import json
from typing import Any

import httpx
import pytest
import respx
from pydantic import ValidationError
from sqlalchemy import select

from app.changes.dnsmasq_schemas import DomainProposal
from app.db.models import AuditLog, ChangeRequest, Role
from app.opnsense.normalise.dnsmasq import normalise_domains
from app.opnsense.registry.entries import get_operation
from tests.conftest import csrf_headers
from tests.test_changes_api import act, switch
from tests.test_changes_rule_create import CHANGES, apply, approve, setup
from tests.test_security import db_rows

pytestmark = pytest.mark.usefixtures("db")

BASE = "https://fw.example.test/api/dnsmasq"
SEARCH = f"{BASE}/settings/searchDomain"
RECONFIGURE = f"{BASE}/service/reconfigure"
TARGET = "0b3a6c1e-1d2f-4a5b-8c7d-9e0f1a2b3c4d"
NEW_UUID = "5d6e7f80-1a2b-4c3d-8e4f-5a6b7c8d9e0f"
OK = {"status": "ok"}


def live(**kw: Any) -> dict[str, Any]:
    base = {
        "uuid": TARGET,
        "domain": "corp.example",
        "ip": "10.0.0.53",
        "port": "",
        "descr": "Corporate DNS",
    }
    base.update(kw)
    return base


def override(**kw: Any) -> dict[str, Any]:
    body: dict[str, Any] = {
        "domain": "lab.example",
        "server": "10.0.0.54",
        "description": "Lab DNS",
    }
    body.update(kw)
    return body


async def stage(
    client: httpx.AsyncClient, fid: str, rows: list[Any], path: str = "dnsmasq-domains", **body: Any
) -> httpx.Response:
    with respx.mock(assert_all_called=False) as router:
        router.get(SEARCH).respond(200, json={"rows": rows})
        return await client.post(
            f"{CHANGES}/{path}", json={"firewall_id": fid, **body}, headers=csrf_headers(client)
        )


async def staged(
    client: httpx.AsyncClient, fid: str, rows: list[Any], path: str = "dnsmasq-domains", **body: Any
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
        {"domain": "*.example.com"},
        {"domain": "*"},
        {"domain": "."},
        {"domain": ""},
        {"domain": "com"},
        {"domain": "internal"},
        {"domain": "co.uk"},
        {"domain": "in-addr.arpa"},
        {"domain": "bad_name.example"},
        {"server": "dns.example"},
        {"server": "10.0.0.0/24"},
        {"server": ""},
        {"port": 0},
        {"port": 70000},
        {"description": ""},
        {"description": "bad\nline"},
        {"srcip": "10.0.0.1"},
    ],
)
def test_invalid_overrides_are_refused(kw: dict[str, Any]) -> None:
    with pytest.raises(ValidationError):
        DomainProposal.model_validate(override(**kw))


def test_values_are_normalised_and_always_risky() -> None:
    p = DomainProposal.model_validate(override(domain="Lab.Example.", port=5353))
    assert p.domain == "lab.example" and p.port == 5353
    assert "lab.example" in p.risk_reasons()[0] and "5353" in p.risk_reasons()[0]


def test_normaliser_is_tolerant() -> None:
    res = normalise_domains({"rows": [live(port=5353), {"domain": "no-uuid"}, "junk"]})
    [d] = res.domains
    assert d.server == "10.0.0.53" and d.port == "5353" and d.description == "Corporate DNS"
    assert normalise_domains(None).domains == []


def test_registry_entries() -> None:
    for op_id in ("dnsmasq.domains.list", "dnsmasq.domains.add", "dnsmasq.domains.update"):
        assert get_operation(op_id).verified is True
    for op_id in ("dnsmasq.domains.add", "dnsmasq.domains.update", "dnsmasq.domains.delete"):
        assert get_operation(op_id).read_only is False
    assert get_operation("dnsmasq.domains.list").read_only is True
    update = get_operation("dnsmasq.domains.update")
    assert update.resolve_endpoint({"uuid": TARGET}).endswith(f"/setDomain/{TARGET}")
    with pytest.raises(ValueError):
        update.resolve_endpoint({"uuid": "../x"})


# ---- staging ----------------------------------------------------------------------------------


async def test_create_is_high_risk_and_only_reads(app_client: httpx.AsyncClient) -> None:
    fid = await setup(app_client)
    with respx.mock(assert_all_called=False) as router:
        router.get(SEARCH).respond(200, json={"rows": [live()]})
        writes = router.post(url__startswith=BASE)
        r = await app_client.post(
            f"{CHANGES}/dnsmasq-domains",
            json={"firewall_id": fid, "override": override()},
            headers=csrf_headers(app_client),
        )
    assert r.status_code == 201, r.text
    body = r.json()
    assert body["status"] == "validated" and body["kind"] == "dnsmasq_domain"
    assert body["high_risk"] is True and "lab.example" in body["proposed"]["risk"][0]
    assert writes.call_count == 0


async def test_duplicate_domain_and_open_request_are_refused(
    app_client: httpx.AsyncClient,
) -> None:
    fid = await setup(app_client)
    dup = await stage(app_client, fid, [live()], override=override(domain="corp.example"))
    assert dup.status_code == 400 and "already exists" in dup.text
    assert (await stage(app_client, fid, [], override=override())).status_code == 201
    again = await stage(app_client, fid, [], override=override(description="Other"))
    assert again.status_code == 400 and "open request" in again.text


async def test_update_and_delete_stage_with_a_base_snapshot(app_client: httpx.AsyncClient) -> None:
    fid = await setup(app_client)
    upd = await stage(
        app_client,
        fid,
        [live()],
        f"dnsmasq-domains/{TARGET}/update",
        override=override(domain="corp.example", server="10.0.0.99"),
    )
    assert upd.status_code == 201, upd.text
    assert upd.json()["base_snapshot"]["server"] == "10.0.0.53" and upd.json()["high_risk"] is True
    await act(app_client, upd.json()["id"], "cancel")
    dele = await stage(app_client, fid, [live()], f"dnsmasq-domains/{TARGET}/delete")
    assert dele.status_code == 201 and dele.json()["high_risk"] is True


async def test_unknown_or_bad_target_is_refused(app_client: httpx.AsyncClient) -> None:
    fid = await setup(app_client)
    gone = await stage(app_client, fid, [], f"dnsmasq-domains/{TARGET}/delete")
    bad = await stage(app_client, fid, [], "dnsmasq-domains/not-a-uuid/delete")
    assert gone.status_code == 400 and bad.status_code == 422


async def test_unreadable_firewall_refuses_staging(app_client: httpx.AsyncClient) -> None:
    fid = await setup(app_client)
    with respx.mock() as router:
        router.get(SEARCH).mock(side_effect=httpx.ConnectError("down"))
        r = await app_client.post(
            f"{CHANGES}/dnsmasq-domains",
            json={"firewall_id": fid, "override": override()},
            headers=csrf_headers(app_client),
        )
    assert r.status_code == 400


@pytest.mark.parametrize("role", [Role.security_admin, Role.read_only])
async def test_view_only_roles_cannot_stage_or_list(
    app_client: httpx.AsyncClient, role: Role
) -> None:
    fid = await setup(app_client)
    await switch(app_client, role, "viewer")
    assert (await stage(app_client, fid, [], override=override())).status_code == 403
    with respx.mock(assert_all_called=False) as router:
        call = router.route().respond(200, json={})
        r = await app_client.get(f"/api/v1/firewalls/{fid}/dnsmasq/domains")
        assert not call.called
    assert r.status_code == 403


async def test_network_admin_can_list_domains(app_client: httpx.AsyncClient) -> None:
    fid = await setup(app_client)
    await switch(app_client, Role.network_admin, "netadmin")
    with respx.mock(assert_all_called=False) as router:
        router.get(SEARCH).respond(200, json={"rows": [live()]})
        r = await app_client.get(f"/api/v1/firewalls/{fid}/dnsmasq/domains")
    assert r.status_code == 200 and r.json()["domains"][0]["server"] == "10.0.0.53"
    anon_id = "5d6e7f80-1a2b-4c3d-8e4f-5a6b7c8d9e0f"
    assert (await app_client.get(f"/api/v1/firewalls/{anon_id}/dnsmasq/domains")).status_code == 404


async def test_network_admin_cannot_approve_their_own_override(
    app_client: httpx.AsyncClient,
) -> None:
    fid = await setup(app_client)
    await switch(app_client, Role.network_admin, "netadmin")
    cid = str((await stage(app_client, fid, [], override=override())).json()["id"])
    await act(app_client, cid, "submit")
    assert (await act(app_client, cid, "approve")).status_code == 403


# ---- apply ------------------------------------------------------------------------------------


async def test_create_needs_the_typed_description_then_saves_and_reconfigures(
    app_client: httpx.AsyncClient,
) -> None:
    fid = await setup(app_client)
    cid = await staged(app_client, fid, [live()], override=override(port=5353))
    with respx.mock(assert_all_called=False) as router:
        add = router.post(f"{BASE}/settings/addDomain")
        missing = await apply(app_client, cid)
        wrong = await apply(app_client, cid, confirm_name="nope")
    assert missing.status_code == 400 and wrong.status_code == 400 and add.call_count == 0

    created = live(
        uuid=NEW_UUID, domain="lab.example", ip="10.0.0.54", port="5353", descr="Lab DNS"
    )
    with respx.mock() as router:
        router.get(SEARCH).mock(
            side_effect=[
                httpx.Response(200, json={"rows": [live()]}),
                httpx.Response(200, json={"rows": [live(), created]}),
            ]
        )
        add = router.post(f"{BASE}/settings/addDomain").respond(
            200, json={"result": "saved", "uuid": NEW_UUID}
        )
        reconf = router.post(RECONFIGURE).respond(200, json=OK)
        done = await apply(app_client, cid, confirm_name="Lab DNS")
        order = [c.request.url.path for c in router.calls]
    assert done.json()["status"] == "applied", done.text
    assert order.index("/api/dnsmasq/settings/addDomain") < order.index(
        "/api/dnsmasq/service/reconfigure"
    )
    sent = json.loads(add.calls.last.request.content)["domainoverride"]
    assert sent == {"domain": "lab.example", "ip": "10.0.0.54", "port": "5353", "descr": "Lab DNS"}
    assert reconf.call_count == 1
    actions = {a.action for a in db_rows(app_client, select(AuditLog))}
    assert {"firewall.dnsmasq.domains.add", "firewall.dnsmasq.reconfigure"} <= actions
    [cr] = db_rows(app_client, select(ChangeRequest))
    assert cr.result_snapshot is not None and cr.result_snapshot["uuid"] == NEW_UUID


async def test_create_is_stale_when_the_domain_appears(app_client: httpx.AsyncClient) -> None:
    fid = await setup(app_client)
    cid = await staged(app_client, fid, [], override=override())
    with respx.mock(assert_all_called=False) as router:
        router.get(SEARCH).respond(200, json={"rows": [live(domain="lab.example")]})
        add = router.post(f"{BASE}/settings/addDomain")
        r = await apply(app_client, cid, confirm_name="Lab DNS")
    assert r.json()["status"] == "stale" and add.call_count == 0


async def test_update_targets_the_uuid_and_checks_the_fingerprint(
    app_client: httpx.AsyncClient,
) -> None:
    fid = await setup(app_client)
    path = f"dnsmasq-domains/{TARGET}/update"
    body = override(domain="corp.example", server="10.0.0.99", description="Corporate DNS")
    cid = await staged(app_client, fid, [live()], path, override=body)
    with respx.mock() as router:
        router.get(SEARCH).respond(200, json={"rows": [live()]})
        route = router.post(f"{BASE}/settings/setDomain/{TARGET}").respond(
            200, json={"result": "saved"}
        )
        router.post(RECONFIGURE).respond(200, json=OK)
        done = await apply(app_client, cid, confirm_name="Corporate DNS")
    assert done.json()["status"] == "applied" and route.call_count == 1
    assert json.loads(route.calls.last.request.content)["domainoverride"]["ip"] == "10.0.0.99"


async def test_update_is_stale_when_changed_or_vanished(app_client: httpx.AsyncClient) -> None:
    fid = await setup(app_client)
    path = f"dnsmasq-domains/{TARGET}/update"
    body = override(domain="corp.example", server="10.0.0.99", description="Corporate DNS")
    cid = await staged(app_client, fid, [live()], path, override=body)
    with respx.mock(assert_all_called=False) as router:
        router.get(SEARCH).respond(200, json={"rows": [live(ip="10.0.0.1")]})
        write = router.post(url__startswith=f"{BASE}/settings")
        changed = await apply(app_client, cid, confirm_name="Corporate DNS")
    assert changed.json()["status"] == "stale" and write.call_count == 0


async def test_delete_removes_the_override(app_client: httpx.AsyncClient) -> None:
    fid = await setup(app_client)
    cid = await staged(app_client, fid, [live()], f"dnsmasq-domains/{TARGET}/delete")
    with respx.mock() as router:
        router.get(SEARCH).respond(200, json={"rows": [live()]})
        route = router.post(f"{BASE}/settings/delDomain/{TARGET}").respond(
            200, json={"result": "deleted"}
        )
        router.post(RECONFIGURE).respond(200, json=OK)
        done = await apply(app_client, cid, confirm_name="Corporate DNS")
    assert done.json()["status"] == "applied" and route.call_count == 1


async def test_reconfigure_failure_says_saved_but_not_active(
    app_client: httpx.AsyncClient,
) -> None:
    fid = await setup(app_client)
    cid = await staged(app_client, fid, [], override=override())
    with respx.mock() as router:
        router.get(SEARCH).respond(200, json={"rows": []})
        router.post(f"{BASE}/settings/addDomain").respond(
            200, json={"result": "saved", "uuid": NEW_UUID}
        )
        router.post(RECONFIGURE).respond(500, json={})
        done = await apply(app_client, cid, confirm_name="Lab DNS")
    assert done.json()["status"] == "failed"
    assert "saved on the firewall but NOT active" in done.json()["failure_message"]


async def test_rejected_save_skips_reconfigure(app_client: httpx.AsyncClient) -> None:
    fid = await setup(app_client)
    cid = await staged(app_client, fid, [], override=override())
    with respx.mock(assert_all_called=False) as router:
        router.get(SEARCH).respond(200, json={"rows": []})
        router.post(f"{BASE}/settings/addDomain").respond(
            200, json={"result": "failed", "validations": {"domain.ip": "Invalid"}}
        )
        reconf = router.post(RECONFIGURE).respond(200, json=OK)
        done = await apply(app_client, cid, confirm_name="Lab DNS")
    assert done.json()["status"] == "failed" and reconf.call_count == 0


async def test_apply_refused_when_writes_are_off_or_role_is_not_admin(
    app_client: httpx.AsyncClient,
) -> None:
    fid = await setup(app_client)
    cid = await staged(app_client, fid, [], override=override())
    await app_client.patch(
        f"/api/v1/firewalls/{fid}", json={"allow_writes": False}, headers=csrf_headers(app_client)
    )
    with respx.mock(assert_all_called=False) as router:
        add = router.post(f"{BASE}/settings/addDomain")
        off = await apply(app_client, cid, confirm_name="Lab DNS")
        assert add.call_count == 0
    assert off.status_code in (400, 403)
    await switch(app_client, Role.network_admin, "netadmin")
    assert (await apply(app_client, cid, confirm_name="Lab DNS")).status_code == 403
