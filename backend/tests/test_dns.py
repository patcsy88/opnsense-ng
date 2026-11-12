"""Unbound DNS overview (ADR-0010). OPNsense is mocked."""

import httpx
import respx
from sqlalchemy import select

from app.db.models import AuditLog, Role
from app.opnsense.normalise import normalise_dns
from tests.test_api import create_fw, login_as
from tests.test_changes_api import switch

STATS_URL = "https://fw.example.test/api/unbound/diagnostics/stats"
TOTALS_URL = "https://fw.example.test/api/unbound/overview/totals/10"
SEARCH_URL = "https://fw.example.test/api/unbound/overview/searchQueries"

STATS = {
    "status": "ok",
    "data": {
        "total": {"num": {"queries": "200", "cachehits": "150", "cachemiss": "50"}},
        "time": {"up": "3600.5"},
    },
}
TOTALS = {
    "total": 180,
    "blocklist_size": 5000,
    "passed": 170,
    "blocked": {"total": 10, "pcnt": 5.56},
    "top": {
        "example.com": {"total": 40, "pcnt": 23.5},
        "b.example": {"total": 90, "pcnt": 52.9},
    },
    "top_blocked": {
        "ads.example": {
            "total": 10,
            "pcnt": 100,
            "blocklist": "oisd",
            "latest_policy_uuid": "11111111-1111-1111-1111-111111111111",
        }
    },
}


def test_mapping_computes_rate_and_sorts_top() -> None:
    r = normalise_dns(STATS, TOTALS)
    assert r.stats_available and r.totals_available
    assert (r.queries, r.cache_hits, r.cache_misses, r.hit_rate, r.uptime_seconds) == (
        200,
        150,
        50,
        75.0,
        3600,
    )
    assert [d.domain for d in r.top_queried] == ["b.example", "example.com"]
    assert (r.top_blocked[0].blocklist, r.blocked, r.blocked_percent) == ("oisd", 10, 5.6)
    assert "11111111" not in r.model_dump_json()


def test_unavailable_parts_are_not_zeros() -> None:
    r = normalise_dns({"status": "failed"}, {"total": 0, "top": {}, "top_blocked": {}})
    assert r.stats_available is False and r.totals_available is False
    assert r.queries is None and r.hit_rate is None and r.top_queried == []
    cases: list[object] = [None, [], "x", {"status": "ok", "data": []}]
    for raw in cases:
        assert normalise_dns(raw, raw).stats_available is False


def test_top_lists_are_capped_and_tolerant() -> None:
    many: dict[str, dict[str, object]] = {f"d{i}.example": {"total": i} for i in range(30)}
    many["bad"] = {"total": "x"}
    many[""] = {"total": 5}
    r = normalise_dns(None, {"total": 1, "top": many, "top_blocked": []})
    assert len(r.top_queried) == 10 and r.top_queried[0].domain == "d29.example"
    assert r.top_blocked == []


async def test_endpoint_roles_audit_and_no_query_search(app_client: httpx.AsyncClient) -> None:
    await login_as(app_client, Role.admin)
    fid = await create_fw(app_client)
    path = f"/api/v1/firewalls/{fid}/dns"
    with respx.mock(assert_all_called=False) as router:
        router.get(STATS_URL).respond(200, json=STATS)
        router.get(TOTALS_URL).respond(200, json=TOTALS)
        search = router.get(SEARCH_URL).respond(200, json={"rows": []})
        r = await app_client.get(path)
        for role, name in ((Role.network_admin, "net"), (Role.security_admin, "sec")):
            await switch(app_client, role, name)
            assert (await app_client.get(path)).status_code == 200
        await switch(app_client, Role.read_only, "ro")
        denied = await app_client.get(path)
        post = await app_client.post(path)
    body = r.json()
    assert r.status_code == 200 and body["hit_rate"] == 75.0 and len(body["top_queried"]) == 2
    assert body["registry_verified"] is False and denied.status_code == 403
    assert post.status_code in (404, 405) and search.call_count == 0
    assert "latest_policy_uuid" not in r.text
    with app_client.app.state.sessionmaker() as db:  # type: ignore[attr-defined]
        actions = [a.action for a in db.scalars(select(AuditLog))]
    assert actions.count("firewall.dns.stats") == 3 and actions.count("firewall.dns.totals") == 3


async def test_failure_is_collapsed_for_non_admins(app_client: httpx.AsyncClient) -> None:
    await login_as(app_client, Role.admin)
    fid = await create_fw(app_client)
    await switch(app_client, Role.network_admin, "net")
    with respx.mock(assert_all_called=False) as router:
        router.get(STATS_URL).respond(403, json={"status": 403})
        router.get(TOTALS_URL).respond(403, json={"status": 403})
        r = await app_client.get(f"/api/v1/firewalls/{fid}/dns")
    assert r.status_code == 502 and r.json()["detail"]["message"] == "Firewall is unreachable"
