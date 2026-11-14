"""Multi-firewall overview (ADR-0015)."""

import asyncio
import time
import uuid

import httpx
import pytest
import respx
from sqlalchemy import select

from app.api import overview
from app.db.models import AuditLog, Role
from tests.conftest import csrf_headers
from tests.test_api import FW_BODY, login_as
from tests.test_security import db_rows

pytestmark = pytest.mark.usefixtures("db")

URL = "/api/v1/firewalls/overview"
BASES = {"fw-a": "https://a.example.test", "fw-b": "https://b.example.test"}


async def add_fw(client: httpx.AsyncClient, name: str) -> str:
    body = {**FW_BODY, "name": name, "base_url": BASES.get(name, f"https://{name}.example.test")}
    r = await client.post("/api/v1/firewalls", json=body, headers=csrf_headers(client))
    assert r.status_code == 201, r.text
    return str(r.json()["id"])


def up(router: respx.MockRouter, base: str, hostname: str) -> None:
    root = f"{base}/api/diagnostics/system"
    router.get(f"{root}/system_information").respond(
        200, json={"name": hostname, "versions": ["OPNsense 26.7"], "secret_extra": "raw"}
    )
    router.get(f"{root}/system_time").respond(200, json={"uptime": "3 days"})
    router.get(f"{root}/system_resources").respond(
        200, json={"memory": {"total": "1000", "used": 250}}
    )
    router.get(f"{root}/system_disk").respond(
        200, json={"devices": [{"mountpoint": "/", "total_bytes": 2000, "used_bytes": 500}]}
    )


async def admin_with_two(client: httpx.AsyncClient) -> tuple[str, str]:
    await login_as(client, Role.admin)
    return await add_fw(client, "fw-a"), await add_fw(client, "fw-b")


async def test_mixed_up_and_down_with_admin_detail(app_client: httpx.AsyncClient) -> None:
    a, b = await admin_with_two(app_client)
    with respx.mock(assert_all_called=False) as router:
        up(router, BASES["fw-a"], "alpha")
        router.route(host="b.example.test").mock(side_effect=httpx.ConnectError("refused"))
        r = await app_client.get(URL)
    assert r.status_code == 200
    rows = {e["name"]: e for e in r.json()["firewalls"]}
    assert rows["fw-a"]["reachable"] is True and rows["fw-a"]["hostname"] == "alpha"
    assert (
        rows["fw-a"]["version"] == "OPNsense 26.7" and rows["fw-a"]["memory_used_percent"] == 25.0
    )
    assert rows["fw-a"]["disk_used_percent"] == 25.0
    assert rows["fw-b"]["reachable"] is False and rows["fw-b"]["status"] == "unreachable"
    assert rows["fw-b"]["id"] == b and rows["fw-a"]["id"] == a
    assert "secret_extra" not in r.text and "api_key" not in r.text and "base_url" not in r.text


async def test_non_admin_sees_only_reachable_or_unreachable(app_client: httpx.AsyncClient) -> None:
    await admin_with_two(app_client)
    await app_client.post("/api/v1/auth/logout", headers=csrf_headers(app_client))
    await login_as(app_client, Role.read_only)
    with respx.mock(assert_all_called=False) as router:
        up(router, BASES["fw-a"], "alpha")
        router.route(host="b.example.test").mock(side_effect=httpx.ConnectTimeout("slow"))
        r = await app_client.get(URL)
    rows = {e["name"]: e for e in r.json()["firewalls"]}
    assert rows["fw-a"]["status"] == "reachable"
    assert (
        rows["fw-b"]["status"] == "unreachable"
        and rows["fw-b"]["message"] == "Firewall is unreachable"
    )


async def test_requires_authentication(app_client: httpx.AsyncClient) -> None:
    assert (await app_client.get(URL)).status_code == 401


async def test_cache_limits_firewall_requests(app_client: httpx.AsyncClient) -> None:
    await admin_with_two(app_client)
    with respx.mock(assert_all_called=False) as router:
        up(router, BASES["fw-a"], "alpha")
        up(router, BASES["fw-b"], "beta")
        first = await app_client.get(URL)
        calls = router.calls.call_count
        second = await app_client.get(URL)
        assert router.calls.call_count == calls  # served from the cache
    assert first.json()["firewalls"] == second.json()["firewalls"]
    overview._cache.clear()
    with respx.mock(assert_all_called=False) as router:
        up(router, BASES["fw-a"], "alpha")
        up(router, BASES["fw-b"], "beta")
        await app_client.get(URL)
        assert router.calls.call_count > 0  # expired cache queries again


async def test_one_audit_record_per_request_with_counts_only(app_client: httpx.AsyncClient) -> None:
    await admin_with_two(app_client)
    with respx.mock(assert_all_called=False) as router:
        up(router, BASES["fw-a"], "alpha")
        router.route(host="b.example.test").mock(side_effect=httpx.ConnectError("refused"))
        await app_client.get(URL)
    rows = db_rows(app_client, select(AuditLog).where(AuditLog.action.like("firewall.%")))
    mine = [r for r in rows if r.action == "firewall.overview"]
    assert len(mine) == 1 and mine[0].outcome == "success"
    assert mine[0].detail["queried"] == 2 and mine[0].detail["unreachable"] == 1
    assert not [r for r in rows if r.action.startswith("firewall.system.")]  # no per-operation rows


async def test_time_budget_and_concurrency_cap(
    app_client: httpx.AsyncClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    await login_as(app_client, Role.admin)
    for i in range(6):
        await add_fw(app_client, f"slow-{i}")
    monkeypatch.setattr(overview, "BUDGET_SECONDS", 0.3)
    running = 0
    peak = 0

    async def slow(request: httpx.Request) -> httpx.Response:
        nonlocal running, peak
        running += 1
        peak = max(peak, running)
        try:
            await asyncio.sleep(5)
        finally:
            running -= 1
        return httpx.Response(200, json={})

    started = time.monotonic()
    with respx.mock(assert_all_called=False) as router:
        router.route().mock(side_effect=slow)
        r = await app_client.get(URL)
    elapsed = time.monotonic() - started
    assert r.status_code == 200 and len(r.json()["firewalls"]) == 6
    assert all(e["status"] == "timeout" for e in r.json()["firewalls"])
    assert peak <= overview.MAX_CONCURRENT
    assert elapsed < 3  # two rounds of 0.3 s, not six sequential 5 s calls


async def test_cap_marks_truncated(
    app_client: httpx.AsyncClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    await login_as(app_client, Role.admin)
    for i in range(3):
        await add_fw(app_client, f"fw-{i}")
    monkeypatch.setattr(overview, "MAX_FIREWALLS", 2)
    with respx.mock(assert_all_called=False) as router:
        router.route().mock(side_effect=httpx.ConnectError("refused"))
        r = await app_client.get(URL)
    assert r.json()["truncated"] is True and len(r.json()["firewalls"]) == 2


async def test_cpu_comes_from_the_sampler_cache_only(app_client: httpx.AsyncClient) -> None:
    from app.opnsense import cpu_sampler

    a, _ = await admin_with_two(app_client)
    cpu_sampler.sample_cpu(uuid.UUID(a), lambda: 37.0)
    with respx.mock(assert_all_called=False) as router:
        up(router, BASES["fw-a"], "alpha")
        up(router, BASES["fw-b"], "beta")
        stream = router.get("https://a.example.test/api/diagnostics/cpu_usage/stream")
        r = await app_client.get(URL)
        assert not stream.called  # the overview never opens a CPU stream
    rows = {e["name"]: e for e in r.json()["firewalls"]}
    assert rows["fw-a"]["cpu_used_percent"] == 37.0 and rows["fw-b"]["cpu_used_percent"] is None


async def test_no_firewalls(app_client: httpx.AsyncClient) -> None:
    await login_as(app_client, Role.read_only)
    r = await app_client.get(URL)
    assert r.json() == {"firewalls": [], "truncated": False}
