"""Near-real-time traffic stream (ADR-0023). OPNsense is mocked.

httpx's ASGITransport buffers whole responses, so the endpoint tests drive the ASGI app directly."""

import asyncio
import json
import uuid
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from typing import Any

import httpx
import pytest
import respx
from sqlalchemy import delete, select

from app.api import traffic_stream as api
from app.db.models import AuditLog, Role
from app.db.models import Session as UserSession
from app.opnsense import traffic_stream as ts
from app.opnsense.errors import ConnectionStatus, FirewallError
from app.opnsense.normalise.traffic import TrafficResult
from tests.test_api import create_fw, login_as
from tests.test_changes_api import switch

URL = "https://fw.example.test/api/diagnostics/traffic/interface"


def raw(n: int) -> dict[str, Any]:
    return {
        "time": 1762950000.0 + n,
        "interfaces": {
            "wan": {
                "bytes received": str(1000 * n),
                "bytes transmitted": str(500 * n),
                "packets received": "1",
                "packets transmitted": "1",
                "name": "WAN",
            }
        },
    }


@pytest.fixture(autouse=True)
def fast(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(ts, "SAMPLE_SECONDS", 0.02)


class FakeClient:
    def __init__(self, results: list[Any] | None = None) -> None:
        self.results = results
        self.calls = 0
        self.closed = False

    async def execute(self, operation_id: str) -> Any:
        self.calls += 1
        if self.results is None:
            return raw(self.calls)
        item = self.results[min(self.calls - 1, len(self.results) - 1)]
        if isinstance(item, Exception):
            raise item
        return item

    async def aclose(self) -> None:
        self.closed = True


def fake(client: FakeClient) -> Any:
    return lambda: client


async def next_sample(sub: ts.Subscription) -> Any:
    async with asyncio.timeout(2):
        return await sub.queue.get()


async def test_one_upstream_poll_serves_every_subscriber_and_stops_with_the_last() -> None:
    hub = ts.TrafficHub()
    fid, client = uuid.uuid4(), FakeClient()
    a = hub.reserve(uuid.uuid4(), fid)
    b = hub.reserve(uuid.uuid4(), fid)
    hub.attach(a, fake(client))
    hub.attach(b, fake(client))
    first_a, first_b = await next_sample(a), await next_sample(b)
    assert isinstance(first_a, ts.Sample) and isinstance(first_b, ts.Sample)
    calls_with_two = client.calls
    hub.release(a)
    await asyncio.sleep(0.1)
    assert client.calls > calls_with_two  # still polling for b
    hub.release(b)
    await asyncio.sleep(0.1)
    after = client.calls
    await asyncio.sleep(0.1)
    assert client.calls == after and client.closed
    assert hub._total == 0 and not hub._samplers


async def test_limits_per_user_firewall_and_process(monkeypatch: pytest.MonkeyPatch) -> None:
    hub = ts.TrafficHub()
    user, fid = uuid.uuid4(), uuid.uuid4()
    held = [hub.reserve(user, fid) for _ in range(ts.MAX_PER_USER)]
    with pytest.raises(ts.StreamLimitError) as e:
        hub.reserve(user, fid)
    assert e.value.scope == "user"
    hub.release(held[0])
    hub.reserve(user, fid)  # a freed slot is reusable

    monkeypatch.setattr(ts, "MAX_PER_USER", 100)
    for _ in range(ts.MAX_PER_FIREWALL - 3):
        hub.reserve(uuid.uuid4(), fid)
    with pytest.raises(ts.StreamLimitError) as e:
        hub.reserve(uuid.uuid4(), fid)
    assert e.value.scope == "firewall"

    monkeypatch.setattr(ts, "MAX_PER_PROCESS", hub._total)
    with pytest.raises(ts.StreamLimitError) as e:
        hub.reserve(uuid.uuid4(), uuid.uuid4())
    assert e.value.scope == "process"


async def test_release_is_idempotent() -> None:
    hub = ts.TrafficHub()
    sub = hub.reserve(uuid.uuid4(), uuid.uuid4())
    hub.release(sub)
    hub.release(sub)
    assert hub._total == 0


async def test_three_failures_in_a_row_end_the_stream() -> None:
    hub = ts.TrafficHub()
    boom = FirewallError(ConnectionStatus.unreachable, "down")
    client = FakeClient([boom])
    sub = hub.reserve(uuid.uuid4(), uuid.uuid4())
    hub.attach(sub, fake(client))
    item = await next_sample(sub)
    assert isinstance(item, ts.Failed) and item.error.status is ConnectionStatus.unreachable
    assert client.calls == ts.MAX_FAILURES and client.closed


async def test_one_failure_between_good_samples_does_not_end_it() -> None:
    hub = ts.TrafficHub()
    boom = FirewallError(ConnectionStatus.timeout, "slow")
    client = FakeClient([raw(1), boom, boom, raw(2), boom, boom, raw(3)])
    sub = hub.reserve(uuid.uuid4(), uuid.uuid4())
    hub.attach(sub, fake(client))
    seen = [await next_sample(sub) for _ in range(3)]
    assert all(isinstance(i, ts.Sample) for i in seen)
    hub.release(sub)


async def test_a_new_subscriber_gets_the_latest_sample_at_once() -> None:
    hub = ts.TrafficHub()
    fid, client = uuid.uuid4(), FakeClient()
    a = hub.reserve(uuid.uuid4(), fid)
    hub.attach(a, fake(client))
    await next_sample(a)
    b = hub.reserve(uuid.uuid4(), fid)
    hub.attach(b, fake(client))
    assert not b.queue.empty()
    hub.release(a)
    hub.release(b)


async def test_forget_ends_streams_and_the_slow_reader_keeps_only_the_latest() -> None:
    hub = ts.TrafficHub()
    fid = uuid.uuid4()
    sub = hub.reserve(uuid.uuid4(), fid)
    hub.attach(sub, fake(FakeClient()))
    await asyncio.sleep(0.2)  # nobody reads: the bounded queue must not grow
    assert sub.queue.qsize() <= 2
    hub.forget(fid)
    await asyncio.sleep(0.05)
    items = [sub.queue.get_nowait() for _ in range(sub.queue.qsize())]
    assert isinstance(items[-1], ts.Ended) and items[-1].reason == "firewall_changed"
    assert fid not in hub._samplers
    hub.release(sub)


class Stream:
    """Runs the ASGI app on a streaming GET and exposes the body chunks as they are sent."""

    def __init__(self, app: Any, path: str, cookies: httpx.Cookies) -> None:
        cookie = "; ".join(f"{k}={v}" for k, v in cookies.items())
        self.scope = {
            "type": "http",
            "asgi": {"version": "3.0", "spec_version": "2.3"},
            "http_version": "1.1",
            "method": "GET",
            "scheme": "https",
            "path": path,
            "raw_path": path.encode(),
            "query_string": b"",
            "headers": [(b"host", b"test"), (b"cookie", cookie.encode())],
            "client": ("127.0.0.1", 5000),
            "server": ("test", 443),
        }
        self.app = app
        self.sent: asyncio.Queue[dict[str, Any]] = asyncio.Queue()
        self.incoming: asyncio.Queue[dict[str, Any]] = asyncio.Queue()
        self.status = 0
        self.headers: dict[str, str] = {}
        self.task: asyncio.Task[None] | None = None

    async def _receive(self) -> dict[str, Any]:
        return await self.incoming.get()

    async def _send(self, message: dict[str, Any]) -> None:
        await self.sent.put(message)

    def start(self) -> None:
        self.task = asyncio.create_task(self.app(self.scope, self._receive, self._send))

    async def start_message(self) -> None:
        async with asyncio.timeout(5):
            message = await self.sent.get()
        assert message["type"] == "http.response.start"
        self.status = message["status"]
        self.headers = {k.decode(): v.decode() for k, v in message["headers"]}

    async def chunk(self) -> str | None:
        async with asyncio.timeout(5):
            message = await self.sent.get()
        if message["type"] == "http.response.body" and not message.get("more_body", False):
            return message.get("body", b"").decode() or None
        return message["body"].decode()

    async def events(self, count: int) -> list[str]:
        out: list[str] = []
        while len(out) < count:
            text = await self.chunk()
            if text is None:
                break
            if text.startswith(("retry:", ":")):
                continue
            out.append(text)
        return out

    async def disconnect(self) -> None:
        await self.incoming.put({"type": "http.disconnect"})
        assert self.task is not None
        async with asyncio.timeout(5):
            await self.task


def data_of(chunk: str) -> dict[str, Any]:
    line = next(x for x in chunk.splitlines() if x.startswith("data:"))
    return json.loads(line[5:])


@asynccontextmanager
async def open_stream(client: httpx.AsyncClient, fid: str) -> AsyncIterator[Stream]:
    stream = Stream(client.app, f"/api/v1/firewalls/{fid}/traffic/stream", client.cookies)  # type: ignore[attr-defined]
    stream.start()
    try:
        await stream.start_message()
        yield stream
    finally:
        if stream.task is not None and not stream.task.done():
            await stream.disconnect()


def actions(client: httpx.AsyncClient) -> list[AuditLog]:
    with client.app.state.sessionmaker() as db:  # type: ignore[attr-defined]
        return list(db.scalars(select(AuditLog).order_by(AuditLog.timestamp)))


async def test_stream_sends_samples_and_audits_open_and_close(
    app_client: httpx.AsyncClient,
) -> None:
    await login_as(app_client, Role.admin)
    fid = await create_fw(app_client)
    with respx.mock() as router:
        route = router.get(URL)
        route.side_effect = [httpx.Response(200, json=raw(n)) for n in range(1, 100)]
        async with open_stream(app_client, fid) as stream:
            assert stream.status == 200
            assert stream.headers["content-type"].startswith("text/event-stream")
            assert stream.headers["cache-control"] == "no-store"
            one, two = await stream.events(2)
        body = data_of(one)
        assert body["firewall_id"] == fid and body["registry_verified"] is True
        assert body["interfaces"][0]["in_bytes"] == 1000
        assert data_of(two)["interfaces"][0]["in_bytes"] == 2000
    rows = [a for a in actions(app_client) if a.action.startswith("firewall.traffic.stream")]
    assert [a.action for a in rows] == [api.OPEN_ACTION, api.CLOSE_ACTION]
    assert rows[1].detail["reason"] == "client_closed" and rows[1].detail["samples"] >= 2
    assert "interfaces" not in json.dumps(rows[1].detail)
    assert ts.hub._total == 0 and not ts.hub._samplers


async def test_roles_and_unknown_firewall(app_client: httpx.AsyncClient) -> None:
    await login_as(app_client, Role.admin)
    fid = await create_fw(app_client)
    with respx.mock() as router:
        router.get(URL).respond(200, json=raw(1))
        for role, name in ((Role.network_admin, "net"), (Role.security_admin, "sec")):
            await switch(app_client, role, name)
            async with open_stream(app_client, fid) as stream:
                assert stream.status == 200
        await switch(app_client, Role.read_only, "ro")
        async with open_stream(app_client, fid) as stream:
            assert stream.status == 403
        async with open_stream(app_client, str(uuid.uuid4())) as stream:
            assert stream.status == 403  # still read_only: the role check comes first
        await switch(app_client, Role.admin, "adm")
        async with open_stream(app_client, str(uuid.uuid4())) as stream:
            assert stream.status == 404


async def test_unauthenticated_is_refused(app_client: httpx.AsyncClient) -> None:
    async with open_stream(app_client, str(uuid.uuid4())) as stream:
        assert stream.status == 401


async def test_per_user_limit_returns_429_and_a_closed_stream_frees_the_slot(
    app_client: httpx.AsyncClient,
) -> None:
    await login_as(app_client, Role.admin)
    fid = await create_fw(app_client)
    with respx.mock() as router:
        router.get(URL).respond(200, json=raw(1))
        async with (
            open_stream(app_client, fid) as s1,
            open_stream(app_client, fid) as s2,
            open_stream(app_client, fid) as s3,
        ):
            assert {s1.status, s2.status, s3.status} == {200}
            async with open_stream(app_client, fid) as s4:
                assert s4.status == 429
        async with open_stream(app_client, fid) as again:
            assert again.status == 200
    denied = [a for a in actions(app_client) if a.action == api.DENIED_ACTION]
    assert len(denied) == 1 and denied[0].detail["scope"] == "user"


async def test_firewall_failure_is_collapsed_for_non_admins(app_client: httpx.AsyncClient) -> None:
    await login_as(app_client, Role.admin)
    fid = await create_fw(app_client)
    await switch(app_client, Role.network_admin, "net")
    with respx.mock() as router:
        router.get(URL).respond(403, json={"status": 403})
        async with open_stream(app_client, fid) as stream:
            (chunk,) = await stream.events(1)
    assert chunk.startswith("event: failure")
    assert data_of(chunk) == {"status": "unreachable", "message": "Firewall is unreachable"}
    close = [a for a in actions(app_client) if a.action == api.CLOSE_ACTION][-1]
    assert close.detail["reason"] == "upstream_failed"


async def test_stream_ends_when_the_session_is_revoked(
    app_client: httpx.AsyncClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(api, "RECHECK_SECONDS", 0.05)
    await login_as(app_client, Role.admin)
    fid = await create_fw(app_client)
    with respx.mock() as router:
        router.get(URL).respond(200, json=raw(1))
        async with open_stream(app_client, fid) as stream:
            await stream.events(1)
            with app_client.app.state.sessionmaker() as db:  # type: ignore[attr-defined]
                db.execute(delete(UserSession))
                db.commit()
            chunks = await stream.events(50)
    assert chunks[-1].startswith("event: end")
    assert data_of(chunks[-1]) == {"reason": "session_ended"}
    close = [a for a in actions(app_client) if a.action == api.CLOSE_ACTION][-1]
    assert close.detail["reason"] == "session_ended"


async def test_stream_ends_after_its_maximum_lifetime(
    app_client: httpx.AsyncClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(ts, "MAX_STREAM_SECONDS", 0.3)
    await login_as(app_client, Role.admin)
    fid = await create_fw(app_client)
    with respx.mock() as router:
        router.get(URL).respond(200, json=raw(1))
        async with open_stream(app_client, fid) as stream:
            chunks = await stream.events(100)
    assert data_of(chunks[-1]) == {"reason": "max_duration"}


async def test_editing_the_firewall_ends_its_streams(app_client: httpx.AsyncClient) -> None:
    await login_as(app_client, Role.admin)
    fid = await create_fw(app_client)
    with respx.mock() as router:
        router.get(URL).respond(200, json=raw(1))
        async with open_stream(app_client, fid) as stream:
            await stream.events(1)
            from tests.conftest import csrf_headers

            renamed = await app_client.patch(
                f"/api/v1/firewalls/{fid}",
                json={"name": "renamed"},
                headers=csrf_headers(app_client),
            )
            assert renamed.status_code == 200
            chunks = await stream.events(50)
    assert data_of(chunks[-1]) == {"reason": "firewall_changed"}


def test_a_result_with_no_interfaces_is_still_a_sample() -> None:
    assert ts.Sample(TrafficResult()).result.interfaces == []
