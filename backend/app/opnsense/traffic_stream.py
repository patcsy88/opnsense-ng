"""Shared per-firewall traffic sampler behind the SSE endpoint (ADR-0023).

One task per firewall polls the plain snapshot once a second while at least one browser is
subscribed, and fans each sample out. Everything here lives on one event loop; `forget` is the only
entry point that may be called from a worker thread. Limits are per process.
"""

import asyncio
import time
import uuid
from collections.abc import Callable
from dataclasses import dataclass, field

from app.core.logging import get_logger
from app.opnsense.client import OPNsenseClient
from app.opnsense.errors import ConnectionStatus, FirewallError
from app.opnsense.normalise.traffic import TrafficResult, normalise_traffic
from app.opnsense.registry.entries import TRAFFIC_INTERFACES

log = get_logger("opnsense.traffic_stream")

SAMPLE_SECONDS = 1.0
KEEPALIVE_SECONDS = 15.0
MAX_STREAM_SECONDS = 600.0
FETCH_TIMEOUT_SECONDS = 5.0
MAX_FAILURES = 3
MAX_PER_USER = 3
MAX_PER_FIREWALL = 10
MAX_PER_PROCESS = 50


class StreamLimitError(Exception):
    def __init__(self, scope: str) -> None:
        super().__init__(scope)
        self.scope = scope


@dataclass(frozen=True)
class Sample:
    result: TrafficResult


@dataclass(frozen=True)
class Failed:
    error: FirewallError


@dataclass(frozen=True)
class Ended:
    reason: str


Item = Sample | Failed | Ended


@dataclass(eq=False)
class Subscription:
    user_id: uuid.UUID
    firewall_id: uuid.UUID
    queue: asyncio.Queue[Item] = field(default_factory=lambda: asyncio.Queue(maxsize=2))
    attached: bool = False
    released: bool = False

    def push(self, item: Item) -> None:
        """Latest wins: a slow reader loses old items, never memory."""
        while self.queue.full():
            self.queue.get_nowait()
        self.queue.put_nowait(item)


class _Sampler:
    def __init__(
        self,
        hub: TrafficHub,
        firewall_id: uuid.UUID,
        make_client: Callable[[], OPNsenseClient],
    ) -> None:
        self.hub = hub
        self.firewall_id = firewall_id
        self.make_client = make_client
        self.subscribers: set[Subscription] = set()
        self.latest: tuple[float, TrafficResult] | None = None
        self.task: asyncio.Task[None] | None = None

    async def run(self) -> None:
        client = self.make_client()
        failures = 0
        try:
            while True:
                started = time.monotonic()
                try:
                    async with asyncio.timeout(FETCH_TIMEOUT_SECONDS):
                        result = normalise_traffic(await client.execute(TRAFFIC_INTERFACES))
                except (FirewallError, TimeoutError) as exc:
                    failures += 1
                    log.warning("traffic_stream_fetch_failed", firewall_id=str(self.firewall_id))
                    if failures >= MAX_FAILURES:
                        error = (
                            exc
                            if isinstance(exc, FirewallError)
                            else FirewallError(
                                ConnectionStatus.timeout, "Firewall did not answer in time"
                            )
                        )
                        self._finish(Failed(error))
                        return
                else:
                    failures = 0
                    self.latest = (time.monotonic(), result)
                    for sub in list(self.subscribers):
                        sub.push(Sample(result))
                await asyncio.sleep(max(0.0, SAMPLE_SECONDS - (time.monotonic() - started)))
        except Exception:
            log.exception("traffic_stream_sampler_crashed", firewall_id=str(self.firewall_id))
            self._finish(Ended("sampler_error"))
        finally:
            await client.aclose()

    def _finish(self, item: Item) -> None:
        for sub in list(self.subscribers):
            sub.push(item)
        self.hub._drop_sampler(self)


class TrafficHub:
    def __init__(self) -> None:
        self._samplers: dict[uuid.UUID, _Sampler] = {}
        self._by_user: dict[uuid.UUID, int] = {}
        self._by_firewall: dict[uuid.UUID, int] = {}
        self._total = 0
        self._loop: asyncio.AbstractEventLoop | None = None

    def reserve(self, user_id: uuid.UUID, firewall_id: uuid.UUID) -> Subscription:
        """Count a stream against the limits. Raises StreamLimitError. Must be released."""
        if self._total >= MAX_PER_PROCESS:
            raise StreamLimitError("process")
        if self._by_user.get(user_id, 0) >= MAX_PER_USER:
            raise StreamLimitError("user")
        if self._by_firewall.get(firewall_id, 0) >= MAX_PER_FIREWALL:
            raise StreamLimitError("firewall")
        self._total += 1
        self._by_user[user_id] = self._by_user.get(user_id, 0) + 1
        self._by_firewall[firewall_id] = self._by_firewall.get(firewall_id, 0) + 1
        return Subscription(user_id, firewall_id)

    def attach(self, sub: Subscription, make_client: Callable[[], OPNsenseClient]) -> None:
        """Join (or start) the firewall's sampler."""
        if sub.released or sub.attached:
            return
        self._loop = asyncio.get_running_loop()
        sampler = self._samplers.get(sub.firewall_id)
        if sampler is None:
            sampler = _Sampler(self, sub.firewall_id, make_client)
            self._samplers[sub.firewall_id] = sampler
            sampler.task = asyncio.create_task(sampler.run())
        sampler.subscribers.add(sub)
        sub.attached = True
        if sampler.latest and time.monotonic() - sampler.latest[0] < 2 * SAMPLE_SECONDS:
            sub.push(Sample(sampler.latest[1]))

    def release(self, sub: Subscription) -> None:
        if sub.released:
            return
        sub.released = True
        self._total -= 1
        _decrement(self._by_user, sub.user_id)
        _decrement(self._by_firewall, sub.firewall_id)
        sampler = self._samplers.get(sub.firewall_id)
        if sampler is not None:
            sampler.subscribers.discard(sub)
            if not sampler.subscribers:
                self._drop_sampler(sampler)

    def forget(self, firewall_id: uuid.UUID) -> None:
        """The firewall was edited or deleted: end its streams so clients reconnect with the new
        settings. Safe to call from a worker thread."""
        loop = self._loop
        if loop is None:
            return
        try:
            loop.call_soon_threadsafe(self._forget_now, firewall_id)
        except RuntimeError:  # loop already closed
            pass

    def _forget_now(self, firewall_id: uuid.UUID) -> None:
        sampler = self._samplers.get(firewall_id)
        if sampler is None:
            return
        for sub in list(sampler.subscribers):
            sub.push(Ended("firewall_changed"))
        self._drop_sampler(sampler)

    def _drop_sampler(self, sampler: _Sampler) -> None:
        if self._samplers.get(sampler.firewall_id) is sampler:
            del self._samplers[sampler.firewall_id]
        task = sampler.task
        if task is not None and not task.done() and task is not asyncio.current_task():
            task.cancel()

    def clear(self) -> None:
        for sampler in list(self._samplers.values()):
            if sampler.task is not None and not sampler.task.done():
                try:
                    sampler.task.cancel()
                except RuntimeError:
                    pass
        self._samplers.clear()
        self._by_user.clear()
        self._by_firewall.clear()
        self._total = 0
        self._loop = None


def _decrement(counts: dict[uuid.UUID, int], key: uuid.UUID) -> None:
    left = counts.get(key, 0) - 1
    if left > 0:
        counts[key] = left
    else:
        counts.pop(key, None)


hub = TrafficHub()
