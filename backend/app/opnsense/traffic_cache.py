"""Short per-firewall cache so several open Traffic pages cause one firewall call (ADR-0007)."""

import threading
import time
import uuid
from collections.abc import Callable

from app.opnsense.normalise.traffic import TrafficResult

CACHE_SECONDS = 2.0

_lock = threading.Lock()
_cache: dict[uuid.UUID, tuple[float, TrafficResult]] = {}


def cached_traffic(firewall_id: uuid.UUID, fetch: Callable[[], TrafficResult]) -> TrafficResult:
    now = time.monotonic()
    with _lock:
        hit = _cache.get(firewall_id)
        if hit and now - hit[0] < CACHE_SECONDS:
            return hit[1]
    value = fetch()
    with _lock:
        _cache[firewall_id] = (time.monotonic(), value)
    return value


def forget(firewall_id: uuid.UUID) -> None:
    with _lock:
        _cache.pop(firewall_id, None)


def clear() -> None:
    with _lock:
        _cache.clear()
