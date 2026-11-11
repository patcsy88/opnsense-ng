"""Per-firewall guard for CPU stream sampling: one stream at a time, short-lived cache."""

import threading
import time
import uuid
from collections.abc import Callable

CACHE_SECONDS = 5.0

_lock = threading.Lock()
_cache: dict[uuid.UUID, tuple[float, float | None]] = {}
_in_flight: set[uuid.UUID] = set()


def sample_cpu(firewall_id: uuid.UUID, fetch: Callable[[], float | None]) -> float | None:
    """Return a cached value, or run `fetch` unless another request is already sampling this
    firewall (then return None rather than opening a second stream)."""
    now = time.monotonic()
    with _lock:
        hit = _cache.get(firewall_id)
        if hit and now - hit[0] < CACHE_SECONDS:
            return hit[1]
        if firewall_id in _in_flight:
            return hit[1] if hit else None
        _in_flight.add(firewall_id)
    value: float | None = None
    try:
        value = fetch()
    finally:
        with _lock:
            _in_flight.discard(firewall_id)
            if value is not None:
                _cache[firewall_id] = (time.monotonic(), value)
    return value


def forget(firewall_id: uuid.UUID) -> None:
    with _lock:
        _cache.pop(firewall_id, None)


def clear() -> None:
    with _lock:
        _cache.clear()
        _in_flight.clear()
