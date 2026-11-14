"""Multi-firewall overview (ADR-0015): a read-only health roll-up.

Reuses the existing system operations. Bounded fan-out, a per-firewall time budget, a short
server-side cache, and one audit record per request instead of one per operation.
"""

import asyncio
import time
import uuid
from typing import Any

import anyio.to_thread
from fastapi import APIRouter, Depends, Request
from pydantic import BaseModel
from sqlalchemy import select
from sqlalchemy.orm import Session

from app import audit
from app.api.firewalls import open_client
from app.auth.deps import ALL_ROLES, CurrentUser, get_db, require_roles
from app.core.config import Settings, get_settings
from app.core.crypto import CredentialDecryptionError
from app.core.logging import get_logger
from app.db.models import Firewall, Role
from app.opnsense import cpu_sampler
from app.opnsense.errors import ConnectionStatus, FirewallError, public_status
from app.opnsense.normalise import normalise_system_status
from app.opnsense.registry.entries import (
    SYSTEM_DISK,
    SYSTEM_RESOURCES,
    SYSTEM_STATUS,
    SYSTEM_TIME,
)

router = APIRouter(prefix="/api/v1/firewalls", tags=["firewalls"])
log = get_logger("api.overview")

MAX_FIREWALLS = 50
MAX_CONCURRENT = 4
BUDGET_SECONDS = 10.0
CACHE_SECONDS = 15.0

_cache: dict[uuid.UUID, tuple[float, Entry]] = {}
_locks: dict[uuid.UUID, asyncio.Lock] = {}
_semaphore: asyncio.Semaphore | None = None


class Entry(BaseModel):
    """Per-firewall result as cached. ``status`` and ``message`` are the detailed (admin) form."""

    id: uuid.UUID
    name: str
    reachable: bool
    status: str
    message: str
    hostname: str | None = None
    version: str | None = None
    uptime: str | None = None
    cpu_used_percent: float | None = None
    memory_used_percent: float | None = None
    disk_used_percent: float | None = None
    checked_at: float


class OverviewEntry(Entry):
    pass


class OverviewOut(BaseModel):
    firewalls: list[OverviewEntry]
    truncated: bool


def clear() -> None:
    """Forget cached results and locks (used by tests and when a firewall is removed)."""
    global _semaphore
    _cache.clear()
    _locks.clear()
    _semaphore = None


def _prune(live: set[uuid.UUID]) -> None:
    """Drop cache entries and locks of firewalls that no longer exist."""
    for stale in [k for k in _cache if k not in live]:
        _cache.pop(stale, None)
    for stale in [k for k in _locks if k not in live]:
        _locks.pop(stale, None)


def _gate() -> asyncio.Semaphore:
    global _semaphore
    if _semaphore is None:
        _semaphore = asyncio.Semaphore(MAX_CONCURRENT)
    return _semaphore


async def _best_effort(coro: Any) -> Any:
    try:
        return await coro
    except FirewallError:
        return None


async def _probe(fw_id: uuid.UUID, name: str, client: Any) -> Entry:
    try:
        async with asyncio.timeout(BUDGET_SECONDS):
            info = await client.execute(SYSTEM_STATUS)
            time_raw, resources, disk = await asyncio.gather(
                _best_effort(client.execute(SYSTEM_TIME)),
                _best_effort(client.execute(SYSTEM_RESOURCES)),
                _best_effort(client.execute(SYSTEM_DISK)),
            )
    except FirewallError as exc:
        return Entry(
            id=fw_id,
            name=name,
            reachable=False,
            status=exc.status.value,
            message=exc.message,
            checked_at=time.time(),
        )
    except TimeoutError:
        return Entry(
            id=fw_id,
            name=name,
            reachable=False,
            status=ConnectionStatus.timeout.value,
            message="No answer within the time limit",
            checked_at=time.time(),
        )
    except Exception:
        log.exception("overview_probe_crashed", firewall_id=str(fw_id))
        return Entry(
            id=fw_id,
            name=name,
            reachable=False,
            status=ConnectionStatus.server_error.value,
            message="Unexpected error",
            checked_at=time.time(),
        )
    finally:
        await client.aclose()
    status = normalise_system_status(info, time_raw, resources, cpu_sampler.peek(fw_id), disk)
    return Entry(
        id=fw_id,
        name=name,
        reachable=True,
        status=ConnectionStatus.ok.value,
        message="Connected",
        hostname=status.hostname,
        version=status.versions[0] if status.versions else None,
        uptime=status.uptime,
        cpu_used_percent=status.cpu_used_percent,
        memory_used_percent=status.memory_used_percent,
        disk_used_percent=status.disk_used_percent,
        checked_at=time.time(),
    )


def _fresh(fw_id: uuid.UUID) -> Entry | None:
    hit = _cache.get(fw_id)
    if hit and time.monotonic() - hit[0] < CACHE_SECONDS:
        return hit[1]
    return None


async def _entry(fw: Firewall, settings: Settings) -> tuple[Entry, bool]:
    """Returns the entry and whether it came from the cache."""
    cached = _fresh(fw.id)
    if cached is not None:
        return cached, True
    lock = _locks.setdefault(fw.id, asyncio.Lock())
    async with lock:
        cached = _fresh(fw.id)  # another request may have just filled it
        if cached is not None:
            return cached, True
        async with _gate():
            try:
                client = await anyio.to_thread.run_sync(lambda: open_client(fw, settings))
            except CredentialDecryptionError:
                log.error("credential_decrypt_failed", firewall_id=str(fw.id))
                entry = Entry(
                    id=fw.id,
                    name=fw.name,
                    reachable=False,
                    status=ConnectionStatus.server_error.value,
                    message="Stored credentials could not be read",
                    checked_at=time.time(),
                )
            else:
                entry = await _probe(fw.id, fw.name, client)
        _cache[fw.id] = (time.monotonic(), entry)
        return entry, False


def _load(db: Session) -> tuple[list[Firewall], bool]:
    rows = list(db.execute(select(Firewall).order_by(Firewall.name).limit(MAX_FIREWALLS + 1)))
    firewalls = [r[0] for r in rows]
    return firewalls[:MAX_FIREWALLS], len(firewalls) > MAX_FIREWALLS


@router.get("/overview", response_model=OverviewOut)
async def overview(
    request: Request,
    user: CurrentUser = Depends(require_roles(*ALL_ROLES)),
    db: Session = Depends(get_db),
    settings: Settings = Depends(get_settings),
) -> OverviewOut:
    firewalls, truncated = await anyio.to_thread.run_sync(lambda: _load(db))
    _prune({fw.id for fw in firewalls})
    results = await asyncio.gather(*(_entry(fw, settings) for fw in firewalls))
    entries = [e for e, _ in results]
    unreachable = [e for e in entries if not e.reachable]
    detail: dict[str, str | int | bool] = {
        "queried": len(entries),
        "reachable": len(entries) - len(unreachable),
        "unreachable": len(unreachable),
        "from_cache": sum(1 for _, cached in results if cached),
        "truncated": truncated,
    }
    if unreachable:
        detail["unreachable_ids"] = ",".join(str(e.id) for e in unreachable)[:500]
    await anyio.to_thread.run_sync(
        lambda: audit.record(
            db,
            action="firewall.overview",
            outcome=audit.OUTCOME_SUCCESS,
            user_id=user.id,
            username=user.username,
            detail=detail,
            request=request,
        )
    )
    admin = user.role is Role.admin
    shown: list[OverviewEntry] = []
    for e in entries:
        data = e.model_dump()
        if not admin and not e.reachable:
            data["status"] = public_status(ConnectionStatus(e.status))
            data["message"] = "Firewall is unreachable"
        elif not admin:
            data["status"] = public_status(ConnectionStatus.ok)
        shown.append(OverviewEntry(**data))
    return OverviewOut(firewalls=shown, truncated=truncated)
