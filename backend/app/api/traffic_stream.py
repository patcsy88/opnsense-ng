"""Near-real-time interface traffic over Server-Sent Events (ADR-0023). Read-only."""

import asyncio
import json
import time
import uuid
from collections.abc import AsyncIterator
from datetime import timedelta
from typing import Any

import anyio
from fastapi import APIRouter, Depends, HTTPException, Request, status
from fastapi.responses import StreamingResponse
from sqlalchemy import select
from sqlalchemy.orm import Session, sessionmaker
from starlette.background import BackgroundTask

from app import audit
from app.api.firewalls import (
    LOG_ROLES,
    _get_firewall,
    _log_error,
    decrypt_credentials,
    make_client,
)
from app.api.schemas import TrafficOut
from app.auth.deps import CurrentUser, get_db, require_roles
from app.core.config import Settings, get_settings
from app.core.crypto import CredentialDecryptionError
from app.core.logging import get_logger
from app.db.models import Firewall, User, utcnow
from app.db.models import Session as UserSession
from app.opnsense import traffic_stream as ts
from app.opnsense.registry import get_operation
from app.opnsense.registry.entries import TRAFFIC_INTERFACES

router = APIRouter(prefix="/api/v1/firewalls", tags=["firewalls"])
log = get_logger("api.traffic_stream")

OPEN_ACTION = "firewall.traffic.stream_open"
CLOSE_ACTION = "firewall.traffic.stream_close"
DENIED_ACTION = "firewall.traffic.stream_denied"
RECHECK_SECONDS = 15.0


def _prepare(
    db: Session,
    firewall_id: uuid.UUID,
    user: CurrentUser,
    request: Request,
    settings: Settings,
) -> tuple[Firewall, str, str]:
    fw = _get_firewall(db, firewall_id, OPEN_ACTION, user, request)
    try:
        api_key, api_secret = decrypt_credentials(fw, settings)
    except CredentialDecryptionError:
        log.error("credential_decrypt_failed", firewall_id=str(fw.id))
        audit.record(
            db,
            action=OPEN_ACTION,
            outcome=audit.OUTCOME_FAILURE,
            user_id=user.id,
            username=user.username,
            firewall_id=fw.id,
            detail={"reason": "credential_decrypt_failed"},
            request=request,
        )
        raise HTTPException(status.HTTP_500_INTERNAL_SERVER_ERROR, "Internal error") from None
    db.expunge(fw)
    db.rollback()  # give the connection back: the stream must not hold one
    return fw, api_key, api_secret


def _audit(
    maker: sessionmaker[Session],
    *,
    action: str,
    outcome: str,
    user: CurrentUser,
    firewall_id: uuid.UUID,
    detail: dict[str, Any],
    request: Request | None,
    throttled: bool = False,
) -> None:
    with maker() as db:
        if throttled and request is not None:
            audit.record_throttled(
                db,
                request=request,
                action=action,
                outcome=outcome,
                user_id=user.id,
                username=user.username,
                detail=detail,
            )
            return
        audit.record(
            db,
            action=action,
            outcome=outcome,
            user_id=user.id,
            username=user.username,
            firewall_id=firewall_id,
            detail=detail,
            request=request,
        )


def _session_valid(maker: sessionmaker[Session], user: CurrentUser, settings: Settings) -> bool:
    """The same rules as a fresh request: the session exists, is not expired or idle, and the
    account is still active, allowed, enrolled and not waiting on a password change."""
    with maker() as db:
        row = db.execute(
            select(UserSession, User)
            .join(User, User.id == UserSession.user_id)
            .where(UserSession.id == user.session_id)
        ).first()
        if row is None:
            return False
        session, account = row
        now = utcnow()
        idle_limit = session.last_seen_at + timedelta(minutes=settings.session_idle_timeout_minutes)
        if session.expires_at <= now or idle_limit <= now:
            return False
        if not account.is_active or account.must_change_password:
            return False
        if account.role not in LOG_ROLES:
            return False
        return not (account.role.value in settings.mfa_required_roles and not account.mfa_enabled)


def _event(name: str | None, data: dict[str, Any]) -> bytes:
    head = f"event: {name}\n" if name else ""
    return f"{head}data: {json.dumps(data, separators=(',', ':'))}\n\n".encode()


@router.get("/{firewall_id}/traffic/stream")
async def traffic_stream(
    request: Request,
    firewall_id: uuid.UUID,
    user: CurrentUser = Depends(require_roles(*LOG_ROLES)),
    db: Session = Depends(get_db),
    settings: Settings = Depends(get_settings),
) -> StreamingResponse:
    """Interface counters about once a second, shared by every viewer of the firewall. Not for
    read_only: usage patterns are sensitive. Limits and lifetime are in ADR-0023."""
    maker: sessionmaker[Session] = request.app.state.sessionmaker
    hub = ts.hub
    fw, api_key, api_secret = await anyio.to_thread.run_sync(
        lambda: _prepare(db, firewall_id, user, request, settings)
    )
    try:
        sub = hub.reserve(user.id, firewall_id)
    except ts.StreamLimitError as exc:
        scope = exc.scope
        await anyio.to_thread.run_sync(
            lambda: _audit(
                maker,
                action=DENIED_ACTION,
                outcome=audit.OUTCOME_DENIED,
                user=user,
                firewall_id=firewall_id,
                detail={"reason": "stream_limit", "scope": scope, "firewall_id": str(firewall_id)},
                request=request,
                throttled=True,
            )
        )
        raise HTTPException(status.HTTP_429_TOO_MANY_REQUESTS, "Too many open streams") from None

    try:
        await anyio.to_thread.run_sync(
            lambda: _audit(
                maker,
                action=OPEN_ACTION,
                outcome=audit.OUTCOME_SUCCESS,
                user=user,
                firewall_id=firewall_id,
                detail={},
                request=request,
            )
        )
    except BaseException:
        hub.release(sub)
        raise

    verified = get_operation(TRAFFIC_INTERFACES).verified
    stats: dict[str, Any] = {"samples": 0, "reason": "client_closed"}

    async def events() -> AsyncIterator[bytes]:
        started = time.monotonic()
        last_check = started
        try:
            hub.attach(sub, lambda: make_client(fw, api_key, api_secret, settings))
            yield b"retry: 3000\n\n"
            while True:
                left = ts.MAX_STREAM_SECONDS - (time.monotonic() - started)
                if left <= 0:
                    stats["reason"] = "max_duration"
                    yield _event("end", {"reason": "max_duration"})
                    return
                try:
                    item = await asyncio.wait_for(
                        sub.queue.get(), timeout=min(ts.KEEPALIVE_SECONDS, left)
                    )
                except TimeoutError:
                    item = None
                if time.monotonic() - last_check >= RECHECK_SECONDS:
                    last_check = time.monotonic()
                    if not await anyio.to_thread.run_sync(
                        lambda: _session_valid(maker, user, settings)
                    ):
                        stats["reason"] = "session_ended"
                        yield _event("end", {"reason": "session_ended"})
                        return
                if item is None:
                    yield b": keep-alive\n\n"
                elif isinstance(item, ts.Sample):
                    stats["samples"] += 1
                    out = TrafficOut(
                        firewall_id=firewall_id,
                        time=item.result.time,
                        interfaces=item.result.interfaces,
                        registry_verified=verified,
                    )
                    yield f"data: {out.model_dump_json()}\n\n".encode()
                elif isinstance(item, ts.Failed):
                    stats["reason"] = "upstream_failed"
                    detail = _log_error(item.error, user).detail
                    yield _event("failure", detail if isinstance(detail, dict) else {})
                    return
                else:
                    stats["reason"] = item.reason
                    yield _event("end", {"reason": item.reason})
                    return
        finally:
            await _close(started)

    async def _close(started: float) -> None:
        hub.release(sub)
        with anyio.CancelScope(shield=True):
            try:
                await anyio.to_thread.run_sync(
                    lambda: _audit(
                        maker,
                        action=CLOSE_ACTION,
                        outcome=audit.OUTCOME_SUCCESS,
                        user=user,
                        firewall_id=firewall_id,
                        detail={
                            "reason": stats["reason"],
                            "seconds": int(time.monotonic() - started),
                            "samples": stats["samples"],
                        },
                        request=None,
                    )
                )
            except Exception:
                log.exception("traffic_stream_close_audit_failed", firewall_id=str(firewall_id))

    return StreamingResponse(
        events(),
        media_type="text/event-stream",
        headers={"Cache-Control": "no-store", "X-Accel-Buffering": "no"},
        background=BackgroundTask(hub.release, sub),
    )
