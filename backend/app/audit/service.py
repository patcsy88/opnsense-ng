"""Audit log writer. Independent of OPNsense logs; never receives secrets."""

import re
import uuid
from datetime import timedelta
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session
from starlette.requests import Request

from app.core.clientip import client_ip
from app.db.models import USER_AGENT_MAX_LENGTH, AuditLog, utcnow

OUTCOME_SUCCESS = "success"
OUTCOME_FAILURE = "failure"
OUTCOME_DENIED = "denied"

THROTTLE_WINDOW = timedelta(minutes=1)
_CONTROL = re.compile(r"[\x00-\x1f\x7f]")


def _user_agent(request: Request | None) -> str | None:
    if request is None:
        return None
    raw = request.headers.get("user-agent")
    if not raw:
        return None
    return _CONTROL.sub("?", raw)[:USER_AGENT_MAX_LENGTH]


def add(
    db: Session,
    *,
    action: str,
    outcome: str,
    user_id: uuid.UUID | None = None,
    username: str | None = None,
    firewall_id: uuid.UUID | None = None,
    detail: dict[str, Any] | None = None,
    request: Request | None = None,
) -> None:
    """Stage an audit record in the caller's transaction (no commit). Use this when the audit
    row must commit or roll back together with the change it describes."""
    db.add(
        AuditLog(
            user_id=user_id,
            username=username,
            action=action,
            firewall_id=firewall_id,
            outcome=outcome,
            detail=detail,
            source_ip=client_ip(request)[:64] if request is not None else None,
            user_agent=_user_agent(request),
        )
    )


def record(
    db: Session,
    *,
    action: str,
    outcome: str,
    user_id: uuid.UUID | None = None,
    username: str | None = None,
    firewall_id: uuid.UUID | None = None,
    detail: dict[str, Any] | None = None,
    request: Request | None = None,
) -> None:
    """Persist an audit record and commit immediately so failures are still recorded."""
    add(
        db,
        action=action,
        outcome=outcome,
        user_id=user_id,
        username=username,
        firewall_id=firewall_id,
        detail=detail,
        request=request,
    )
    db.commit()


def record_throttled(
    db: Session,
    *,
    request: Request,
    action: str,
    outcome: str = OUTCOME_DENIED,
    user_id: uuid.UUID | None = None,
    username: str | None = None,
    detail: dict[str, Any] | None = None,
) -> bool:
    """Like ``record`` but writes at most one row per (source IP, action) per minute, so
    unauthenticated noise (401s, CSRF failures) cannot bloat the table. Returns True if written."""
    ip = client_ip(request)[:64]
    recent = db.execute(
        select(AuditLog.id)
        .where(
            AuditLog.source_ip == ip,
            AuditLog.action == action,
            AuditLog.timestamp > utcnow() - THROTTLE_WINDOW,
        )
        .limit(1)
    ).first()
    if recent is not None:
        return False
    record(
        db,
        action=action,
        outcome=outcome,
        user_id=user_id,
        username=username,
        detail=detail,
        request=request,
    )
    return True
