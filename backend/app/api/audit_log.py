"""Audit log viewer and manual purge (ADR-0011). Read-only except for the admin purge."""

import uuid
from datetime import datetime, timedelta
from typing import Annotated, Any, Literal, cast

from fastapi import APIRouter, Depends, Query, Request
from pydantic import BaseModel
from sqlalchemy import ColumnElement, CursorResult, delete, func, select
from sqlalchemy.orm import Session

from app import audit
from app.auth.deps import CurrentUser, get_db, require_roles
from app.core.config import Settings, get_settings
from app.db.models import AuditLog, Role, utcnow

router = APIRouter(prefix="/api/v1/audit", tags=["audit"])

VIEW_ROLES = (Role.admin, Role.security_admin)
MAX_PAGE_SIZE = 200
DETAIL_KEY_MAX = 64
DETAIL_VALUE_MAX = 200
DETAIL_KEYS_MAX = 20
USER_AGENT_MAX = 120

Scalar = str | int | float | bool | None


class AuditEntryOut(BaseModel):
    id: uuid.UUID
    timestamp: datetime
    username: str | None
    action: str
    firewall_id: uuid.UUID | None
    outcome: str
    source_ip: str | None
    user_agent: str | None
    detail: dict[str, Scalar]


class AuditPageOut(BaseModel):
    items: list[AuditEntryOut]
    total: int
    page: int
    page_size: int
    retention_days: int
    purgeable: int


class PurgeIn(BaseModel):
    confirm: Literal["PURGE"]


class PurgeOut(BaseModel):
    removed: int
    cutoff: datetime


def public_detail(detail: Any) -> dict[str, Scalar]:
    """Only flat scalars under short keys leave the backend; nesting and long text are cut."""
    if not isinstance(detail, dict):
        return {}
    out: dict[str, Scalar] = {}
    for key, value in detail.items():
        if len(out) >= DETAIL_KEYS_MAX:
            break
        if not isinstance(key, str) or len(key) > DETAIL_KEY_MAX:
            continue
        if isinstance(value, str):
            out[key] = value[:DETAIL_VALUE_MAX]
        elif value is None or isinstance(value, (bool, int, float)):
            out[key] = value
    return out


def _entry(row: AuditLog) -> AuditEntryOut:
    return AuditEntryOut(
        id=row.id,
        timestamp=row.timestamp,
        username=row.username,
        action=row.action,
        firewall_id=row.firewall_id,
        outcome=row.outcome,
        source_ip=row.source_ip,
        user_agent=row.user_agent[:USER_AGENT_MAX] if row.user_agent else None,
        detail=public_detail(row.detail),
    )


def _cutoff(settings: Settings) -> datetime:
    return utcnow() - timedelta(days=settings.audit_retention_days)


@router.get("", response_model=AuditPageOut)
def list_audit(
    request: Request,
    username: Annotated[str | None, Query(max_length=64)] = None,
    action: Annotated[str | None, Query(max_length=100)] = None,
    firewall_id: uuid.UUID | None = None,
    outcome: Annotated[Literal["success", "failure", "denied"] | None, Query()] = None,
    since: datetime | None = None,
    until: datetime | None = None,
    page: Annotated[int, Query(ge=1, le=100_000)] = 1,
    page_size: Annotated[int, Query(ge=1, le=MAX_PAGE_SIZE)] = 50,
    user: CurrentUser = Depends(require_roles(*VIEW_ROLES)),
    db: Session = Depends(get_db),
    settings: Settings = Depends(get_settings),
) -> AuditPageOut:
    conditions: list[ColumnElement[bool]] = []
    if username:
        conditions.append(AuditLog.username == username)
    if action:
        conditions.append(AuditLog.action.startswith(action, autoescape=True))
    if firewall_id:
        conditions.append(AuditLog.firewall_id == firewall_id)
    if outcome:
        conditions.append(AuditLog.outcome == outcome)
    if since:
        conditions.append(AuditLog.timestamp >= since)
    if until:
        conditions.append(AuditLog.timestamp <= until)

    total = db.scalar(select(func.count()).select_from(AuditLog).where(*conditions)) or 0
    rows = db.scalars(
        select(AuditLog)
        .where(*conditions)
        .order_by(AuditLog.timestamp.desc(), AuditLog.id)
        .offset((page - 1) * page_size)
        .limit(page_size)
    ).all()
    purgeable = (
        db.scalar(
            select(func.count()).select_from(AuditLog).where(AuditLog.timestamp < _cutoff(settings))
        )
        or 0
    )
    audit.record(
        db,
        action="audit.view",
        outcome=audit.OUTCOME_SUCCESS,
        user_id=user.id,
        username=user.username,
        request=request,
    )
    return AuditPageOut(
        items=[_entry(r) for r in rows],
        total=total,
        page=page,
        page_size=page_size,
        retention_days=settings.audit_retention_days,
        purgeable=purgeable,
    )


@router.post("/purge", response_model=PurgeOut)
def purge_audit(
    request: Request,
    body: PurgeIn,
    user: CurrentUser = Depends(require_roles(Role.admin)),
    db: Session = Depends(get_db),
    settings: Settings = Depends(get_settings),
) -> PurgeOut:
    """Delete records older than the retention period. The purge is recorded in the same
    transaction, and records inside the period can never be removed here."""
    cutoff = _cutoff(settings)
    result = cast(
        "CursorResult[Any]", db.execute(delete(AuditLog).where(AuditLog.timestamp < cutoff))
    )
    removed = result.rowcount
    audit.add(
        db,
        action="audit.purge",
        outcome=audit.OUTCOME_SUCCESS,
        user_id=user.id,
        username=user.username,
        detail={
            "cutoff": cutoff.isoformat(),
            "removed": removed,
            "retention_days": settings.audit_retention_days,
        },
        request=request,
    )
    db.commit()
    return PurgeOut(removed=removed, cutoff=cutoff)
