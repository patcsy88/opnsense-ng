"""Change request endpoints (ADR-0005). Staging and review only: nothing here calls OPNsense."""

import uuid
from datetime import datetime
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Query, Request, status
from pydantic import BaseModel, ConfigDict, Field
from sqlalchemy import select
from sqlalchemy.orm import Session

from app import audit
from app.auth.deps import ALL_ROLES, CurrentUser, get_db, require_roles
from app.changes import apply as apply_changes
from app.changes import service
from app.changes.schemas import AliasProposal
from app.changes.states import Status
from app.core.config import Settings, get_settings
from app.db.models import ChangeRequest, Role

router = APIRouter(prefix="/api/v1/changes", tags=["changes"])

LIST_LIMIT = 200
MANAGERS = (Role.admin, Role.network_admin)


class NoteBody(BaseModel):
    model_config = ConfigDict(extra="forbid")

    note: str | None = Field(default=None, max_length=service.NOTE_MAX)


class AliasChangeCreate(BaseModel):
    model_config = ConfigDict(extra="forbid")

    firewall_id: uuid.UUID
    alias: AliasProposal


class ChangeEventOut(BaseModel):
    timestamp: datetime
    actor_username: str
    from_status: str | None
    to_status: str
    note: str | None


class ChangeOut(BaseModel):
    id: uuid.UUID
    firewall_id: uuid.UUID
    kind: str
    action: str
    target_uuid: str | None
    proposed: dict[str, Any] | None
    status: str
    high_risk: bool
    self_approved: bool
    requester_username: str
    reviewer_username: str | None
    applier_username: str | None
    failure_message: str | None
    created_at: datetime
    updated_at: datetime


class ChangeDetailOut(ChangeOut):
    events: list[ChangeEventOut]


def _out(cr: ChangeRequest) -> ChangeOut:
    return ChangeOut.model_validate(cr, from_attributes=True)


def _detail(db: Session, cr: ChangeRequest) -> ChangeDetailOut:
    events = [
        ChangeEventOut.model_validate(e, from_attributes=True) for e in service.list_events(db, cr)
    ]
    return ChangeDetailOut(**_out(cr).model_dump(), events=events)


def _get(db: Session, change_id: uuid.UUID) -> ChangeRequest:
    cr = db.get(ChangeRequest, change_id)
    if cr is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Change request not found")
    return cr


def _refuse(
    db: Session,
    exc: service.ChangeError,
    *,
    action: str,
    user: CurrentUser,
    request: Request,
    firewall_id: uuid.UUID | None,
    change_id: uuid.UUID | None,
) -> HTTPException:
    denied = isinstance(exc, service.NotPermitted)
    db.rollback()
    audit.record(
        db,
        action=action,
        outcome=audit.OUTCOME_DENIED if denied else audit.OUTCOME_FAILURE,
        user_id=user.id,
        username=user.username,
        firewall_id=firewall_id,
        detail={"change_request": str(change_id) if change_id else None, "reason": str(exc)},
        request=request,
    )
    code = (
        status.HTTP_403_FORBIDDEN
        if denied
        else status.HTTP_409_CONFLICT
        if isinstance(exc, service.InvalidTransition)
        else status.HTTP_400_BAD_REQUEST
    )
    return HTTPException(code, str(exc))


@router.post("/aliases", response_model=ChangeDetailOut, status_code=status.HTTP_201_CREATED)
def stage_alias_create(
    request: Request,
    body: AliasChangeCreate,
    user: CurrentUser = Depends(require_roles(*MANAGERS)),
    db: Session = Depends(get_db),
) -> ChangeDetailOut:
    """Stage a new alias. Local validation has already passed (422 otherwise), so the request
    moves straight from draft to validated. Nothing is sent to the firewall."""
    name = body.alias.name
    duplicate = db.scalar(
        select(ChangeRequest.id).where(
            ChangeRequest.firewall_id == body.firewall_id,
            ChangeRequest.kind == "alias",
            ChangeRequest.action == "create",
            ChangeRequest.proposed["name"].astext == name,
            ChangeRequest.status.in_(
                [
                    s.value
                    for s in (Status.draft, Status.validated, Status.in_review, Status.approved)
                ]
            ),
        )
    )
    if duplicate is not None:
        raise _refuse(
            db,
            service.ChangeError("An open request already creates an alias with this name"),
            action="change.stage_alias",
            user=user,
            request=request,
            firewall_id=body.firewall_id,
            change_id=duplicate,
        )
    try:
        cr = service.create_draft(
            db,
            user=user,
            firewall_id=body.firewall_id,
            kind="alias",
            action="create",
            target_uuid=None,
            proposed=body.alias.model_dump(),
            base_snapshot=None,
            request=request,
        )
        service.transition(db, cr, Status.validated, user=user, request=request)
    except service.ChangeError as exc:
        raise _refuse(
            db,
            exc,
            action="change.stage_alias",
            user=user,
            request=request,
            firewall_id=body.firewall_id,
            change_id=None,
        ) from None
    db.commit()
    return _detail(db, cr)


@router.get("", response_model=list[ChangeOut])
def list_changes(
    firewall_id: uuid.UUID | None = None,
    status_filter: str | None = Query(default=None, alias="status", max_length=20),
    _user: CurrentUser = Depends(require_roles(*ALL_ROLES)),
    db: Session = Depends(get_db),
) -> list[ChangeOut]:
    query = select(ChangeRequest).order_by(ChangeRequest.created_at.desc()).limit(LIST_LIMIT)
    if firewall_id is not None:
        query = query.where(ChangeRequest.firewall_id == firewall_id)
    if status_filter is not None:
        if status_filter not in {s.value for s in Status}:
            raise HTTPException(status.HTTP_422_UNPROCESSABLE_CONTENT, "Unknown status")
        query = query.where(ChangeRequest.status == status_filter)
    return [_out(cr) for cr in db.scalars(query)]


@router.get("/{change_id}", response_model=ChangeDetailOut)
def get_change(
    change_id: uuid.UUID,
    _user: CurrentUser = Depends(require_roles(*ALL_ROLES)),
    db: Session = Depends(get_db),
) -> ChangeDetailOut:
    return _detail(db, _get(db, change_id))


def _move(
    *,
    change_id: uuid.UUID,
    to: Status,
    body: NoteBody | None,
    user: CurrentUser,
    db: Session,
    request: Request,
) -> ChangeDetailOut:
    cr = _get(db, change_id)
    firewall_id = cr.firewall_id
    try:
        service.transition(db, cr, to, user=user, note=body.note if body else None, request=request)
    except service.ChangeError as exc:
        raise _refuse(
            db,
            exc,
            action=f"change.{to.value}",
            user=user,
            request=request,
            firewall_id=firewall_id,
            change_id=change_id,
        ) from None
    db.commit()
    return _detail(db, cr)


@router.post("/{change_id}/submit", response_model=ChangeDetailOut)
def submit_change(
    request: Request,
    change_id: uuid.UUID,
    body: NoteBody | None = None,
    user: CurrentUser = Depends(require_roles(*MANAGERS)),
    db: Session = Depends(get_db),
) -> ChangeDetailOut:
    return _move(
        change_id=change_id, to=Status.in_review, body=body, user=user, db=db, request=request
    )


@router.post("/{change_id}/approve", response_model=ChangeDetailOut)
def approve_change(
    request: Request,
    change_id: uuid.UUID,
    body: NoteBody | None = None,
    user: CurrentUser = Depends(require_roles(*MANAGERS)),
    db: Session = Depends(get_db),
) -> ChangeDetailOut:
    return _move(
        change_id=change_id, to=Status.approved, body=body, user=user, db=db, request=request
    )


@router.post("/{change_id}/reject", response_model=ChangeDetailOut)
def reject_change(
    request: Request,
    change_id: uuid.UUID,
    body: NoteBody | None = None,
    user: CurrentUser = Depends(require_roles(*MANAGERS)),
    db: Session = Depends(get_db),
) -> ChangeDetailOut:
    return _move(
        change_id=change_id, to=Status.rejected, body=body, user=user, db=db, request=request
    )


@router.post("/{change_id}/cancel", response_model=ChangeDetailOut)
def cancel_change(
    request: Request,
    change_id: uuid.UUID,
    body: NoteBody | None = None,
    user: CurrentUser = Depends(require_roles(*MANAGERS)),
    db: Session = Depends(get_db),
) -> ChangeDetailOut:
    return _move(
        change_id=change_id, to=Status.cancelled, body=body, user=user, db=db, request=request
    )


class ApplyBody(BaseModel):
    model_config = ConfigDict(extra="forbid")

    confirm_name: str | None = Field(default=None, max_length=64)


@router.post("/{change_id}/apply", response_model=ChangeDetailOut)
def apply_change(
    request: Request,
    change_id: uuid.UUID,
    body: ApplyBody | None = None,
    user: CurrentUser = Depends(require_roles(Role.admin)),
    db: Session = Depends(get_db),
    settings: Settings = Depends(get_settings),
) -> ChangeDetailOut:
    """Send an approved change to the firewall. Admin only, and only where allow_writes is on.
    A failed apply is reported in the body with status failed or stale (HTTP 200); there is no
    automatic rollback."""
    cr = _get(db, change_id)
    firewall_id = cr.firewall_id
    try:
        cr = apply_changes.apply_alias_create(
            db,
            change_id=change_id,
            user=user,
            settings=settings,
            request=request,
            confirm_name=body.confirm_name if body else None,
        )
    except (service.ChangeError, apply_changes.ApplyRefused) as exc:
        error = (
            service.ChangeError(str(exc)) if isinstance(exc, apply_changes.ApplyRefused) else exc
        )
        raise _refuse(
            db,
            error,
            action="change.apply",
            user=user,
            request=request,
            firewall_id=firewall_id,
            change_id=change_id,
        ) from None
    return _detail(db, cr)
