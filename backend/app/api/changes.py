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
from app.changes.rule_schemas import RuleProposal
from app.changes.schemas import AliasProposal
from app.changes.states import Status
from app.core.config import Settings, get_settings
from app.core.crypto import CredentialDecryptionError
from app.db.models import ChangeRequest, Firewall, Role
from app.opnsense.errors import FirewallError
from app.opnsense.normalise.aliases import AliasInfo
from app.opnsense.normalise.rules import RuleInfo

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
    base_snapshot: dict[str, Any] | None
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


class AliasUpdateCreate(BaseModel):
    model_config = ConfigDict(extra="forbid")

    firewall_id: uuid.UUID
    alias: AliasProposal


class AliasDeleteCreate(BaseModel):
    model_config = ConfigDict(extra="forbid")

    firewall_id: uuid.UUID


OPEN_STATES = [s.value for s in (Status.draft, Status.validated, Status.in_review, Status.approved)]


def _live_alias(
    db: Session,
    *,
    firewall_id: uuid.UUID,
    target: str,
    user: CurrentUser,
    settings: Settings,
    request: Request,
    action: str,
) -> AliasInfo:
    """Read the alias from the firewall (read-only) so the request records what it is based on."""
    fw = db.get(Firewall, firewall_id)
    try:
        if fw is None:
            raise service.ChangeError("Unknown firewall")
        rows = apply_changes.read_aliases(
            db, firewall=fw, user=user, settings=settings, request=request
        )
    except service.ChangeError as exc:
        raise _refuse(
            db,
            exc,
            action=action,
            user=user,
            request=request,
            firewall_id=firewall_id,
            change_id=None,
        ) from None
    except FirewallError, CredentialDecryptionError:
        raise _refuse(
            db,
            service.ChangeError("Could not read the alias from the firewall"),
            action=action,
            user=user,
            request=request,
            firewall_id=firewall_id,
            change_id=None,
        ) from None
    found = next((a for a in rows if a.uuid == target), None)
    if found is None or found.name is None or found.type is None:
        raise _refuse(
            db,
            service.ChangeError("That alias was not found on the firewall"),
            action=action,
            user=user,
            request=request,
            firewall_id=firewall_id,
            change_id=None,
        )
    return found


def _stage_alias_change(
    *,
    db: Session,
    request: Request,
    user: CurrentUser,
    settings: Settings,
    firewall_id: uuid.UUID,
    target: str,
    action: str,
    proposal: AliasProposal | None,
) -> ChangeDetailOut:
    audit_action = f"change.stage_alias_{action}"
    if not _is_uuid(target):
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_CONTENT, "Invalid alias id")
    current = _live_alias(
        db,
        firewall_id=firewall_id,
        target=target,
        user=user,
        settings=settings,
        request=request,
        action=audit_action,
    )
    if proposal is not None and (proposal.name != current.name or proposal.type != current.type):
        raise _refuse(
            db,
            service.ChangeError(
                "Renaming an alias or changing its type is not supported; "
                "create a new alias instead"
            ),
            action=audit_action,
            user=user,
            request=request,
            firewall_id=firewall_id,
            change_id=None,
        )
    duplicate = db.scalar(
        select(ChangeRequest.id).where(
            ChangeRequest.firewall_id == firewall_id,
            ChangeRequest.kind == "alias",
            ChangeRequest.target_uuid == target,
            ChangeRequest.status.in_(OPEN_STATES),
        )
    )
    if duplicate is not None:
        raise _refuse(
            db,
            service.ChangeError("An open request already changes this alias"),
            action=audit_action,
            user=user,
            request=request,
            firewall_id=firewall_id,
            change_id=duplicate,
        )
    base = current.model_dump()
    if proposal is not None:
        proposed = proposal.model_dump()
    else:
        proposed = {
            "name": current.name,
            "type": current.type,
            "content": current.content,
            "description": current.description or "",
            "enabled": current.enabled is not False,
        }
    try:
        cr = service.create_draft(
            db,
            user=user,
            firewall_id=firewall_id,
            kind="alias",
            action=action,
            target_uuid=target,
            proposed=proposed,
            base_snapshot=base,
            high_risk=action == "delete",
            request=request,
        )
        service.transition(db, cr, Status.validated, user=user, request=request)
    except service.ChangeError as exc:
        raise _refuse(
            db,
            exc,
            action=audit_action,
            user=user,
            request=request,
            firewall_id=firewall_id,
            change_id=None,
        ) from None
    db.commit()
    return _detail(db, cr)


def _is_uuid(value: str) -> bool:
    try:
        return str(uuid.UUID(value)) == value
    except ValueError:
        return False


@router.post("/aliases/{target}/update", response_model=ChangeDetailOut, status_code=201)
def stage_alias_update(
    request: Request,
    target: str,
    body: AliasUpdateCreate,
    user: CurrentUser = Depends(require_roles(*MANAGERS)),
    db: Session = Depends(get_db),
    settings: Settings = Depends(get_settings),
) -> ChangeDetailOut:
    """Stage new content for an existing alias. The live alias is read once (read-only) and its
    state is recorded; apply refuses if the alias has changed since."""
    return _stage_alias_change(
        db=db,
        request=request,
        user=user,
        settings=settings,
        firewall_id=body.firewall_id,
        target=target,
        action="update",
        proposal=body.alias,
    )


@router.post("/aliases/{target}/delete", response_model=ChangeDetailOut, status_code=201)
def stage_alias_delete(
    request: Request,
    target: str,
    body: AliasDeleteCreate,
    user: CurrentUser = Depends(require_roles(*MANAGERS)),
    db: Session = Depends(get_db),
    settings: Settings = Depends(get_settings),
) -> ChangeDetailOut:
    """Stage deletion of an alias. Always high risk: an admin must approve it and the name is
    typed again at apply. The firewall itself refuses if the alias is still referenced."""
    return _stage_alias_change(
        db=db,
        request=request,
        user=user,
        settings=settings,
        firewall_id=body.firewall_id,
        target=target,
        action="delete",
        proposal=None,
    )


class RuleCreate(BaseModel):
    model_config = ConfigDict(extra="forbid")

    firewall_id: uuid.UUID
    rule: RuleProposal


@router.post("/rules", response_model=ChangeDetailOut, status_code=status.HTTP_201_CREATED)
def stage_rule_create(
    request: Request,
    body: RuleCreate,
    user: CurrentUser = Depends(require_roles(*MANAGERS)),
    db: Session = Depends(get_db),
    settings: Settings = Depends(get_settings),
) -> ChangeDetailOut:
    """Stage a new rule. The rules and any aliases it names are read (read-only) to check that the
    description is unused and the aliases exist. High risk for pass-any rules and WAN rules."""
    audit_action = "change.stage_rule_create"
    firewall_id = body.firewall_id
    rule = body.rule

    def refuse(message: str, change_id: uuid.UUID | None = None) -> HTTPException:
        return _refuse(
            db,
            service.ChangeError(message),
            action=audit_action,
            user=user,
            request=request,
            firewall_id=firewall_id,
            change_id=change_id,
        )

    fw = db.get(Firewall, firewall_id)
    if fw is None:
        raise refuse("Unknown firewall")
    try:
        rows = apply_changes.read_rules(
            db, firewall=fw, user=user, settings=settings, request=request
        )
        aliases = (
            apply_changes.read_aliases(
                db, firewall=fw, user=user, settings=settings, request=request
            )
            if rule.alias_references()
            else []
        )
    except FirewallError, CredentialDecryptionError:
        raise refuse("Could not read the current configuration from the firewall") from None
    if any(r.description == rule.description for r in rows):
        raise refuse("A rule with this description already exists on the firewall")
    problem = apply_changes.alias_problem(rule.alias_references(), aliases, rule.model_dump())
    if problem:
        raise refuse(problem)
    duplicate = db.scalar(
        select(ChangeRequest.id).where(
            ChangeRequest.firewall_id == firewall_id,
            ChangeRequest.kind == "rule",
            ChangeRequest.action == "create",
            ChangeRequest.proposed["description"].astext == rule.description,
            ChangeRequest.status.in_(OPEN_STATES),
        )
    )
    if duplicate is not None:
        raise refuse("An open request already creates a rule with this description", duplicate)
    reasons = rule.risk_reasons()
    try:
        cr = service.create_draft(
            db,
            user=user,
            firewall_id=firewall_id,
            kind="rule",
            action="create",
            target_uuid=None,
            proposed={**rule.model_dump(), "label": rule.description, "risk": reasons},
            base_snapshot=None,
            high_risk=bool(reasons),
            request=request,
        )
        service.transition(db, cr, Status.validated, user=user, request=request)
    except service.ChangeError as exc:
        raise _refuse(
            db,
            exc,
            action=audit_action,
            user=user,
            request=request,
            firewall_id=firewall_id,
            change_id=None,
        ) from None
    db.commit()
    return _detail(db, cr)


class RuleToggleCreate(BaseModel):
    model_config = ConfigDict(extra="forbid")

    firewall_id: uuid.UUID
    enabled: bool


def _rule_label(rule: RuleInfo) -> str:
    return (rule.description or str(rule.uuid)[:8])[:64]


@router.post(
    "/rules/{target}/toggle", response_model=ChangeDetailOut, status_code=status.HTTP_201_CREATED
)
def stage_rule_toggle(
    request: Request,
    target: str,
    body: RuleToggleCreate,
    user: CurrentUser = Depends(require_roles(*MANAGERS)),
    db: Session = Depends(get_db),
    settings: Settings = Depends(get_settings),
) -> ChangeDetailOut:
    """Stage enabling or disabling an existing rule. The live rule is read once (read-only) and
    recorded; apply refuses if it has changed since. High risk when the rule is a pass-any rule or
    sits on WAN."""
    audit_action = "change.stage_rule_toggle"
    firewall_id = body.firewall_id
    if not _is_uuid(target):
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_CONTENT, "Invalid rule id")

    def refuse(message: str, change_id: uuid.UUID | None = None) -> HTTPException:
        return _refuse(
            db,
            service.ChangeError(message),
            action=audit_action,
            user=user,
            request=request,
            firewall_id=firewall_id,
            change_id=change_id,
        )

    fw = db.get(Firewall, firewall_id)
    if fw is None:
        raise refuse("Unknown firewall")
    try:
        rows = apply_changes.read_rules(
            db, firewall=fw, user=user, settings=settings, request=request
        )
    except FirewallError, CredentialDecryptionError:
        raise refuse("Could not read the rule from the firewall") from None
    current = next((r for r in rows if r.uuid == target), None)
    if current is None:
        raise refuse("That rule was not found on the firewall")
    if (current.enabled is not False) == body.enabled:
        raise refuse("The rule is already " + ("enabled" if body.enabled else "disabled"))
    duplicate = db.scalar(
        select(ChangeRequest.id).where(
            ChangeRequest.firewall_id == firewall_id,
            ChangeRequest.kind == "rule",
            ChangeRequest.target_uuid == target,
            ChangeRequest.status.in_(OPEN_STATES),
        )
    )
    if duplicate is not None:
        raise refuse("An open request already changes this rule", duplicate)
    high_risk = (
        current.sequence is None  # auto-generated system rule (anti-lockout and similar)
        or current.interface == "wan"
        or (
            current.action == "pass"
            and current.source in (None, "any")
            and current.destination in (None, "any")
        )
    )
    try:
        cr = service.create_draft(
            db,
            user=user,
            firewall_id=firewall_id,
            kind="rule",
            action="toggle",
            target_uuid=target,
            proposed={
                "label": _rule_label(current),
                "enabled": body.enabled,
                "description": current.description or "",
            },
            base_snapshot=current.model_dump(),
            high_risk=high_risk,
            request=request,
        )
        service.transition(db, cr, Status.validated, user=user, request=request)
    except service.ChangeError as exc:
        raise _refuse(
            db,
            exc,
            action=audit_action,
            user=user,
            request=request,
            firewall_id=firewall_id,
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
        run = (
            apply_changes.apply_rule_change
            if cr.kind == "rule"
            else apply_changes.apply_alias_change
        )
        cr = run(
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
