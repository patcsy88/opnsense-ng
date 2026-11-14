"""Change request endpoints (ADR-0005). Staging and review only: nothing here calls OPNsense."""

import ipaddress
import uuid
from datetime import datetime
from typing import Any
from urllib.parse import urlsplit

from fastapi import APIRouter, Depends, HTTPException, Query, Request, status
from pydantic import BaseModel, ConfigDict, Field
from sqlalchemy import select
from sqlalchemy.orm import Session

from app import audit
from app.auth.deps import ALL_ROLES, CurrentUser, get_db, require_roles
from app.changes import apply as apply_changes
from app.changes import service
from app.changes.dnsmasq_schemas import DomainProposal, HostProposal
from app.changes.forward_schemas import ForwardProposal, forward_risk
from app.changes.rule_schemas import RuleProposal
from app.changes.schemas import AliasProposal
from app.changes.states import Status
from app.changes.unbound_schemas import UnboundHostProposal
from app.core.config import Settings, get_settings
from app.core.crypto import CredentialDecryptionError
from app.db.models import ChangeRequest, Firewall, Role
from app.opnsense.errors import FirewallError
from app.opnsense.normalise.aliases import AliasInfo
from app.opnsense.normalise.nat import NatRule
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


def _visible[T: ChangeOut](out: T, user: CurrentUser) -> T:
    """MAC addresses in Dnsmasq host requests are only for admin and network_admin (ADR-0017)."""
    if out.kind != "dnsmasq_host" or user.role in MANAGERS:
        return out

    def strip(data: dict[str, Any] | None) -> dict[str, Any] | None:
        if data is None:
            return None
        return {k: v for k, v in data.items() if k not in ("hwaddrs",)}

    out.proposed = strip(out.proposed)
    out.base_snapshot = strip(out.base_snapshot)
    return out


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


class RuleUpdateCreate(BaseModel):
    model_config = ConfigDict(extra="forbid")

    firewall_id: uuid.UUID
    rule: RuleProposal


class RuleDeleteCreate(BaseModel):
    model_config = ConfigDict(extra="forbid")

    firewall_id: uuid.UUID


def _existing_risky(rule: RuleInfo) -> bool:
    return (
        rule.sequence is None
        or rule.interface == "wan"
        or (
            rule.action == "pass"
            and rule.source in (None, "any")
            and rule.destination in (None, "any")
        )
    )


def _stage_rule_edit(
    request: Request,
    target: str,
    firewall_id: uuid.UUID,
    proposal: RuleProposal | None,
    user: CurrentUser,
    db: Session,
    settings: Settings,
) -> ChangeDetailOut:
    action = "update" if proposal is not None else "delete"
    audit_action = f"change.stage_rule_{action}"
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
        aliases = (
            apply_changes.read_aliases(
                db, firewall=fw, user=user, settings=settings, request=request
            )
            if proposal is not None and proposal.alias_references()
            else []
        )
    except FirewallError, CredentialDecryptionError:
        raise refuse("Could not read the rule from the firewall") from None
    current = next((r for r in rows if r.uuid == target), None)
    if current is None:
        raise refuse("That rule was not found on the firewall")
    reasons: list[str] = []
    if proposal is not None:
        if current.sequence is None:
            raise refuse("Automatic and system rules cannot be edited here")
        if not current.description:
            raise refuse("Only rules with a description can be edited here")
        if proposal.interface != current.interface or proposal.description != current.description:
            raise refuse("The interface and description of a rule cannot be changed")
        problem = apply_changes.alias_problem(
            proposal.alias_references(), aliases, proposal.model_dump()
        )
        if problem:
            raise refuse(problem)
        reasons = proposal.risk_reasons()
    else:
        reasons = ["deletes a rule"]
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
    if (
        proposal is not None
        and _existing_risky(current)
        and "existing rule is high risk" not in reasons
    ):
        reasons.append("existing rule is high risk")
    proposed: dict[str, Any] = (
        {**proposal.model_dump(), "label": _rule_label(current), "risk": reasons}
        if proposal is not None
        else {
            "label": _rule_label(current),
            "description": current.description or "",
            "risk": reasons,
        }
    )
    try:
        cr = service.create_draft(
            db,
            user=user,
            firewall_id=firewall_id,
            kind="rule",
            action=action,
            target_uuid=target,
            proposed=proposed,
            base_snapshot=current.model_dump(),
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


@router.post(
    "/rules/{target}/update", response_model=ChangeDetailOut, status_code=status.HTTP_201_CREATED
)
def stage_rule_update(
    request: Request,
    target: str,
    body: RuleUpdateCreate,
    user: CurrentUser = Depends(require_roles(*MANAGERS)),
    db: Session = Depends(get_db),
    settings: Settings = Depends(get_settings),
) -> ChangeDetailOut:
    """Stage editing an existing rule. Interface and description stay fixed."""
    return _stage_rule_edit(request, target, body.firewall_id, body.rule, user, db, settings)


@router.post(
    "/rules/{target}/delete", response_model=ChangeDetailOut, status_code=status.HTTP_201_CREATED
)
def stage_rule_delete(
    request: Request,
    target: str,
    body: RuleDeleteCreate,
    user: CurrentUser = Depends(require_roles(*MANAGERS)),
    db: Session = Depends(get_db),
    settings: Settings = Depends(get_settings),
) -> ChangeDetailOut:
    """Stage deleting a rule. Always high risk."""
    return _stage_rule_edit(request, target, body.firewall_id, None, user, db, settings)


class ForwardCreate(BaseModel):
    model_config = ConfigDict(extra="forbid")

    firewall_id: uuid.UUID
    forward: ForwardProposal


class ForwardToggleCreate(BaseModel):
    model_config = ConfigDict(extra="forbid")

    firewall_id: uuid.UUID
    enabled: bool


class ForwardDeleteCreate(BaseModel):
    model_config = ConfigDict(extra="forbid")

    firewall_id: uuid.UUID


def _forward_label(fwd: NatRule) -> str:
    return (fwd.description or str(fwd.uuid)[:8])[:64]


def _stage_forward(
    request: Request,
    firewall_id: uuid.UUID,
    user: CurrentUser,
    db: Session,
    settings: Settings,
    *,
    action: str,
    target: str | None,
    proposal: ForwardProposal | None = None,
    enabled: bool | None = None,
) -> ChangeDetailOut:
    """Shared staging for create, update, toggle and delete of a port forward (ADR-0006). Reads the
    forwards (and aliases when named) read-only; nothing is written to the firewall."""
    audit_action = f"change.stage_forward_{action}"
    if target is not None and not _is_uuid(target):
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_CONTENT, "Invalid forward id")

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
        rows = apply_changes.read_forwards(
            db, firewall=fw, user=user, settings=settings, request=request
        )
        aliases = (
            apply_changes.read_aliases(
                db, firewall=fw, user=user, settings=settings, request=request
            )
            if proposal is not None and proposal.alias_references()
            else []
        )
    except FirewallError, CredentialDecryptionError:
        raise refuse("Could not read the port forwards from the firewall") from None

    current = next((r for r in rows if r.uuid == target), None) if target else None
    if target is not None and current is None:
        raise refuse("That port forward was not found on the firewall")
    if current is not None:
        if current.automatic or current.sequence is None:
            raise refuse("Automatic forwards cannot be changed here")
        if current.excluded:
            raise refuse("'No redirect' exception forwards cannot be changed here")

    reasons: list[str] = []
    proposed: dict[str, Any]
    if action == "create" and proposal is not None:
        if any(r.description == proposal.description for r in rows):
            raise refuse("A port forward with this description already exists on the firewall")
        label = proposal.description
        reasons = proposal.risk_reasons()
        proposed = {**proposal.model_dump(), "label": label, "risk": reasons}
    elif action == "update" and proposal is not None and current is not None:
        if not current.description:
            raise refuse("Only forwards with a description can be edited here")
        if proposal.interface != current.interface or proposal.description != current.description:
            raise refuse("The interface and description of a forward cannot be changed")
        reasons = proposal.risk_reasons()
        for reason in forward_risk(current.interface, current.source, current.destination_port):
            if reason not in reasons:
                reasons.append(f"existing forward: {reason}")
        proposed = {**proposal.model_dump(), "label": _forward_label(current), "risk": reasons}
    elif action == "toggle" and current is not None:
        if (current.enabled is not False) == enabled:
            raise refuse("The forward is already " + ("enabled" if enabled else "disabled"))
        reasons = forward_risk(current.interface, current.source, current.destination_port)
        proposed = {
            "label": _forward_label(current),
            "enabled": enabled,
            "description": current.description or "",
            "risk": reasons,
        }
    elif action == "delete" and current is not None:
        reasons = ["deletes a port forward"]
        proposed = {
            "label": _forward_label(current),
            "description": current.description or "",
            "risk": reasons,
        }
    else:
        raise refuse("Unsupported request")

    if proposal is not None:
        problem = apply_changes.alias_problem(
            proposal.alias_references(), aliases, proposal.model_dump()
        )
        if problem:
            raise refuse(problem)

    if action == "create":
        clash = ChangeRequest.proposed["description"].astext == proposed["description"]
        duplicate = db.scalar(
            select(ChangeRequest.id).where(
                ChangeRequest.firewall_id == firewall_id,
                ChangeRequest.kind == "nat_forward",
                ChangeRequest.action == "create",
                clash,
                ChangeRequest.status.in_(OPEN_STATES),
            )
        )
    else:
        duplicate = db.scalar(
            select(ChangeRequest.id).where(
                ChangeRequest.firewall_id == firewall_id,
                ChangeRequest.kind == "nat_forward",
                ChangeRequest.target_uuid == target,
                ChangeRequest.status.in_(OPEN_STATES),
            )
        )
    if duplicate is not None:
        raise refuse("An open request already changes this port forward", duplicate)

    try:
        cr = service.create_draft(
            db,
            user=user,
            firewall_id=firewall_id,
            kind="nat_forward",
            action=action,
            target_uuid=target,
            proposed=proposed,
            base_snapshot=current.model_dump() if current is not None else None,
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


@router.post("/forwards", response_model=ChangeDetailOut, status_code=status.HTTP_201_CREATED)
def stage_forward_create(
    request: Request,
    body: ForwardCreate,
    user: CurrentUser = Depends(require_roles(*MANAGERS)),
    db: Session = Depends(get_db),
    settings: Settings = Depends(get_settings),
) -> ChangeDetailOut:
    """Stage a new port forward. High risk on WAN and for wide-open sources."""
    return _stage_forward(
        request,
        body.firewall_id,
        user,
        db,
        settings,
        action="create",
        target=None,
        proposal=body.forward,
    )


@router.post(
    "/forwards/{target}/update", response_model=ChangeDetailOut, status_code=status.HTTP_201_CREATED
)
def stage_forward_update(
    request: Request,
    target: str,
    body: ForwardCreate,
    user: CurrentUser = Depends(require_roles(*MANAGERS)),
    db: Session = Depends(get_db),
    settings: Settings = Depends(get_settings),
) -> ChangeDetailOut:
    """Stage editing a port forward. Interface and description stay fixed."""
    return _stage_forward(
        request,
        body.firewall_id,
        user,
        db,
        settings,
        action="update",
        target=target,
        proposal=body.forward,
    )


@router.post(
    "/forwards/{target}/toggle", response_model=ChangeDetailOut, status_code=status.HTTP_201_CREATED
)
def stage_forward_toggle(
    request: Request,
    target: str,
    body: ForwardToggleCreate,
    user: CurrentUser = Depends(require_roles(*MANAGERS)),
    db: Session = Depends(get_db),
    settings: Settings = Depends(get_settings),
) -> ChangeDetailOut:
    """Stage enabling or disabling a port forward."""
    return _stage_forward(
        request,
        body.firewall_id,
        user,
        db,
        settings,
        action="toggle",
        target=target,
        enabled=body.enabled,
    )


@router.post(
    "/forwards/{target}/delete", response_model=ChangeDetailOut, status_code=status.HTTP_201_CREATED
)
def stage_forward_delete(
    request: Request,
    target: str,
    body: ForwardDeleteCreate,
    user: CurrentUser = Depends(require_roles(*MANAGERS)),
    db: Session = Depends(get_db),
    settings: Settings = Depends(get_settings),
) -> ChangeDetailOut:
    """Stage deleting a port forward. Always high risk."""
    return _stage_forward(
        request, body.firewall_id, user, db, settings, action="delete", target=target
    )


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
    return [_visible(_out(cr), _user) for cr in db.scalars(query)]


@router.get("/{change_id}", response_model=ChangeDetailOut)
def get_change(
    change_id: uuid.UUID,
    _user: CurrentUser = Depends(require_roles(*ALL_ROLES)),
    db: Session = Depends(get_db),
) -> ChangeDetailOut:
    return _visible(_detail(db, _get(db, change_id)), _user)


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
        run = {
            "rule": apply_changes.apply_rule_change,
            "nat_forward": apply_changes.apply_forward_change,
            "dnsmasq_host": apply_changes.apply_host_change,
            "dnsmasq_domain": apply_changes.apply_domain_change,
            "unbound_host": apply_changes.apply_unbound_host_change,
        }.get(cr.kind, apply_changes.apply_alias_change)
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


class HostCreate(BaseModel):
    model_config = ConfigDict(extra="forbid")

    firewall_id: uuid.UUID
    host: HostProposal


class HostDeleteCreate(BaseModel):
    model_config = ConfigDict(extra="forbid")

    firewall_id: uuid.UUID


def firewall_identity(fw: Firewall) -> tuple[frozenset[str], str | None]:
    """The firewall's own address or host name, as far as the stored URL tells us."""
    name = urlsplit(fw.base_url).hostname
    if not name:
        return frozenset(), None
    try:
        return frozenset({str(ipaddress.ip_address(name))}), None
    except ValueError:
        return frozenset(), name.split(".")[0]


def _host_label(h: Any) -> str:
    return (h.description or h.host or str(h.uuid)[:8])[:64]


def _stage_host(
    request: Request,
    firewall_id: uuid.UUID,
    user: CurrentUser,
    db: Session,
    settings: Settings,
    *,
    action: str,
    target: str | None,
    proposal: HostProposal | None = None,
) -> ChangeDetailOut:
    """Shared staging for create, update and delete of a Dnsmasq static host (ADR-0017). Reads the
    hosts read-only; nothing is written to the firewall."""
    audit_action = f"change.stage_host_{action}"
    if target is not None and not _is_uuid(target):
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_CONTENT, "Invalid host id")

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
        rows = apply_changes.read_hosts(
            db, firewall=fw, user=user, settings=settings, request=request
        )
    except FirewallError, CredentialDecryptionError:
        raise refuse("Could not read the host entries from the firewall") from None

    current = next((h for h in rows if h.uuid == target), None) if target else None
    if target is not None and current is None:
        raise refuse("That host entry was not found on the firewall")
    addresses, hostname = firewall_identity(fw)

    proposed: dict[str, Any]
    if proposal is not None:
        clash = apply_changes.host_conflict(proposal.model_dump(), rows, target)
        if clash:
            raise refuse(clash)
        reasons = proposal.risk_reasons(addresses, hostname)
        proposed = {**proposal.model_dump(), "label": proposal.description, "risk": reasons}
        if action == "update" and current is not None:
            proposed["label"] = _host_label(current)
    elif action == "delete" and current is not None:
        reasons = ["deletes a host entry"]
        proposed = {
            "label": _host_label(current),
            "host": current.host,
            "domain": current.domain,
            "description": current.description or "",
            "risk": reasons,
        }
    else:
        raise refuse("Unsupported request")

    if action == "create":
        clash_expr = ChangeRequest.proposed["description"].astext == proposed["description"]
        duplicate = db.scalar(
            select(ChangeRequest.id).where(
                ChangeRequest.firewall_id == firewall_id,
                ChangeRequest.kind == "dnsmasq_host",
                ChangeRequest.action == "create",
                clash_expr,
                ChangeRequest.status.in_(OPEN_STATES),
            )
        )
    else:
        duplicate = db.scalar(
            select(ChangeRequest.id).where(
                ChangeRequest.firewall_id == firewall_id,
                ChangeRequest.kind == "dnsmasq_host",
                ChangeRequest.target_uuid == target,
                ChangeRequest.status.in_(OPEN_STATES),
            )
        )
    if duplicate is not None:
        raise refuse("An open request already changes this host entry", duplicate)

    try:
        cr = service.create_draft(
            db,
            user=user,
            firewall_id=firewall_id,
            kind="dnsmasq_host",
            action=action,
            target_uuid=target,
            proposed=proposed,
            base_snapshot=current.model_dump() if current is not None else None,
            high_risk=bool(reasons) or action == "delete",
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


@router.post("/dnsmasq-hosts", response_model=ChangeDetailOut, status_code=201)
def stage_host_create(
    request: Request,
    body: HostCreate,
    user: CurrentUser = Depends(require_roles(*MANAGERS)),
    db: Session = Depends(get_db),
    settings: Settings = Depends(get_settings),
) -> ChangeDetailOut:
    """Stage a new Dnsmasq static host."""
    return _stage_host(
        request,
        body.firewall_id,
        user,
        db,
        settings,
        action="create",
        target=None,
        proposal=body.host,
    )


@router.post("/dnsmasq-hosts/{target}/update", response_model=ChangeDetailOut, status_code=201)
def stage_host_update(
    request: Request,
    target: str,
    body: HostCreate,
    user: CurrentUser = Depends(require_roles(*MANAGERS)),
    db: Session = Depends(get_db),
    settings: Settings = Depends(get_settings),
) -> ChangeDetailOut:
    """Stage editing a Dnsmasq static host."""
    return _stage_host(
        request,
        body.firewall_id,
        user,
        db,
        settings,
        action="update",
        target=target,
        proposal=body.host,
    )


@router.post("/dnsmasq-hosts/{target}/delete", response_model=ChangeDetailOut, status_code=201)
def stage_host_delete(
    request: Request,
    target: str,
    body: HostDeleteCreate,
    user: CurrentUser = Depends(require_roles(*MANAGERS)),
    db: Session = Depends(get_db),
    settings: Settings = Depends(get_settings),
) -> ChangeDetailOut:
    """Stage deleting a Dnsmasq static host. Always high risk."""
    return _stage_host(
        request, body.firewall_id, user, db, settings, action="delete", target=target
    )


class DomainCreate(BaseModel):
    model_config = ConfigDict(extra="forbid")

    firewall_id: uuid.UUID
    override: DomainProposal


def _stage_domain(
    request: Request,
    firewall_id: uuid.UUID,
    user: CurrentUser,
    db: Session,
    settings: Settings,
    *,
    action: str,
    target: str | None,
    proposal: DomainProposal | None = None,
) -> ChangeDetailOut:
    """Shared staging for create, update and delete of a Dnsmasq domain override (ADR-0017).
    Every override is high risk. Reads the overrides read-only; nothing is written."""
    audit_action = f"change.stage_domain_{action}"
    if target is not None and not _is_uuid(target):
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_CONTENT, "Invalid override id")

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
        rows = apply_changes.read_domains(
            db, firewall=fw, user=user, settings=settings, request=request
        )
    except FirewallError, CredentialDecryptionError:
        raise refuse("Could not read the domain overrides from the firewall") from None

    current = next((d for d in rows if d.uuid == target), None) if target else None
    if target is not None and current is None:
        raise refuse("That domain override was not found on the firewall")

    proposed: dict[str, Any]
    if proposal is not None:
        clash = apply_changes.domain_conflict(proposal.model_dump(), rows, target)
        if clash:
            raise refuse(clash)
        proposed = {
            **proposal.model_dump(),
            "label": proposal.description,
            "risk": proposal.risk_reasons(),
        }
        if action == "update" and current is not None:
            proposed["label"] = (current.description or current.domain or "override")[:64]
    elif action == "delete" and current is not None:
        proposed = {
            "label": (current.description or current.domain or "override")[:64],
            "domain": current.domain,
            "description": current.description or "",
            "risk": [f"removes the override for {current.domain}"],
        }
    else:
        raise refuse("Unsupported request")

    duplicate = db.scalar(
        select(ChangeRequest.id).where(
            ChangeRequest.firewall_id == firewall_id,
            ChangeRequest.kind == "dnsmasq_domain",
            ChangeRequest.status.in_(OPEN_STATES),
            (
                ChangeRequest.proposed["domain"].astext == proposed["domain"]
                if action == "create"
                else ChangeRequest.target_uuid == target
            ),
        )
    )
    if duplicate is not None:
        raise refuse("An open request already changes this domain override", duplicate)

    try:
        cr = service.create_draft(
            db,
            user=user,
            firewall_id=firewall_id,
            kind="dnsmasq_domain",
            action=action,
            target_uuid=target,
            proposed=proposed,
            base_snapshot=current.model_dump() if current is not None else None,
            high_risk=True,
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


@router.post("/dnsmasq-domains", response_model=ChangeDetailOut, status_code=201)
def stage_domain_create(
    request: Request,
    body: DomainCreate,
    user: CurrentUser = Depends(require_roles(*MANAGERS)),
    db: Session = Depends(get_db),
    settings: Settings = Depends(get_settings),
) -> ChangeDetailOut:
    """Stage a new Dnsmasq domain override. Always high risk."""
    return _stage_domain(
        request,
        body.firewall_id,
        user,
        db,
        settings,
        action="create",
        target=None,
        proposal=body.override,
    )


@router.post("/dnsmasq-domains/{target}/update", response_model=ChangeDetailOut, status_code=201)
def stage_domain_update(
    request: Request,
    target: str,
    body: DomainCreate,
    user: CurrentUser = Depends(require_roles(*MANAGERS)),
    db: Session = Depends(get_db),
    settings: Settings = Depends(get_settings),
) -> ChangeDetailOut:
    """Stage editing a Dnsmasq domain override. Always high risk."""
    return _stage_domain(
        request,
        body.firewall_id,
        user,
        db,
        settings,
        action="update",
        target=target,
        proposal=body.override,
    )


@router.post("/dnsmasq-domains/{target}/delete", response_model=ChangeDetailOut, status_code=201)
def stage_domain_delete(
    request: Request,
    target: str,
    body: HostDeleteCreate,
    user: CurrentUser = Depends(require_roles(*MANAGERS)),
    db: Session = Depends(get_db),
    settings: Settings = Depends(get_settings),
) -> ChangeDetailOut:
    """Stage deleting a Dnsmasq domain override. Always high risk."""
    return _stage_domain(
        request, body.firewall_id, user, db, settings, action="delete", target=target
    )


class UnboundHostCreate(BaseModel):
    model_config = ConfigDict(extra="forbid")

    firewall_id: uuid.UUID
    host: UnboundHostProposal


def _unbound_label(h: Any) -> str:
    return (h.description or h.hostname or str(h.uuid)[:8])[:64]


def _stage_unbound_host(
    request: Request,
    firewall_id: uuid.UUID,
    user: CurrentUser,
    db: Session,
    settings: Settings,
    *,
    action: str,
    target: str | None,
    proposal: UnboundHostProposal | None = None,
    enabled: bool | None = None,
) -> ChangeDetailOut:
    """Shared staging for create, update, toggle and delete of an Unbound host override
    (ADR-0018). Reads the hosts read-only; nothing is written to the firewall."""
    audit_action = f"change.stage_unbound_host_{action}"
    if target is not None and not _is_uuid(target):
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_CONTENT, "Invalid host id")

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
        rows = apply_changes.read_unbound_hosts(
            db, firewall=fw, user=user, settings=settings, request=request
        )
    except FirewallError, CredentialDecryptionError:
        raise refuse("Could not read the host overrides from the firewall") from None

    current = next((h for h in rows if h.uuid == target), None) if target else None
    if target is not None and current is None:
        raise refuse("That host override was not found on the firewall")
    if current is not None and not current.editable:
        raise refuse(f"{current.rr} records cannot be changed here; use OPNsense")
    addresses, hostname = firewall_identity(fw)

    proposed: dict[str, Any]
    if proposal is not None:
        clash = apply_changes.unbound_host_conflict(proposal.model_dump(), rows, target)
        if clash:
            raise refuse(clash)
        reasons = proposal.risk_reasons(addresses, hostname)
        proposed = {**proposal.model_dump(), "label": proposal.description, "risk": reasons}
        if action == "update" and current is not None:
            proposed["label"] = _unbound_label(current)
    elif action == "toggle" and current is not None and enabled is not None:
        if current.enabled == enabled:
            raise refuse("The host override is already " + ("enabled" if enabled else "disabled"))
        reasons = []
        proposed = {
            "label": _unbound_label(current),
            "enabled": enabled,
            "hostname": current.hostname,
            "domain": current.domain,
            "description": current.description or "",
            "risk": reasons,
        }
    elif action == "delete" and current is not None:
        reasons = ["deletes a host override"]
        proposed = {
            "label": _unbound_label(current),
            "hostname": current.hostname,
            "domain": current.domain,
            "description": current.description or "",
            "risk": reasons,
        }
    else:
        raise refuse("Unsupported request")

    if action == "create":
        same = ChangeRequest.proposed["description"].astext == proposed["description"]
    else:
        same = ChangeRequest.target_uuid == target
    duplicate = db.scalar(
        select(ChangeRequest.id).where(
            ChangeRequest.firewall_id == firewall_id,
            ChangeRequest.kind == "unbound_host",
            ChangeRequest.status.in_(OPEN_STATES),
            same,
            *([ChangeRequest.action == "create"] if action == "create" else []),
        )
    )
    if duplicate is not None:
        raise refuse("An open request already changes this host override", duplicate)

    try:
        cr = service.create_draft(
            db,
            user=user,
            firewall_id=firewall_id,
            kind="unbound_host",
            action=action,
            target_uuid=target,
            proposed=proposed,
            base_snapshot=current.model_dump() if current is not None else None,
            high_risk=bool(reasons) or action == "delete",
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


@router.post("/unbound-hosts", response_model=ChangeDetailOut, status_code=201)
def stage_unbound_host_create(
    request: Request,
    body: UnboundHostCreate,
    user: CurrentUser = Depends(require_roles(*MANAGERS)),
    db: Session = Depends(get_db),
    settings: Settings = Depends(get_settings),
) -> ChangeDetailOut:
    """Stage a new Unbound host override (A or AAAA)."""
    return _stage_unbound_host(
        request,
        body.firewall_id,
        user,
        db,
        settings,
        action="create",
        target=None,
        proposal=body.host,
    )


@router.post("/unbound-hosts/{target}/update", response_model=ChangeDetailOut, status_code=201)
def stage_unbound_host_update(
    request: Request,
    target: str,
    body: UnboundHostCreate,
    user: CurrentUser = Depends(require_roles(*MANAGERS)),
    db: Session = Depends(get_db),
    settings: Settings = Depends(get_settings),
) -> ChangeDetailOut:
    """Stage editing an Unbound host override."""
    return _stage_unbound_host(
        request,
        body.firewall_id,
        user,
        db,
        settings,
        action="update",
        target=target,
        proposal=body.host,
    )


@router.post("/unbound-hosts/{target}/toggle", response_model=ChangeDetailOut, status_code=201)
def stage_unbound_host_toggle(
    request: Request,
    target: str,
    body: ForwardToggleCreate,
    user: CurrentUser = Depends(require_roles(*MANAGERS)),
    db: Session = Depends(get_db),
    settings: Settings = Depends(get_settings),
) -> ChangeDetailOut:
    """Stage enabling or disabling an Unbound host override."""
    return _stage_unbound_host(
        request,
        body.firewall_id,
        user,
        db,
        settings,
        action="toggle",
        target=target,
        enabled=body.enabled,
    )


@router.post("/unbound-hosts/{target}/delete", response_model=ChangeDetailOut, status_code=201)
def stage_unbound_host_delete(
    request: Request,
    target: str,
    body: HostDeleteCreate,
    user: CurrentUser = Depends(require_roles(*MANAGERS)),
    db: Session = Depends(get_db),
    settings: Settings = Depends(get_settings),
) -> ChangeDetailOut:
    """Stage deleting an Unbound host override. Always high risk."""
    return _stage_unbound_host(
        request, body.firewall_id, user, db, settings, action="delete", target=target
    )
