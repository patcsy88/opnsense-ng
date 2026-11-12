"""Change request lifecycle: creation and status transitions (ADR-0005).

Nothing here talks to OPNsense. Every transition is checked against the status machine and the
role policy, written together with its history event and audit record, and takes a row lock so
two actors cannot move the same request at once. Callers commit.
"""

import uuid
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session
from starlette.requests import Request

from app import audit
from app.auth.deps import CurrentUser
from app.changes.fingerprint import fingerprint
from app.changes.states import Status, can_transition
from app.db.models import ChangeRequest, ChangeRequestEvent, Firewall, Role

MANAGE_ROLES = frozenset({Role.admin, Role.network_admin})
KINDS = frozenset({"alias", "rule", "nat_forward"})
ACTIONS = frozenset({"create", "update", "delete", "toggle"})
NOTE_MAX = 500


class ChangeError(Exception):
    """Base class; the message is safe to show to the acting user."""


class InvalidTransition(ChangeError):
    pass


class NotPermitted(ChangeError):
    pass


def create_draft(
    db: Session,
    *,
    user: CurrentUser,
    firewall_id: uuid.UUID,
    kind: str,
    action: str,
    target_uuid: str | None,
    proposed: dict[str, Any] | None,
    base_snapshot: dict[str, Any] | None,
    high_risk: bool = False,
    request: Request | None = None,
) -> ChangeRequest:
    if user.role not in MANAGE_ROLES:
        raise NotPermitted("Your role cannot create change requests")
    if kind not in KINDS or action not in ACTIONS:
        raise ChangeError("Unsupported change kind or action")
    if action != "create" and not target_uuid:
        raise ChangeError("A target is required for this action")
    if db.get(Firewall, firewall_id) is None:
        raise ChangeError("Unknown firewall")
    cr = ChangeRequest(
        firewall_id=firewall_id,
        kind=kind,
        action=action,
        target_uuid=target_uuid,
        proposed=proposed,
        base_snapshot=base_snapshot,
        base_fingerprint=fingerprint(base_snapshot) if base_snapshot is not None else None,
        status=Status.draft.value,
        high_risk=high_risk,
        requester_id=user.id,
        requester_username=user.username,
    )
    db.add(cr)
    db.flush()
    _record(db, cr, user, None, Status.draft, None, request)
    return cr


def transition(
    db: Session,
    cr: ChangeRequest,
    to: Status,
    *,
    user: CurrentUser,
    note: str | None = None,
    request: Request | None = None,
) -> ChangeRequest:
    db.refresh(cr, with_for_update=True)
    current = Status(cr.status)
    if not can_transition(current, to):
        raise InvalidTransition(f"A {current.value} request cannot become {to.value}")
    _authorise(db, cr, to, user)
    if to is Status.approved:
        cr.reviewer_username = user.username
        cr.self_approved = user.id == cr.requester_id
    elif to in (Status.rejected,):
        cr.reviewer_username = user.username
    elif to is Status.applying:
        cr.applier_username = user.username
    cr.status = to.value
    _record(db, cr, user, current, to, note, request)
    # Flush so the lock-and-refresh at the start of the next transition sees this status.
    db.flush()
    return cr


def _authorise(db: Session, cr: ChangeRequest, to: Status, user: CurrentUser) -> None:
    role = user.role
    if to is Status.cancelled:
        if role is not Role.admin and not (role in MANAGE_ROLES and user.id == cr.requester_id):
            raise NotPermitted("Only the requester or an admin can cancel a request")
        return
    if to in (Status.applying, Status.applied, Status.failed, Status.stale):
        if role is not Role.admin:
            raise NotPermitted("Only an admin can apply changes")
        if to is Status.applying:
            firewall = db.get(Firewall, cr.firewall_id)
            if firewall is None or not firewall.allow_writes:
                raise NotPermitted("Writes are not enabled for this firewall")
        return
    if role not in MANAGE_ROLES:
        raise NotPermitted("Your role cannot manage change requests")
    if to is Status.approved:
        if cr.high_risk and role is not Role.admin:
            raise NotPermitted("A high-risk change needs an admin to approve it")
        if user.id == cr.requester_id and role is not Role.admin:
            raise NotPermitted("You cannot approve your own request")
    elif to in (Status.validated, Status.draft, Status.in_review):
        if user.id != cr.requester_id and role is not Role.admin:
            raise NotPermitted("Only the requester or an admin can move this request")


def _record(
    db: Session,
    cr: ChangeRequest,
    user: CurrentUser,
    previous: Status | None,
    to: Status,
    note: str | None,
    request: Request | None,
) -> None:
    db.add(
        ChangeRequestEvent(
            change_request_id=cr.id,
            actor_username=user.username,
            from_status=previous.value if previous else None,
            to_status=to.value,
            note=note[:NOTE_MAX] if note else None,
        )
    )
    audit.add(
        db,
        action=f"change.{to.value}",
        outcome=audit.OUTCOME_SUCCESS,
        user_id=user.id,
        username=user.username,
        firewall_id=cr.firewall_id,
        detail={
            "change_request": str(cr.id),
            "kind": cr.kind,
            "action": cr.action,
            "from": previous.value if previous else None,
            "to": to.value,
            "self_approved": cr.self_approved,
            "high_risk": cr.high_risk,
        },
        request=request,
    )


def list_events(db: Session, cr: ChangeRequest) -> list[ChangeRequestEvent]:
    return list(
        db.scalars(
            select(ChangeRequestEvent)
            .where(ChangeRequestEvent.change_request_id == cr.id)
            .order_by(ChangeRequestEvent.timestamp, ChangeRequestEvent.id)
        )
    )
