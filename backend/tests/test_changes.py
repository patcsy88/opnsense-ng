"""Change request status machine and service (ADR-0005). No OPNsense calls."""

import uuid
from collections.abc import Iterator

import pytest
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.auth.deps import CurrentUser
from app.changes import service
from app.changes.fingerprint import fingerprint
from app.changes.states import TERMINAL, TRANSITIONS, Status, can_transition
from app.db.models import AuditLog, ChangeRequest, Firewall, Role, User
from app.main import create_app


def test_every_status_has_a_transition_entry() -> None:
    assert set(TRANSITIONS) == set(Status)


def test_terminal_states_allow_nothing() -> None:
    assert {Status.applied, Status.rejected, Status.cancelled, Status.failed, Status.stale} == set(
        TERMINAL
    )
    for status in TERMINAL:
        assert all(not can_transition(status, other) for other in Status)


def test_cannot_skip_review_or_apply_without_approval() -> None:
    assert not can_transition(Status.draft, Status.approved)
    assert not can_transition(Status.validated, Status.approved)
    assert not can_transition(Status.in_review, Status.applying)
    assert not can_transition(Status.draft, Status.applied)
    assert can_transition(Status.approved, Status.applying)


def test_fingerprint_is_stable_and_sensitive() -> None:
    a = {"name": "x", "content": ["1", "2"]}
    assert fingerprint(a) == fingerprint({"content": ["1", "2"], "name": "x"})
    assert fingerprint(a) != fingerprint({"name": "x", "content": ["2", "1"]})
    assert len(fingerprint(a)) == 64


def user(db: Session, role: Role, name: str | None = None) -> CurrentUser:
    row = User(username=name or role.value, password_hash="x", role=role)
    db.add(row)
    db.flush()
    return CurrentUser(id=row.id, username=row.username, role=role, session_id=uuid.uuid4())


@pytest.fixture
def session(db: None) -> Iterator[Session]:
    app = create_app()
    with app.state.sessionmaker() as s:
        yield s
    app.state.engine.dispose()


def make_firewall(db: Session, *, allow_writes: bool = False) -> Firewall:
    fw = Firewall(
        name=f"fw-{uuid.uuid4().hex[:8]}",
        base_url="https://fw.example.test",
        api_key_encrypted="x",
        api_secret_encrypted="x",
        allow_writes=allow_writes,
    )
    db.add(fw)
    db.flush()
    return fw


def draft(db: Session, fw: Firewall, requester: CurrentUser, **kw: object) -> ChangeRequest:
    args: dict[str, object] = {
        "firewall_id": fw.id,
        "kind": "alias",
        "action": "create",
        "target_uuid": None,
        "proposed": {"name": "test_hosts", "type": "host", "content": ["10.0.0.1"]},
        "base_snapshot": None,
    }
    args.update(kw)
    return service.create_draft(db, user=requester, **args)  # type: ignore[arg-type]


def walk_to_review(db: Session, cr: ChangeRequest, requester: CurrentUser) -> None:
    service.transition(db, cr, Status.validated, user=requester)
    service.transition(db, cr, Status.in_review, user=requester)


def test_draft_creates_event_and_audit(session: Session) -> None:
    fw = make_firewall(session)
    nadmin = user(session, Role.network_admin)
    cr = draft(session, fw, nadmin)
    session.commit()
    assert cr.status == "draft" and cr.requester_username == "network_admin"
    events = service.list_events(session, cr)
    assert [(e.from_status, e.to_status) for e in events] == [(None, "draft")]
    actions = [a.action for a in session.scalars(select(AuditLog))]
    assert "change.draft" in actions


@pytest.mark.parametrize("role", [Role.read_only, Role.security_admin])
def test_view_only_roles_cannot_create(session: Session, role: Role) -> None:
    fw = make_firewall(session)
    with pytest.raises(service.NotPermitted):
        draft(session, fw, user(session, role))


def test_update_requires_target_and_bad_kind_is_rejected(session: Session) -> None:
    fw = make_firewall(session)
    nadmin = user(session, Role.network_admin)
    with pytest.raises(service.ChangeError):
        draft(session, fw, nadmin, action="update", target_uuid=None)
    with pytest.raises(service.ChangeError):
        draft(session, fw, nadmin, kind="nat")
    with pytest.raises(service.ChangeError):
        draft(session, fw, nadmin, firewall_id=uuid.uuid4())


def test_snapshot_fingerprint_is_stored(session: Session) -> None:
    fw = make_firewall(session)
    snap = {"name": "a", "content": ["1"]}
    cr = draft(
        session,
        fw,
        user(session, Role.admin),
        action="update",
        target_uuid="u1",
        base_snapshot=snap,
    )
    assert cr.base_fingerprint == fingerprint(snap)


def test_invalid_transition_is_refused_and_leaves_status(session: Session) -> None:
    fw = make_firewall(session)
    nadmin = user(session, Role.network_admin)
    cr = draft(session, fw, nadmin)
    with pytest.raises(service.InvalidTransition):
        service.transition(session, cr, Status.approved, user=nadmin)
    assert cr.status == "draft"


def test_network_admin_cannot_approve_own_request(session: Session) -> None:
    fw = make_firewall(session)
    nadmin = user(session, Role.network_admin)
    cr = draft(session, fw, nadmin)
    walk_to_review(session, cr, nadmin)
    with pytest.raises(service.NotPermitted):
        service.transition(session, cr, Status.approved, user=nadmin)
    other = user(session, Role.network_admin, "other")
    service.transition(session, cr, Status.approved, user=other)
    assert cr.status == "approved" and cr.self_approved is False
    assert cr.reviewer_username == "other"


def test_admin_may_approve_own_request_and_it_is_flagged(session: Session) -> None:
    fw = make_firewall(session)
    admin = user(session, Role.admin)
    cr = draft(session, fw, admin)
    walk_to_review(session, cr, admin)
    service.transition(session, cr, Status.approved, user=admin)
    session.commit()
    assert cr.self_approved is True
    row = session.scalars(select(AuditLog).where(AuditLog.action == "change.approved")).one()
    assert row.detail is not None and row.detail["self_approved"] is True


def test_high_risk_needs_admin_approver(session: Session) -> None:
    fw = make_firewall(session)
    requester = user(session, Role.network_admin)
    cr = draft(session, fw, requester, high_risk=True)
    walk_to_review(session, cr, requester)
    with pytest.raises(service.NotPermitted):
        service.transition(
            session, cr, Status.approved, user=user(session, Role.network_admin, "peer")
        )
    service.transition(session, cr, Status.approved, user=user(session, Role.admin))
    assert cr.status == "approved"


def test_only_requester_or_admin_can_move_a_draft(session: Session) -> None:
    fw = make_firewall(session)
    requester = user(session, Role.network_admin)
    cr = draft(session, fw, requester)
    with pytest.raises(service.NotPermitted):
        service.transition(
            session, cr, Status.validated, user=user(session, Role.network_admin, "peer")
        )
    with pytest.raises(service.NotPermitted):
        service.transition(session, cr, Status.validated, user=user(session, Role.read_only))
    service.transition(session, cr, Status.validated, user=user(session, Role.admin))
    assert cr.status == "validated"


def test_cancel_by_requester_or_admin_only(session: Session) -> None:
    fw = make_firewall(session)
    requester = user(session, Role.network_admin)
    cr = draft(session, fw, requester)
    with pytest.raises(service.NotPermitted):
        service.transition(
            session, cr, Status.cancelled, user=user(session, Role.network_admin, "peer")
        )
    service.transition(session, cr, Status.cancelled, user=requester, note="no longer needed")
    assert cr.status == "cancelled"
    with pytest.raises(service.InvalidTransition):
        service.transition(session, cr, Status.validated, user=requester)


def test_apply_needs_admin_and_allow_writes(session: Session) -> None:
    fw = make_firewall(session, allow_writes=False)
    admin = user(session, Role.admin)
    cr = draft(session, fw, admin)
    walk_to_review(session, cr, admin)
    service.transition(session, cr, Status.approved, user=admin)
    with pytest.raises(service.NotPermitted):  # writes switched off
        service.transition(session, cr, Status.applying, user=admin)
    fw.allow_writes = True
    session.flush()
    with pytest.raises(service.NotPermitted):  # not an admin
        service.transition(
            session, cr, Status.applying, user=user(session, Role.network_admin, "n")
        )
    service.transition(session, cr, Status.applying, user=admin)
    assert cr.status == "applying" and cr.applier_username == "admin"
    service.transition(session, cr, Status.applied, user=admin)
    assert cr.status == "applied"


def test_history_is_ordered_and_audit_rows_survive_firewall_delete(session: Session) -> None:
    fw = make_firewall(session)
    admin = user(session, Role.admin)
    cr = draft(session, fw, admin)
    walk_to_review(session, cr, admin)
    service.transition(session, cr, Status.rejected, user=admin, note="not needed")
    session.commit()
    assert [e.to_status for e in service.list_events(session, cr)] == [
        "draft",
        "validated",
        "in_review",
        "rejected",
    ]
    session.delete(fw)
    session.commit()
    assert session.scalars(select(ChangeRequest)).first() is None  # cascade
    assert len(list(session.scalars(select(AuditLog).where(AuditLog.action.like("change.%"))))) == 4
