"""User management (ADR-0013): admin-only account administration and self-service password
change. Temporary passwords are shown once and never logged or audited."""

import secrets
import uuid
from datetime import datetime

from fastapi import APIRouter, Depends, HTTPException, Request, status
from pydantic import BaseModel, ConfigDict, Field, field_validator
from sqlalchemy import func, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from app import audit
from app.auth import mfa, sessions, throttle
from app.auth.account import fail, guard_attempt, ok
from app.auth.deps import ALL_ROLES, CurrentUser, get_db, require_roles
from app.auth.security import (
    PASSWORD_MAX_LENGTH,
    PasswordPolicyError,
    hash_password,
    validate_password,
    validate_username,
    verify_password,
)
from app.core.config import Settings, get_settings
from app.db.models import Role, User
from app.db.models import Session as UserSession

router = APIRouter(prefix="/api/v1/users", tags=["users"])
password_router = APIRouter(prefix="/api/v1/auth", tags=["auth"])

TEMP_PASSWORD_LENGTH = 20
_ALPHABET = "ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnpqrstuvwxyz23456789"
_Admin = require_roles(Role.admin)


class UserRowOut(BaseModel):
    id: uuid.UUID
    username: str
    role: Role
    is_active: bool
    mfa_enabled: bool
    must_change_password: bool
    created_at: datetime
    sessions: int


class UserCreateIn(BaseModel):
    model_config = ConfigDict(extra="forbid")

    username: str = Field(min_length=1, max_length=64)
    role: Role

    @field_validator("username")
    @classmethod
    def _valid(cls, value: str) -> str:
        return validate_username(value)


class RoleIn(BaseModel):
    model_config = ConfigDict(extra="forbid")

    role: Role


class ConfirmIn(BaseModel):
    """The acting admin re-proves their identity for sensitive steps."""

    model_config = ConfigDict(extra="forbid")

    password: str = Field(min_length=1, max_length=PASSWORD_MAX_LENGTH)
    code: str | None = Field(default=None, min_length=1, max_length=32)


class TempPasswordOut(BaseModel):
    user: UserRowOut
    temporary_password: str


class PasswordChangeIn(BaseModel):
    model_config = ConfigDict(extra="forbid")

    current_password: str = Field(min_length=1, max_length=PASSWORD_MAX_LENGTH)
    new_password: str = Field(min_length=1, max_length=PASSWORD_MAX_LENGTH)
    code: str | None = Field(default=None, min_length=1, max_length=32)

    @field_validator("new_password")
    @classmethod
    def _policy(cls, value: str) -> str:
        try:
            return validate_password(value)
        except PasswordPolicyError as exc:
            raise ValueError(str(exc)) from None


def temporary_password() -> str:
    return "".join(secrets.choice(_ALPHABET) for _ in range(TEMP_PASSWORD_LENGTH))


def _row(db: Session, user: User) -> UserRowOut:
    count = db.scalar(
        select(func.count()).select_from(UserSession).where(UserSession.user_id == user.id)
    )
    return UserRowOut(
        id=user.id,
        username=user.username,
        role=user.role,
        is_active=user.is_active,
        mfa_enabled=user.mfa_enabled,
        must_change_password=user.must_change_password,
        created_at=user.created_at,
        sessions=int(count or 0),
    )


def _target(db: Session, user_id: uuid.UUID) -> User:
    row = db.get(User, user_id)
    if row is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "No such user")
    return row


def _lock_admins(db: Session) -> int:
    """Lock the active admin rows for this transaction and return how many there are, so two
    concurrent changes cannot both remove the last admin."""
    ids = db.execute(
        select(User.id).where(User.role == Role.admin, User.is_active.is_(True)).with_for_update()
    ).all()
    return len(ids)


def _protect_admins(
    db: Session, request: Request, actor: CurrentUser, target: User, action: str
) -> None:
    """Refuse a change that would remove an active admin when it is the actor, or the last one."""
    if not (target.role == Role.admin and target.is_active):
        return
    reason = None
    if target.id == actor.id:
        reason = "self"
    elif _lock_admins(db) <= 1:
        reason = "last_admin"
    if reason is None:
        return
    audit.record(
        db,
        action=action,
        outcome=audit.OUTCOME_DENIED,
        user_id=actor.id,
        username=actor.username,
        detail={"target": target.username, "reason": reason},
        request=request,
    )
    message = (
        "You cannot do this to your own account"
        if reason == "self"
        else "The last active administrator cannot be changed"
    )
    raise HTTPException(status.HTTP_409_CONFLICT, message)


def _not_self(db: Session, request: Request, actor: CurrentUser, target: User, action: str) -> None:
    if target.id != actor.id:
        return
    audit.record(
        db,
        action=action,
        outcome=audit.OUTCOME_DENIED,
        user_id=actor.id,
        username=actor.username,
        detail={"target": target.username, "reason": "self"},
        request=request,
    )
    raise HTTPException(status.HTTP_409_CONFLICT, "Use your Account page for your own login")


def _audit(
    db: Session, request: Request, actor: CurrentUser, action: str, target: User, **extra: str
) -> None:
    audit.add(
        db,
        action=action,
        outcome=audit.OUTCOME_SUCCESS,
        user_id=actor.id,
        username=actor.username,
        detail={"target": target.username, **extra},
        request=request,
    )


@router.get("", response_model=list[UserRowOut])
def list_users(
    user: CurrentUser = Depends(_Admin), db: Session = Depends(get_db)
) -> list[UserRowOut]:
    counts = {
        uid: int(n)
        for uid, n in db.execute(
            select(UserSession.user_id, func.count()).group_by(UserSession.user_id)
        ).all()
    }
    rows = db.scalars(select(User).order_by(User.username)).all()
    return [
        UserRowOut(
            id=u.id,
            username=u.username,
            role=u.role,
            is_active=u.is_active,
            mfa_enabled=u.mfa_enabled,
            must_change_password=u.must_change_password,
            created_at=u.created_at,
            sessions=int(counts.get(u.id, 0)),
        )
        for u in rows
    ]


@router.post("", response_model=TempPasswordOut, status_code=status.HTTP_201_CREATED)
def create_user(
    request: Request,
    body: UserCreateIn,
    actor: CurrentUser = Depends(_Admin),
    db: Session = Depends(get_db),
) -> TempPasswordOut:
    password = temporary_password()
    target = User(
        username=body.username,
        role=body.role,
        password_hash=hash_password(password),
        must_change_password=True,
    )
    db.add(target)
    try:
        db.flush()
    except IntegrityError:
        db.rollback()
        raise HTTPException(status.HTTP_409_CONFLICT, "That username is taken") from None
    _audit(db, request, actor, "user.create", target, role=body.role.value)
    db.commit()
    db.refresh(target)
    return TempPasswordOut(user=_row(db, target), temporary_password=password)


@router.post("/{user_id}/role", response_model=UserRowOut)
def change_role(
    request: Request,
    user_id: uuid.UUID,
    body: RoleIn,
    actor: CurrentUser = Depends(_Admin),
    db: Session = Depends(get_db),
) -> UserRowOut:
    target = _target(db, user_id)
    if body.role == target.role:
        return _row(db, target)
    _protect_admins(db, request, actor, target, "user.role_change")
    old = target.role.value
    target.role = body.role
    ended = sessions.revoke_user_sessions(db, target.id)
    _audit(
        db,
        request,
        actor,
        "user.role_change",
        target,
        old_role=old,
        new_role=body.role.value,
        sessions_ended=str(ended),
    )
    db.commit()
    return _row(db, target)


@router.post("/{user_id}/deactivate", response_model=UserRowOut)
def deactivate(
    request: Request,
    user_id: uuid.UUID,
    actor: CurrentUser = Depends(_Admin),
    db: Session = Depends(get_db),
) -> UserRowOut:
    target = _target(db, user_id)
    if not target.is_active:
        return _row(db, target)
    _protect_admins(db, request, actor, target, "user.deactivate")
    target.is_active = False
    ended = sessions.revoke_user_sessions(db, target.id)
    _audit(db, request, actor, "user.deactivate", target, sessions_ended=str(ended))
    db.commit()
    return _row(db, target)


@router.post("/{user_id}/reactivate", response_model=UserRowOut)
def reactivate(
    request: Request,
    user_id: uuid.UUID,
    actor: CurrentUser = Depends(_Admin),
    db: Session = Depends(get_db),
) -> UserRowOut:
    target = _target(db, user_id)
    if not target.is_active:
        target.is_active = True
        _audit(db, request, actor, "user.reactivate", target)
        db.commit()
    return _row(db, target)


@router.post("/{user_id}/reset-password", response_model=TempPasswordOut)
def reset_password(
    request: Request,
    user_id: uuid.UUID,
    actor: CurrentUser = Depends(_Admin),
    db: Session = Depends(get_db),
) -> TempPasswordOut:
    target = _target(db, user_id)
    _not_self(db, request, actor, target, "user.password_reset")
    password = temporary_password()
    target.password_hash = hash_password(password)
    target.must_change_password = True
    ended = sessions.revoke_user_sessions(db, target.id)
    _audit(db, request, actor, "user.password_reset", target, sessions_ended=str(ended))
    db.commit()
    return TempPasswordOut(user=_row(db, target), temporary_password=password)


@router.post("/{user_id}/reset-mfa", response_model=UserRowOut)
def reset_user_mfa(
    request: Request,
    user_id: uuid.UUID,
    body: ConfirmIn,
    actor: CurrentUser = Depends(_Admin),
    db: Session = Depends(get_db),
    settings: Settings = Depends(get_settings),
) -> UserRowOut:
    target = _target(db, user_id)
    _not_self(db, request, actor, target, "user.mfa_reset")
    me = _target(db, actor.id)
    guard_attempt(db, request, me, "user.mfa_reset")
    if not verify_password(me.password_hash, body.password):
        raise fail(
            db, request, settings, me, "user.mfa_reset", "wrong_password", "Wrong password or code"
        )
    if me.mfa_enabled and (
        body.code is None or mfa.check_code(db, settings, me, body.code) is None
    ):
        raise fail(
            db, request, settings, me, "user.mfa_reset", "invalid_code", "Wrong password or code"
        )
    throttle.clear(db, me.username)
    mfa.clear_mfa(db, target)
    ended = sessions.revoke_user_sessions(db, target.id)
    _audit(db, request, actor, "user.mfa_reset", target, sessions_ended=str(ended))
    db.commit()
    return _row(db, target)


@password_router.post("/password", status_code=status.HTTP_204_NO_CONTENT)
def change_password(
    request: Request,
    body: PasswordChangeIn,
    user: CurrentUser = Depends(
        require_roles(*ALL_ROLES, allow_restricted=True, allow_password_pending=True)
    ),
    db: Session = Depends(get_db),
    settings: Settings = Depends(get_settings),
) -> None:
    row = _target(db, user.id)
    guard_attempt(db, request, row, "auth.password_change")
    if not verify_password(row.password_hash, body.current_password):
        raise fail(
            db,
            request,
            settings,
            row,
            "auth.password_change",
            "wrong_password",
            "Wrong password or code",
        )
    if row.mfa_enabled and (
        body.code is None or mfa.check_code(db, settings, row, body.code) is None
    ):
        raise fail(
            db,
            request,
            settings,
            row,
            "auth.password_change",
            "invalid_code",
            "Wrong password or code",
        )
    if body.new_password == body.current_password:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_CONTENT, "Choose a different password")
    throttle.clear(db, row.username)
    row.password_hash = hash_password(body.new_password)
    row.must_change_password = False
    ended = sessions.revoke_user_sessions(db, row.id, except_session_id=user.session_id)
    ok(db, request, row, "auth.password_change", other_sessions_ended=ended)
    db.commit()
