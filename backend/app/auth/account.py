"""Self-service MFA enrolment and management (ADR-0012). Passwords and codes are verified on
every sensitive step; nothing secret is audited."""

from fastapi import APIRouter, Depends, HTTPException, Request, status
from pydantic import BaseModel, ConfigDict, Field
from sqlalchemy.orm import Session

from app import audit
from app.auth import mfa, sessions, throttle, totp
from app.auth.deps import ALL_ROLES, CurrentUser, get_db, require_roles
from app.auth.security import PASSWORD_MAX_LENGTH, verify_password
from app.core.config import Settings, get_settings
from app.db.models import User

router = APIRouter(prefix="/api/v1/auth/mfa", tags=["mfa"])

_Guard = require_roles(*ALL_ROLES, allow_restricted=True)


class MfaStatusOut(BaseModel):
    enabled: bool
    required: bool
    recovery_codes_left: int


class PasswordIn(BaseModel):
    model_config = ConfigDict(extra="forbid")

    password: str = Field(min_length=1, max_length=PASSWORD_MAX_LENGTH)


class CodeIn(BaseModel):
    model_config = ConfigDict(extra="forbid")

    code: str = Field(min_length=1, max_length=32)


class PasswordCodeIn(PasswordIn):
    code: str = Field(min_length=1, max_length=32)


class EnrolStartOut(BaseModel):
    secret: str
    otpauth_uri: str
    qr: list[list[bool]]


class RecoveryCodesOut(BaseModel):
    recovery_codes: list[str]


def _load(db: Session, user: CurrentUser) -> User:
    row = db.get(User, user.id)
    if row is None:  # the session join already proved the user exists
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Not authenticated")
    return row


def _guard_attempt(db: Session, request: Request, user: User, action: str) -> None:
    remaining = throttle.locked_seconds(db, user.username)
    if remaining:
        audit.record(
            db,
            action=action,
            outcome=audit.OUTCOME_DENIED,
            user_id=user.id,
            username=user.username,
            detail={"reason": "throttled"},
            request=request,
        )
        raise HTTPException(
            status.HTTP_429_TOO_MANY_REQUESTS,
            "Too many failed attempts. Try again later.",
            headers={"Retry-After": str(remaining)},
        )


def _fail(
    db: Session,
    request: Request,
    settings: Settings,
    user: User,
    action: str,
    reason: str,
    message: str,
) -> HTTPException:
    audit.add(
        db,
        action=action,
        outcome=audit.OUTCOME_FAILURE,
        user_id=user.id,
        username=user.username,
        detail={"reason": reason},
        request=request,
    )
    throttle.register_failure(db, settings, user.username)
    db.commit()
    return HTTPException(status.HTTP_401_UNAUTHORIZED, message)


def _ok(db: Session, request: Request, user: User, action: str, **detail: int | str) -> None:
    audit.add(
        db,
        action=action,
        outcome=audit.OUTCOME_SUCCESS,
        user_id=user.id,
        username=user.username,
        detail=dict(detail) or None,
        request=request,
    )


@router.get("", response_model=MfaStatusOut)
def mfa_status(
    user: CurrentUser = Depends(_Guard),
    db: Session = Depends(get_db),
    settings: Settings = Depends(get_settings),
) -> MfaStatusOut:
    return MfaStatusOut(
        enabled=user.mfa_enabled,
        required=mfa.is_required(settings, user.role.value),
        recovery_codes_left=mfa.recovery_remaining(db, user.id) if user.mfa_enabled else 0,
    )


@router.post("/enrol/start", response_model=EnrolStartOut)
def enrol_start(
    request: Request,
    body: PasswordIn,
    user: CurrentUser = Depends(_Guard),
    db: Session = Depends(get_db),
    settings: Settings = Depends(get_settings),
) -> EnrolStartOut:
    row = _load(db, user)
    if row.mfa_enabled:
        raise HTTPException(status.HTTP_409_CONFLICT, "MFA is already enabled")
    _guard_attempt(db, request, row, "mfa.enrol_start")
    if not verify_password(row.password_hash, body.password):
        raise _fail(
            db, request, settings, row, "mfa.enrol_start", "wrong_password", "Wrong password"
        )
    secret = totp.new_secret()
    mfa.store_secret(db, settings, row, secret)
    _ok(db, request, row, "mfa.enrol_start")
    db.commit()
    uri = totp.otpauth_uri(secret, row.username)
    return EnrolStartOut(secret=secret, otpauth_uri=uri, qr=totp.qr_matrix(uri))


@router.post("/enrol/confirm", response_model=RecoveryCodesOut)
def enrol_confirm(
    request: Request,
    body: CodeIn,
    user: CurrentUser = Depends(_Guard),
    db: Session = Depends(get_db),
    settings: Settings = Depends(get_settings),
) -> RecoveryCodesOut:
    row = _load(db, user)
    if row.mfa_enabled:
        raise HTTPException(status.HTTP_409_CONFLICT, "MFA is already enabled")
    if mfa.load_secret(settings, row) is None:
        raise HTTPException(status.HTTP_409_CONFLICT, "Start enrolment first")
    _guard_attempt(db, request, row, "mfa.enable")
    if mfa.check_code(db, settings, row, body.code, allow_recovery=False) is None:
        raise _fail(db, request, settings, row, "mfa.enable", "invalid_code", "Invalid code")
    row.mfa_enabled = True
    codes = mfa.replace_recovery_codes(db, row)
    ended = sessions.revoke_user_sessions(db, row.id, except_session_id=user.session_id)
    throttle.clear(db, row.username)
    _ok(db, request, row, "mfa.enable", other_sessions_ended=ended)
    db.commit()
    return RecoveryCodesOut(recovery_codes=codes)


def _verify_password_and_code(
    db: Session, request: Request, settings: Settings, row: User, body: PasswordCodeIn, action: str
) -> None:
    _guard_attempt(db, request, row, action)
    if not verify_password(row.password_hash, body.password):
        raise _fail(db, request, settings, row, action, "wrong_password", "Wrong password or code")
    if mfa.check_code(db, settings, row, body.code) is None:
        raise _fail(db, request, settings, row, action, "invalid_code", "Wrong password or code")
    throttle.clear(db, row.username)


@router.post("/disable", status_code=status.HTTP_204_NO_CONTENT)
def disable(
    request: Request,
    body: PasswordCodeIn,
    user: CurrentUser = Depends(_Guard),
    db: Session = Depends(get_db),
    settings: Settings = Depends(get_settings),
) -> None:
    row = _load(db, user)
    if not row.mfa_enabled:
        raise HTTPException(status.HTTP_409_CONFLICT, "MFA is not enabled")
    if mfa.is_required(settings, row.role.value):
        audit.record(
            db,
            action="mfa.disable",
            outcome=audit.OUTCOME_DENIED,
            user_id=row.id,
            username=row.username,
            detail={"reason": "required_for_role"},
            request=request,
        )
        raise HTTPException(status.HTTP_403_FORBIDDEN, "MFA is required for your role")
    _verify_password_and_code(db, request, settings, row, body, "mfa.disable")
    mfa.clear_mfa(db, row)
    ended = sessions.revoke_user_sessions(db, row.id, except_session_id=user.session_id)
    _ok(db, request, row, "mfa.disable", other_sessions_ended=ended)
    db.commit()


@router.post("/recovery-codes", response_model=RecoveryCodesOut)
def regenerate_recovery_codes(
    request: Request,
    body: PasswordCodeIn,
    user: CurrentUser = Depends(_Guard),
    db: Session = Depends(get_db),
    settings: Settings = Depends(get_settings),
) -> RecoveryCodesOut:
    row = _load(db, user)
    if not row.mfa_enabled:
        raise HTTPException(status.HTTP_409_CONFLICT, "MFA is not enabled")
    _verify_password_and_code(db, request, settings, row, body, "mfa.recovery_regenerate")
    codes = mfa.replace_recovery_codes(db, row)
    ended = sessions.revoke_user_sessions(db, row.id, except_session_id=user.session_id)
    _ok(db, request, row, "mfa.recovery_regenerate", other_sessions_ended=ended)
    db.commit()
    return RecoveryCodesOut(recovery_codes=codes)
