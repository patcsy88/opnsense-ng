from datetime import UTC, datetime, timedelta

from fastapi import APIRouter, Depends, HTTPException, Request, Response, status
from sqlalchemy import delete, select
from sqlalchemy.orm import Session

from app import audit
from app.auth.deps import (
    ALL_ROLES,
    CSRF_COOKIE,
    SESSION_COOKIE,
    CurrentUser,
    get_current_user,
    get_db,
    require_roles,
)
from app.auth.schemas import LoginRequest, LoginResponse, UserOut
from app.auth.security import hash_token, new_token, verify_password
from app.core.config import Settings, get_settings
from app.core.ratelimit import limiter, login_limit
from app.db.models import Session as UserSession
from app.db.models import User

router = APIRouter(prefix="/api/v1/auth", tags=["auth"])


def _set_cookies(response: Response, settings: Settings, session_token: str, csrf: str) -> None:
    max_age = settings.session_ttl_minutes * 60
    common = {
        "max_age": max_age,
        "secure": settings.cookie_secure,
        "samesite": "strict",
        "path": "/",
    }
    response.set_cookie(SESSION_COOKIE, session_token, httponly=True, **common)  # type: ignore[arg-type]
    # Readable by the PWA so it can echo it in X-CSRF-Token (double-submit).
    response.set_cookie(CSRF_COOKIE, csrf, httponly=False, **common)  # type: ignore[arg-type]


def _clear_cookies(response: Response) -> None:
    response.delete_cookie(SESSION_COOKIE, path="/")
    response.delete_cookie(CSRF_COOKIE, path="/")


@router.post("/login", response_model=LoginResponse)
@limiter.limit(login_limit)
def login(
    request: Request,
    body: LoginRequest,
    response: Response,
    db: Session = Depends(get_db),
    settings: Settings = Depends(get_settings),
) -> LoginResponse:
    # Login is unauthenticated, so there is no session to bind a CSRF token to; the
    # SameSite=Strict cookies plus the JSON-only body mitigate login CSRF.
    user = (db.execute(select(User).where(User.username == body.username))).scalar_one_or_none()
    valid = verify_password(user.password_hash if user else None, body.password)
    if user is None or not valid or not user.is_active:
        audit.record(
            db,
            action="auth.login",
            outcome=audit.OUTCOME_FAILURE,
            user_id=user.id if user else None,
            username=user.username if user else None,
            detail={"reason": "invalid_credentials"},
        )
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Invalid username or password")

    token, csrf = new_token(), new_token()
    db.add(
        UserSession(
            user_id=user.id,
            token_hash=hash_token(token),
            csrf_token_hash=hash_token(csrf),
            expires_at=datetime.now(UTC) + timedelta(minutes=settings.session_ttl_minutes),
        )
    )
    db.execute(delete(UserSession).where(UserSession.expires_at <= datetime.now(UTC)))
    db.commit()
    audit.record(
        db,
        action="auth.login",
        outcome=audit.OUTCOME_SUCCESS,
        user_id=user.id,
        username=user.username,
    )
    _set_cookies(response, settings, token, csrf)
    return LoginResponse(
        user=UserOut(id=user.id, username=user.username, role=user.role), csrf_token=csrf
    )


@router.post("/logout", status_code=status.HTTP_204_NO_CONTENT)
def logout(
    response: Response,
    user: CurrentUser = Depends(require_roles(*ALL_ROLES)),
    db: Session = Depends(get_db),
) -> None:
    db.execute(delete(UserSession).where(UserSession.id == user.session_id))
    db.commit()
    audit.record(
        db,
        action="auth.logout",
        outcome=audit.OUTCOME_SUCCESS,
        user_id=user.id,
        username=user.username,
    )
    _clear_cookies(response)


@router.get("/me", response_model=UserOut)
def me(user: CurrentUser = Depends(get_current_user)) -> UserOut:
    return UserOut(id=user.id, username=user.username, role=user.role)
