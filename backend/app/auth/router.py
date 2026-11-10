from datetime import timedelta
from urllib.parse import urlsplit

from fastapi import APIRouter, Depends, HTTPException, Request, Response, status
from sqlalchemy import delete, select
from sqlalchemy.orm import Session

from app import audit
from app.auth import sessions, throttle
from app.auth.deps import (
    ALL_ROLES,
    CurrentUser,
    cookie_names,
    get_db,
    require_roles,
)
from app.auth.schemas import LoginRequest, LoginResponse, LogoutAllResponse, UserOut
from app.auth.security import (
    bind_csrf,
    hash_password,
    hash_token,
    needs_rehash,
    new_token,
    verify_password,
)
from app.core.config import Settings, get_settings
from app.core.ratelimit import limiter, login_limit
from app.db.models import Session as UserSession
from app.db.models import User, utcnow

router = APIRouter(prefix="/api/v1/auth", tags=["auth"])

_INVALID = "Invalid username or password"


def _set_cookies(response: Response, settings: Settings, session_token: str, csrf: str) -> None:
    session_name, csrf_name = cookie_names(settings)
    max_age = settings.session_ttl_minutes * 60
    common = {
        "max_age": max_age,
        "secure": settings.cookie_secure,
        "samesite": "strict",
        "path": "/",
    }
    response.set_cookie(session_name, session_token, httponly=True, **common)  # type: ignore[arg-type]
    # Readable by the PWA so it can echo it in X-CSRF-Token (double-submit).
    response.set_cookie(csrf_name, csrf, httponly=False, **common)  # type: ignore[arg-type]


def _clear_cookies(response: Response, settings: Settings) -> None:
    for name in cookie_names(settings):
        response.delete_cookie(
            name, path="/", secure=settings.cookie_secure, httponly=False, samesite="strict"
        )


def _origin_allowed(request: Request, settings: Settings) -> bool:
    origin = request.headers.get("origin")
    if origin is None:
        return True  # non-browser client; browsers always send Origin on cross-site POSTs
    if origin == "null":
        return False
    parts = urlsplit(origin)
    normalised = f"{parts.scheme}://{parts.netloc}".lower()
    if settings.allowed_origins:
        return normalised in settings.allowed_origins
    # No explicit list configured: same-origin only (Origin must match the Host header).
    return parts.netloc.lower() == (request.headers.get("host") or "").lower()


def login_guard(request: Request, settings: Settings = Depends(get_settings)) -> None:
    """Login CSRF defence: JSON content type only, and a matching Origin when one is sent."""
    media_type = request.headers.get("content-type", "").split(";")[0].strip().lower()
    if media_type != "application/json":
        raise HTTPException(status.HTTP_415_UNSUPPORTED_MEDIA_TYPE, "Content-Type must be JSON")
    if not _origin_allowed(request, settings):
        raise HTTPException(status.HTTP_403_FORBIDDEN, "Origin not allowed")


@router.post("/login", response_model=LoginResponse, dependencies=[Depends(login_guard)])
@limiter.limit(login_limit)
def login(
    request: Request,
    body: LoginRequest,
    response: Response,
    db: Session = Depends(get_db),
    settings: Settings = Depends(get_settings),
) -> LoginResponse:
    username = body.username  # already normalised
    remaining = throttle.locked_seconds(db, username)
    if remaining:
        audit.record(
            db,
            action="auth.login",
            outcome=audit.OUTCOME_DENIED,
            detail={"reason": "throttled"},
            request=request,
        )
        raise HTTPException(
            status.HTTP_429_TOO_MANY_REQUESTS,
            "Too many failed attempts. Try again later.",
            headers={"Retry-After": str(remaining)},
        )

    user = db.execute(select(User).where(User.username == username)).scalar_one_or_none()
    valid = verify_password(user.password_hash if user else None, body.password)
    if user is None or not valid or not user.is_active:
        audit.add(
            db,
            action="auth.login",
            outcome=audit.OUTCOME_FAILURE,
            user_id=user.id if user else None,
            username=user.username if user else None,
            detail={"reason": "invalid_credentials"},
            request=request,
        )
        throttle.register_failure(db, settings, username)
        db.commit()
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, _INVALID)

    if needs_rehash(user.password_hash):
        user.password_hash = hash_password(body.password)
    throttle.clear(db, username)

    token, csrf = new_token(), new_token()
    now = utcnow()
    db.add(
        UserSession(
            user_id=user.id,
            token_hash=hash_token(token),
            csrf_token_hash=bind_csrf(csrf, settings.session_secret.get_secret_value()),
            created_at=now,
            last_seen_at=now,
            expires_at=now + timedelta(minutes=settings.session_ttl_minutes),
        )
    )
    db.flush()
    sessions.cleanup_expired(db, settings, now)
    evicted = sessions.enforce_session_cap(db, user.id, settings.max_sessions_per_user)
    audit.add(
        db,
        action="auth.login",
        outcome=audit.OUTCOME_SUCCESS,
        user_id=user.id,
        username=user.username,
        detail={"sessions_evicted": evicted} if evicted else None,
        request=request,
    )
    db.commit()
    _set_cookies(response, settings, token, csrf)
    return LoginResponse(
        user=UserOut(id=user.id, username=user.username, role=user.role), csrf_token=csrf
    )


@router.post("/logout", status_code=status.HTTP_204_NO_CONTENT)
def logout(
    request: Request,
    response: Response,
    user: CurrentUser = Depends(require_roles(*ALL_ROLES)),
    db: Session = Depends(get_db),
    settings: Settings = Depends(get_settings),
) -> None:
    db.execute(delete(UserSession).where(UserSession.id == user.session_id))
    audit.add(
        db,
        action="auth.logout",
        outcome=audit.OUTCOME_SUCCESS,
        user_id=user.id,
        username=user.username,
        request=request,
    )
    db.commit()
    _clear_cookies(response, settings)


@router.post("/logout-all", response_model=LogoutAllResponse)
def logout_all(
    request: Request,
    response: Response,
    user: CurrentUser = Depends(require_roles(*ALL_ROLES)),
    db: Session = Depends(get_db),
    settings: Settings = Depends(get_settings),
) -> LogoutAllResponse:
    """Revoke every session of the current user, including this one."""
    revoked = sessions.revoke_user_sessions(db, user.id)
    audit.add(
        db,
        action="auth.logout_all",
        outcome=audit.OUTCOME_SUCCESS,
        user_id=user.id,
        username=user.username,
        detail={"revoked": revoked},
        request=request,
    )
    db.commit()
    _clear_cookies(response, settings)
    return LogoutAllResponse(revoked=revoked)


@router.get("/me", response_model=UserOut)
def me(user: CurrentUser = Depends(require_roles(*ALL_ROLES))) -> UserOut:
    return UserOut(id=user.id, username=user.username, role=user.role)
