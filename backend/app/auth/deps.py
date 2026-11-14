"""Request dependencies: DB session, authenticated user, RBAC (default deny), CSRF."""

import uuid
from collections.abc import Callable, Iterator
from dataclasses import dataclass
from datetime import timedelta

from fastapi import Depends, HTTPException, Request, status
from sqlalchemy import delete, select
from sqlalchemy.orm import Session

from app import audit
from app.auth.security import bind_csrf, hash_token, tokens_match
from app.auth.sessions import LAST_SEEN_RESOLUTION
from app.core.config import Settings, get_settings
from app.db.models import Role, User, utcnow
from app.db.models import Session as UserSession

CSRF_HEADER = "X-CSRF-Token"
SAFE_METHODS = {"GET", "HEAD", "OPTIONS"}

ALL_ROLES: frozenset[Role] = frozenset(Role)

# Every dependency produced by require_roles; the route-coverage test checks against this.
RBAC_DEPENDENCIES: set[Callable[..., CurrentUser]] = set()


def cookie_names(settings: Settings) -> tuple[str, str]:
    """(session cookie, csrf cookie). Over HTTPS they carry the ``__Host-`` prefix, which makes
    browsers require Secure, Path=/ and no Domain. The prefix is impossible on plain HTTP, so
    DEV_MODE with COOKIE_SECURE=false falls back to unprefixed names."""
    if settings.cookie_secure:
        return "__Host-session", "__Host-csrf_token"
    return "session", "csrf_token"


@dataclass(frozen=True)
class CurrentUser:
    id: uuid.UUID
    username: str
    role: Role
    session_id: uuid.UUID
    mfa_enabled: bool = False
    # The role requires MFA and the user has not enrolled yet.
    mfa_restricted: bool = False
    must_change_password: bool = False


def get_db(request: Request) -> Iterator[Session]:
    with request.app.state.sessionmaker() as session:
        yield session


def _unauthenticated(request: Request, db: Session, reason: str) -> HTTPException:
    audit.record_throttled(
        db, request=request, action="auth.unauthenticated", detail={"reason": reason}
    )
    return HTTPException(status.HTTP_401_UNAUTHORIZED, "Not authenticated")


def get_current_user(
    request: Request,
    db: Session = Depends(get_db),
    settings: Settings = Depends(get_settings),
) -> CurrentUser:
    token = request.cookies.get(cookie_names(settings)[0])
    if not token:
        raise _unauthenticated(request, db, "no_session")
    row = db.execute(
        select(UserSession, User)
        .join(User, User.id == UserSession.user_id)
        .where(UserSession.token_hash == hash_token(token))
    ).first()
    if row is None:
        raise _unauthenticated(request, db, "unknown_session")
    session, user = row
    now = utcnow()
    idle_limit = session.last_seen_at + timedelta(minutes=settings.session_idle_timeout_minutes)
    if session.expires_at <= now or idle_limit <= now:
        db.execute(delete(UserSession).where(UserSession.id == session.id))
        db.commit()
        raise _unauthenticated(request, db, "session_expired")
    if not user.is_active:
        raise _unauthenticated(request, db, "inactive_user")
    if now - session.last_seen_at >= LAST_SEEN_RESOLUTION:
        session.last_seen_at = now
        db.commit()
    request.state.session_csrf_hash = session.csrf_token_hash
    restricted = user.role.value in settings.mfa_required_roles and not user.mfa_enabled
    return CurrentUser(
        user.id,
        user.username,
        user.role,
        session.id,
        user.mfa_enabled,
        restricted,
        user.must_change_password,
    )


def enforce_csrf(
    request: Request,
    db: Session,
    settings: Settings,
    user: CurrentUser | None = None,
) -> None:
    """Double-submit check: header must equal the CSRF cookie AND match the HMAC bound to the
    server-side session. Applied to every state-changing method."""
    if request.method in SAFE_METHODS:
        return
    header = request.headers.get(CSRF_HEADER)
    cookie = request.cookies.get(cookie_names(settings)[1])
    expected_hash: str | None = getattr(request.state, "session_csrf_hash", None)
    if (
        not header
        or not cookie
        or expected_hash is None
        or not tokens_match(header, cookie)
        or not tokens_match(
            bind_csrf(header, settings.session_secret.get_secret_value()), expected_hash
        )
    ):
        audit.record_throttled(
            db,
            request=request,
            action="auth.csrf_failed",
            user_id=user.id if user else None,
            username=user.username if user else None,
            detail={"method": request.method, "path": request.url.path},
        )
        raise HTTPException(status.HTTP_403_FORBIDDEN, "CSRF validation failed")


def require_roles(
    *allowed: Role,
    allow_restricted: bool = False,
    allow_password_pending: bool = False,
) -> Callable[..., CurrentUser]:
    """RBAC dependency. Default deny: no allowed roles means nobody passes.
    Also enforces CSRF on state-changing methods, after authentication. A session that must
    still enrol in MFA only passes where ``allow_restricted`` is set (ADR-0012); one with a
    temporary password only where ``allow_password_pending`` is set (ADR-0013)."""
    allowed_set = frozenset(allowed)

    def dependency(
        request: Request,
        user: CurrentUser = Depends(get_current_user),
        db: Session = Depends(get_db),
        settings: Settings = Depends(get_settings),
    ) -> CurrentUser:
        enforce_csrf(request, db, settings, user)
        if user.must_change_password and not allow_password_pending:
            raise HTTPException(status.HTTP_403_FORBIDDEN, "password_change_required")
        if user.mfa_restricted and not allow_restricted:
            raise HTTPException(status.HTTP_403_FORBIDDEN, "mfa_enrolment_required")
        if user.role not in allowed_set:
            audit.record(
                db,
                action="rbac.denied",
                outcome=audit.OUTCOME_DENIED,
                user_id=user.id,
                username=user.username,
                detail={"method": request.method, "path": request.url.path},
                request=request,
            )
            raise HTTPException(status.HTTP_403_FORBIDDEN, "Insufficient privileges")
        return user

    RBAC_DEPENDENCIES.add(dependency)
    return dependency
