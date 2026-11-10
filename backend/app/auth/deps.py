"""Request dependencies: DB session, authenticated user, RBAC (default deny), CSRF."""

import uuid
from collections.abc import Callable, Iterator
from dataclasses import dataclass
from datetime import UTC, datetime

from fastapi import Depends, HTTPException, Request, status
from sqlalchemy import delete, select
from sqlalchemy.orm import Session

from app import audit
from app.auth.security import hash_token, tokens_match
from app.db.models import Role, User
from app.db.models import Session as UserSession

SESSION_COOKIE = "session"
CSRF_COOKIE = "csrf_token"
CSRF_HEADER = "X-CSRF-Token"
SAFE_METHODS = {"GET", "HEAD", "OPTIONS"}

ALL_ROLES: frozenset[Role] = frozenset(Role)


@dataclass(frozen=True)
class CurrentUser:
    id: uuid.UUID
    username: str
    role: Role
    session_id: uuid.UUID


def get_db(request: Request) -> Iterator[Session]:
    with request.app.state.sessionmaker() as session:
        yield session


def _unauthenticated() -> HTTPException:
    return HTTPException(status.HTTP_401_UNAUTHORIZED, "Not authenticated")


def get_current_user(request: Request, db: Session = Depends(get_db)) -> CurrentUser:
    token = request.cookies.get(SESSION_COOKIE)
    if not token:
        raise _unauthenticated()
    row = db.execute(
        select(UserSession, User)
        .join(User, User.id == UserSession.user_id)
        .where(UserSession.token_hash == hash_token(token))
    ).first()
    if row is None:
        raise _unauthenticated()
    session, user = row
    if session.expires_at <= datetime.now(UTC):
        db.execute(delete(UserSession).where(UserSession.id == session.id))
        db.commit()
        raise _unauthenticated()
    if not user.is_active:
        raise _unauthenticated()
    request.state.session_csrf_hash = session.csrf_token_hash
    return CurrentUser(user.id, user.username, user.role, session.id)


def enforce_csrf(request: Request) -> None:
    """Double-submit check: header must equal the CSRF cookie AND match the hash bound to the
    server-side session. Applied to every state-changing method."""
    if request.method in SAFE_METHODS:
        return
    header = request.headers.get(CSRF_HEADER)
    cookie = request.cookies.get(CSRF_COOKIE)
    expected_hash: str | None = getattr(request.state, "session_csrf_hash", None)
    if (
        not header
        or not cookie
        or expected_hash is None
        or not tokens_match(header, cookie)
        or not tokens_match(hash_token(header), expected_hash)
    ):
        raise HTTPException(status.HTTP_403_FORBIDDEN, "CSRF validation failed")


def require_roles(
    *allowed: Role,
) -> Callable[..., CurrentUser]:
    """RBAC dependency. Default deny: no allowed roles means nobody passes.
    Also enforces CSRF on state-changing methods, after authentication."""
    allowed_set = frozenset(allowed)

    def dependency(
        request: Request,
        user: CurrentUser = Depends(get_current_user),
        db: Session = Depends(get_db),
    ) -> CurrentUser:
        enforce_csrf(request)
        if user.role not in allowed_set:
            audit.record(
                db,
                action="rbac.denied",
                outcome=audit.OUTCOME_DENIED,
                user_id=user.id,
                username=user.username,
                detail={"method": request.method, "path": request.url.path},
            )
            raise HTTPException(status.HTTP_403_FORBIDDEN, "Insufficient privileges")
        return user

    return dependency
