"""Session lifecycle: creation with a concurrency cap, revocation and expired-session cleanup."""

import uuid
from datetime import datetime, timedelta

from sqlalchemy import delete, func, select
from sqlalchemy.orm import Session

from app.core.config import Settings
from app.db.models import LoginThrottle, utcnow
from app.db.models import Session as UserSession

LAST_SEEN_RESOLUTION = timedelta(seconds=60)


def cleanup_expired(db: Session, settings: Settings, now: datetime | None = None) -> int:
    """Delete sessions past their absolute expiry or idle timeout, and stale throttle rows.
    Does not commit. Returns the number of sessions removed."""
    now = now or utcnow()
    idle_cutoff = now - timedelta(minutes=settings.session_idle_timeout_minutes)
    result = db.execute(
        delete(UserSession).where(
            (UserSession.expires_at <= now) | (UserSession.last_seen_at <= idle_cutoff)
        )
    )
    stale = now - timedelta(seconds=settings.login_lockout_max_seconds * 2)
    db.execute(
        delete(LoginThrottle).where(
            LoginThrottle.last_failure_at <= stale,
            (LoginThrottle.locked_until.is_(None)) | (LoginThrottle.locked_until <= now),
        )
    )
    return int(getattr(result, "rowcount", 0) or 0)


def enforce_session_cap(db: Session, user_id: uuid.UUID, max_sessions: int) -> int:
    """Revoke the oldest sessions of ``user_id`` beyond ``max_sessions``. Does not commit."""
    ids = list(
        db.execute(
            select(UserSession.id)
            .where(UserSession.user_id == user_id)
            .order_by(UserSession.created_at.desc(), UserSession.id)
        ).scalars()
    )
    surplus = ids[max_sessions:]
    if surplus:
        db.execute(delete(UserSession).where(UserSession.id.in_(surplus)))
    return len(surplus)


def revoke_user_sessions(
    db: Session, user_id: uuid.UUID, *, except_session_id: uuid.UUID | None = None
) -> int:
    """Revoke every session of a user (optionally keeping one). Does not commit."""
    stmt = delete(UserSession).where(UserSession.user_id == user_id)
    if except_session_id is not None:
        stmt = stmt.where(UserSession.id != except_session_id)
    return int(getattr(db.execute(stmt), "rowcount", 0) or 0)


def count_sessions(db: Session, user_id: uuid.UUID) -> int:
    return int(
        db.execute(
            select(func.count()).select_from(UserSession).where(UserSession.user_id == user_id)
        ).scalar_one()
    )
