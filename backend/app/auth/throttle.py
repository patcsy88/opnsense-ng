"""Per-username login backoff, stored in PostgreSQL so it survives restarts.

Applies to unknown usernames too, so the behaviour never reveals whether an account exists.
After ``login_lockout_threshold`` consecutive failures the username is locked for
``base * 2^(n - threshold)`` seconds (capped). A lock rejects even the correct password; this
trades a possible targeted nuisance lock-out (bounded by the cap and the per-IP limiter) for
protection against distributed guessing that the per-IP limiter cannot see.
"""

from datetime import datetime, timedelta

from sqlalchemy import case, delete, select, update
from sqlalchemy.dialects.postgresql import insert as pg_insert
from sqlalchemy.orm import Session

from app.core.config import Settings
from app.db.models import LoginThrottle, utcnow


def locked_seconds(db: Session, username: str, now: datetime | None = None) -> int:
    """Remaining lock time in whole seconds (0 when not locked)."""
    now = now or utcnow()
    until = db.execute(
        select(LoginThrottle.locked_until).where(LoginThrottle.username == username)
    ).scalar_one_or_none()
    if until is None or until <= now:
        return 0
    return int((until - now).total_seconds()) + 1


def register_failure(db: Session, settings: Settings, username: str) -> None:
    """Atomically count a failure and set the lock. Does not commit."""
    now = utcnow()
    window = timedelta(seconds=settings.login_lockout_max_seconds * 2)
    insert_stmt = pg_insert(LoginThrottle).values(
        username=username, failures=1, last_failure_at=now
    )
    stmt = insert_stmt.on_conflict_do_update(
        index_elements=[LoginThrottle.username],
        set_={
            # an old streak (older than the window) starts over
            "failures": case(
                (LoginThrottle.last_failure_at < now - window, 1),
                else_=LoginThrottle.failures + 1,
            ),
            "last_failure_at": now,
        },
    ).returning(LoginThrottle.failures)
    failures = int(db.execute(stmt).scalar_one())
    over = failures - settings.login_lockout_threshold
    if over >= 0:
        delay = min(
            settings.login_lockout_base_seconds * (2 ** min(over, 20)),
            settings.login_lockout_max_seconds,
        )
        db.execute(
            update(LoginThrottle)
            .where(LoginThrottle.username == username)
            .values(locked_until=now + timedelta(seconds=delay))
        )


def clear(db: Session, username: str) -> None:
    db.execute(delete(LoginThrottle).where(LoginThrottle.username == username))
