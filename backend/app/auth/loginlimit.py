"""Per-IP login rate limit stored in PostgreSQL (ADR-0014).

Exact across restarts and across several backend processes. Fixed windows, like the in-memory
limiter it replaces for the two login endpoints. The counter commits on its own session, so a
later rollback in the request cannot undo it. If the database is down the request fails; the
limit is never skipped.
"""

import secrets
from datetime import UTC, datetime, timedelta

from fastapi import Depends, HTTPException, Request, status
from limits import parse
from sqlalchemy import delete
from sqlalchemy.dialects.postgresql import insert as pg_insert
from sqlalchemy.orm import Session, sessionmaker

from app.core.clientip import client_ip
from app.core.config import Settings, get_settings
from app.db.models import RateLimitCounter, utcnow

RETENTION = timedelta(hours=1)
CLEANUP_ONE_IN = 100


def _window(now: datetime, period: int) -> datetime:
    seconds = int(now.timestamp()) // period * period
    return datetime.fromtimestamp(seconds, tz=UTC)


def hit(db: Session, key: str, limit: str, now: datetime | None = None) -> int:
    """Count one request and return the seconds to wait when over the limit, else 0."""
    item = parse(limit)
    period = int(item.get_expiry())
    now = now or utcnow()
    start = _window(now, period)
    upsert = pg_insert(RateLimitCounter).values(key=key, window_start=start, count=1)
    stmt = upsert.on_conflict_do_update(
        index_elements=[RateLimitCounter.key, RateLimitCounter.window_start],
        set_={"count": RateLimitCounter.count + 1},
    ).returning(RateLimitCounter.count)
    count = db.execute(stmt).scalar_one()
    db.commit()
    if count <= item.amount:
        return 0
    return max(1, int((start + timedelta(seconds=period) - now).total_seconds()) + 1)


def cleanup(db: Session, now: datetime | None = None) -> int:
    cutoff = (now or utcnow()) - RETENTION
    result = db.execute(delete(RateLimitCounter).where(RateLimitCounter.window_start < cutoff))
    db.commit()
    return int(getattr(result, "rowcount", 0) or 0)


def login_rate_limit(request: Request, settings: Settings = Depends(get_settings)) -> None:
    """Dependency for the login endpoints."""
    maker: sessionmaker[Session] = request.app.state.sessionmaker
    with maker() as db:
        wait = hit(db, f"login:{client_ip(request)}", settings.login_rate_limit)
        if secrets.randbelow(CLEANUP_ONE_IN) == 0:
            cleanup(db)
    if wait:
        raise HTTPException(
            status.HTTP_429_TOO_MANY_REQUESTS,
            "Too many requests",
            headers={"Retry-After": str(wait)},
        )
