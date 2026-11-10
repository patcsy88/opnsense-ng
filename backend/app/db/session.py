"""Synchronous SQLAlchemy engine (psycopg).

SQLAlchemy's asyncio extension needs ``greenlet``, which is not on the ADR-0003 approved list,
so DB access is synchronous and runs in FastAPI's threadpool (sync ``def`` endpoints).
"""

from sqlalchemy import Engine, create_engine
from sqlalchemy.orm import Session, sessionmaker


def to_sync_url(url: str) -> str:
    """Accept postgresql:// or postgresql+psycopg:// and always use the psycopg driver."""
    if url.startswith("postgresql://"):
        return "postgresql+psycopg://" + url.removeprefix("postgresql://")
    return url


def make_engine(database_url: str) -> Engine:
    return create_engine(to_sync_url(database_url), pool_pre_ping=True)


def make_sessionmaker(engine: Engine) -> sessionmaker[Session]:
    return sessionmaker(engine, expire_on_commit=False)
