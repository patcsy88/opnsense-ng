"""Test fixtures. Requires a disposable PostgreSQL reachable via TEST_DATABASE_URL
(e.g. postgresql://postgres:pw@127.0.0.1:55440/opnsense_test). Tests are skipped without it."""

import os
from collections.abc import AsyncIterator, Iterator

import httpx
import pytest
import pytest_asyncio
from alembic import command
from alembic.config import Config
from cryptography.fernet import Fernet
from sqlalchemy import create_engine, text

TEST_DB = os.environ.get("TEST_DATABASE_URL")
TEST_SESSION_SECRET = "x" * 48  # test-only value
TEST_FERNET_KEY = Fernet.generate_key().decode()

if TEST_DB:
    os.environ["DATABASE_URL"] = TEST_DB
os.environ["SESSION_SECRET"] = TEST_SESSION_SECRET
os.environ["CREDENTIAL_ENCRYPTION_KEY"] = TEST_FERNET_KEY
os.environ["SESSION_TTL_MINUTES"] = "30"
os.environ["OPNSENSE_BACKOFF_BASE_S"] = "0"
os.environ["LOGIN_RATE_LIMIT"] = "5/minute"
os.environ["ALLOWED_HOSTS"] = "test,localhost"
os.environ["MFA_REQUIRED_ROLES"] = ""  # MFA tests opt in per test
os.environ["LOGIN_LOCKOUT_THRESHOLD"] = "50"  # per-IP limiter is what most tests exercise

from app.auth.security import hash_password  # noqa: E402
from app.core.ratelimit import limiter  # noqa: E402
from app.db.models import Role, User  # noqa: E402
from app.main import create_app  # noqa: E402

PASSWORD = "correct-horse-battery"


def reset_limits() -> None:
    """Clear the per-IP limits: the in-memory general limiter and the PostgreSQL login counters
    (ADR-0014)."""
    limiter.reset()
    engine = create_engine(os.environ["DATABASE_URL"])
    with engine.begin() as conn:
        conn.execute(text("DELETE FROM rate_limit_counters"))
    engine.dispose()


SESSION_COOKIE = "__Host-session"
CSRF_COOKIE = "__Host-csrf_token"


def pytest_collection_modifyitems(items: list[pytest.Item]) -> None:
    if TEST_DB:
        return
    skip = pytest.mark.skip(reason="TEST_DATABASE_URL not set (PostgreSQL required)")
    for item in items:
        if "db" in getattr(item, "fixturenames", ()):
            item.add_marker(skip)


@pytest.fixture(scope="session")
def migrated_db() -> Iterator[None]:
    if not TEST_DB:
        yield
        return
    cfg = Config("alembic.ini")
    command.downgrade(cfg, "base")
    command.upgrade(cfg, "head")  # also verifies the migration
    yield


@pytest_asyncio.fixture
async def db(migrated_db: None) -> AsyncIterator[None]:
    limiter.reset()
    app = create_app()
    with app.state.engine.begin() as conn:
        conn.execute(
            text(
                "TRUNCATE audit_log, change_request_events, change_requests, sessions, "
                "mfa_challenges, mfa_recovery_codes, "
                "firewalls, users, login_throttle, rate_limit_counters "
                "RESTART IDENTITY CASCADE"
            )
        )
    app.state.engine.dispose()
    yield


@pytest_asyncio.fixture
async def app_client(db: None) -> AsyncIterator[httpx.AsyncClient]:
    app = create_app()
    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="https://test") as client:
        client.app = app  # type: ignore[attr-defined]
        yield client
    app.state.engine.dispose()


async def make_user(client: httpx.AsyncClient, username: str, role: Role) -> None:
    with client.app.state.sessionmaker() as s:  # type: ignore[attr-defined]
        s.add(User(username=username, role=role, password_hash=hash_password(PASSWORD)))
        s.commit()


async def login(
    client: httpx.AsyncClient, username: str, password: str = PASSWORD
) -> httpx.Response:
    return await client.post(
        "/api/v1/auth/login", json={"username": username, "password": password}
    )


def csrf_headers(client: httpx.AsyncClient) -> dict[str, str]:
    return {"X-CSRF-Token": client.cookies.get("__Host-csrf_token") or ""}


@pytest.fixture(autouse=True)
def _reset_cpu_sampler() -> Iterator[None]:
    from app.opnsense import cpu_sampler, traffic_cache

    cpu_sampler.clear()
    traffic_cache.clear()
    yield
    cpu_sampler.clear()
    traffic_cache.clear()
