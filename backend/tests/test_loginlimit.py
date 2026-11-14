"""Login rate limit in PostgreSQL (ADR-0014)."""

from datetime import UTC, datetime, timedelta

import httpx
import pytest
from sqlalchemy import func, select

from app.auth import cli, loginlimit
from app.db.models import RateLimitCounter, Role
from app.main import create_app
from tests.conftest import PASSWORD, login, make_user
from tests.test_security import db_rows

pytestmark = pytest.mark.usefixtures("db")

T0 = datetime(2026, 11, 14, 12, 0, 10, tzinfo=UTC)  # 10 s into a minute window


def with_session(client: httpx.AsyncClient):  # type: ignore[no-untyped-def]
    return client.app.state.sessionmaker()  # type: ignore[attr-defined]


async def test_hit_counts_per_key_and_reports_the_wait(app_client: httpx.AsyncClient) -> None:
    with with_session(app_client) as db:
        assert [loginlimit.hit(db, "login:1.1.1.1", "3/minute", T0) for _ in range(3)] == [0, 0, 0]
        assert loginlimit.hit(db, "login:1.1.1.1", "3/minute", T0) == 51  # window ends at :60
        assert loginlimit.hit(db, "login:2.2.2.2", "3/minute", T0) == 0  # another client
        later = T0 + timedelta(seconds=55)  # next window
        assert loginlimit.hit(db, "login:1.1.1.1", "3/minute", later) == 0


async def test_counting_survives_a_restart_and_is_shared(app_client: httpx.AsyncClient) -> None:
    now = datetime.now(UTC)
    with with_session(app_client) as db:
        for _ in range(5):
            loginlimit.hit(db, "login:9.9.9.9", "5/minute", now)
    # a brand new application instance (restart, or a second process) sees the same counts
    other = create_app()
    try:
        with other.state.sessionmaker() as db:
            assert loginlimit.hit(db, "login:9.9.9.9", "5/minute", now) > 0
    finally:
        other.state.engine.dispose()


async def test_login_endpoint_answers_429_with_retry_after(app_client: httpx.AsyncClient) -> None:
    await make_user(app_client, "ann", Role.read_only)
    codes = [(await login(app_client, "ann", "wrong-wrong-wrong")).status_code for _ in range(5)]
    assert codes == [401] * 5
    blocked = await login(app_client, "ann", PASSWORD)  # even the right password is limited
    assert blocked.status_code == 429
    assert int(blocked.headers["Retry-After"]) >= 1
    rows = db_rows(app_client, select(RateLimitCounter))
    assert len(rows) == 1 and rows[0].count == 6 and rows[0].key.startswith("login:")


async def test_cleanup_removes_only_old_windows(app_client: httpx.AsyncClient) -> None:
    now = datetime.now(UTC)
    with with_session(app_client) as db:
        loginlimit.hit(db, "login:old", "5/minute", now - timedelta(hours=2))
        loginlimit.hit(db, "login:new", "5/minute", now)
        assert loginlimit.cleanup(db, now) == 1
    assert [r.key for r in db_rows(app_client, select(RateLimitCounter))] == ["login:new"]
    assert db_rows(app_client, select(func.count()).select_from(RateLimitCounter)) == [1]


async def test_cli_cleanup_includes_the_counters(app_client: httpx.AsyncClient) -> None:
    with with_session(app_client) as db:
        loginlimit.hit(db, "login:old", "5/minute", datetime.now(UTC) - timedelta(hours=3))
    assert cli.cleanup_sessions() >= 1
    assert db_rows(app_client, select(RateLimitCounter)) == []
