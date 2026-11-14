"""User management (ADR-0013)."""

import uuid

import httpx
import pytest
from sqlalchemy import func, select, update

from app.auth.deps import RBAC_DEPENDENCIES
from app.core.config import get_settings
from app.core.ratelimit import limiter
from app.db.models import AuditLog, MfaRecoveryCode, Role, User
from app.db.models import Session as UserSession
from tests.conftest import PASSWORD, csrf_headers, login, make_user
from tests.test_mfa import current_code, enrol
from tests.test_security import _dependant_calls, _flatten_routes, db_rows, override

pytestmark = pytest.mark.usefixtures("db")

USERS = "/api/v1/users"
NEW_PASSWORD = "a-brand-new-passphrase"


def uid(client: httpx.AsyncClient, name: str) -> str:
    return str(db_rows(client, select(User).where(User.username == name))[0].id)


async def post(client: httpx.AsyncClient, path: str, body: object | None = None) -> httpx.Response:
    return await client.post(
        path, json=body if body is not None else {}, headers=csrf_headers(client)
    )


async def as_user(client: httpx.AsyncClient, name: str, password: str = PASSWORD) -> None:
    client.cookies.clear()
    limiter.reset()
    assert (await login(client, name, password)).status_code == 200


async def test_only_admin_can_manage_users(app_client: httpx.AsyncClient) -> None:
    for role in (Role.network_admin, Role.security_admin, Role.read_only):
        await make_user(app_client, role.value, role)
    await make_user(app_client, "boss", Role.admin)
    target = uid(app_client, "read_only")
    for role in (Role.network_admin, Role.security_admin, Role.read_only):
        await as_user(app_client, role.value)
        assert (await app_client.get(USERS)).status_code == 403
        for path, body in (
            (USERS, {"username": "x", "role": "read_only"}),
            (f"{USERS}/{target}/role", {"role": "admin"}),
            (f"{USERS}/{target}/deactivate", {}),
            (f"{USERS}/{target}/reactivate", {}),
            (f"{USERS}/{target}/reset-password", {}),
            (f"{USERS}/{target}/reset-mfa", {"password": PASSWORD}),
        ):
            assert (await post(app_client, path, body)).status_code == 403, path
    assert db_rows(app_client, select(User.role).where(User.username == "read_only")) == [
        Role.read_only
    ]


async def test_list_hides_secrets(app_client: httpx.AsyncClient) -> None:
    await make_user(app_client, "boss", Role.admin)
    await make_user(app_client, "ann", Role.read_only)
    await as_user(app_client, "boss")
    rows = (await app_client.get(USERS)).json()
    assert [r["username"] for r in rows] == ["ann", "boss"]
    assert set(rows[0]) == {
        "id", "username", "role", "is_active", "mfa_enabled", "must_change_password",
        "created_at", "sessions",
    }  # fmt: skip
    assert next(r for r in rows if r["username"] == "boss")["sessions"] == 1
    assert "argon2" not in (await app_client.get(USERS)).text


async def test_create_gives_a_temporary_password_that_must_be_changed(
    app_client: httpx.AsyncClient,
) -> None:
    await make_user(app_client, "boss", Role.admin)
    await as_user(app_client, "boss")
    bad = await post(app_client, USERS, {"username": "Bad Name", "role": "read_only"})
    assert bad.status_code == 422
    made = await post(app_client, USERS, {"username": "  Newbie ", "role": "network_admin"})
    assert made.status_code == 201
    temp = made.json()["temporary_password"]
    assert len(temp) == 20 and made.json()["user"]["username"] == "newbie"
    assert made.json()["user"]["must_change_password"] is True
    assert (
        await post(app_client, USERS, {"username": "newbie", "role": "read_only"})
    ).status_code == 409

    stored = db_rows(app_client, select(User).where(User.username == "newbie"))[0]
    assert temp not in stored.password_hash
    blob = " ".join(str(r.detail) for r in db_rows(app_client, select(AuditLog)))
    assert temp not in blob and "user.create" in {
        r.action for r in db_rows(app_client, select(AuditLog))
    }

    await as_user(app_client, "newbie", temp)
    me = (await app_client.get("/api/v1/auth/me")).json()
    assert me["must_change_password"] is True
    blocked = await app_client.get("/api/v1/firewalls")
    assert blocked.status_code == 403 and blocked.json()["detail"] == "password_change_required"

    weak = await post(
        app_client, "/api/v1/auth/password", {"current_password": temp, "new_password": "short"}
    )
    assert weak.status_code == 422
    same = await post(
        app_client,
        "/api/v1/auth/password",
        {"current_password": temp, "new_password": temp},
    )
    assert same.status_code == 422
    wrong = await post(
        app_client,
        "/api/v1/auth/password",
        {"current_password": "nope-nope-nope", "new_password": NEW_PASSWORD},
    )
    assert wrong.status_code == 401
    done = await post(
        app_client,
        "/api/v1/auth/password",
        {"current_password": temp, "new_password": NEW_PASSWORD},
    )
    assert done.status_code == 204
    assert (await app_client.get("/api/v1/firewalls/options")).status_code == 200
    assert (await app_client.get("/api/v1/auth/me")).json()["must_change_password"] is False
    app_client.cookies.clear()
    assert (await login(app_client, "newbie", temp)).status_code == 401
    assert (await login(app_client, "newbie", NEW_PASSWORD)).status_code == 200
    blob = " ".join(str(r.detail) for r in db_rows(app_client, select(AuditLog)))
    assert NEW_PASSWORD not in blob


async def test_password_change_ends_other_sessions_and_needs_mfa_code(
    app_client: httpx.AsyncClient,
) -> None:
    await make_user(app_client, "eve", Role.read_only)
    await enrol(app_client, "eve")
    transport = httpx.ASGITransport(app=app_client.app)  # type: ignore[attr-defined]
    other = httpx.AsyncClient(transport=transport, base_url="https://test")
    async with other:
        limiter.reset()
        first = await login(other, "eve")
        code = current_code(app_client, "eve")
        done = await other.post(
            "/api/v1/auth/login/mfa", json={"challenge": first.json()["challenge"], "code": code}
        )
        assert done.status_code == 200
        assert db_rows(app_client, select(func.count()).select_from(UserSession)) == [2]
        no_code = await post(
            app_client,
            "/api/v1/auth/password",
            {"current_password": PASSWORD, "new_password": NEW_PASSWORD},
        )
        assert no_code.status_code == 401
        ok = await post(
            app_client,
            "/api/v1/auth/password",
            {
                "current_password": PASSWORD,
                "new_password": NEW_PASSWORD,
                "code": current_code(app_client, "eve"),
            },
        )
        assert ok.status_code == 204
        assert (await other.get("/api/v1/auth/me")).status_code == 401
        assert (await app_client.get("/api/v1/auth/me")).status_code == 200


async def test_role_change_and_deactivation_end_sessions(app_client: httpx.AsyncClient) -> None:
    await make_user(app_client, "boss", Role.admin)
    await make_user(app_client, "ann", Role.read_only)
    await as_user(app_client, "ann")
    ann_cookies = dict(app_client.cookies)
    await as_user(app_client, "boss")
    ann = uid(app_client, "ann")
    changed = await post(app_client, f"{USERS}/{ann}/role", {"role": "network_admin"})
    assert changed.status_code == 200 and changed.json()["role"] == "network_admin"
    assert changed.json()["sessions"] == 0
    audit = [r for r in db_rows(app_client, select(AuditLog)) if r.action == "user.role_change"]
    assert (
        audit[0].detail["old_role"] == "read_only"
        and audit[0].detail["new_role"] == "network_admin"
    )
    assert (
        await post(app_client, f"{USERS}/{uid(app_client, 'ann')}/role", {"role": "bogus"})
    ).status_code == 422
    assert (
        await post(app_client, f"{USERS}/{uuid.uuid4()}/role", {"role": "admin"})
    ).status_code == 404

    await as_user(app_client, "ann")
    await as_user(app_client, "boss")
    off = await post(app_client, f"{USERS}/{ann}/deactivate")
    assert off.json()["is_active"] is False and off.json()["sessions"] == 0
    app_client.cookies.clear()
    app_client.cookies.update(ann_cookies)
    assert (await app_client.get("/api/v1/auth/me")).status_code == 401
    limiter.reset()
    assert (await login(app_client, "ann")).status_code == 401  # inactive: same answer as bad login
    await as_user(app_client, "boss")
    on = await post(app_client, f"{USERS}/{ann}/reactivate")
    assert on.json()["is_active"] is True
    await as_user(app_client, "ann")


async def test_last_admin_and_self_protection(app_client: httpx.AsyncClient) -> None:
    await make_user(app_client, "boss", Role.admin)
    await as_user(app_client, "boss")
    boss = uid(app_client, "boss")
    for path, body in (
        (f"{USERS}/{boss}/deactivate", {}),
        (f"{USERS}/{boss}/role", {"role": "read_only"}),
    ):
        assert (await post(app_client, path, body)).status_code == 409
    assert (await post(app_client, f"{USERS}/{boss}/reset-password")).status_code == 409
    assert (
        await post(app_client, f"{USERS}/{boss}/reset-mfa", {"password": PASSWORD})
    ).status_code == 409

    await make_user(app_client, "second", Role.admin)
    second = uid(app_client, "second")
    assert (await post(app_client, f"{USERS}/{boss}/deactivate")).status_code == 409  # still self
    assert (
        await post(app_client, f"{USERS}/{second}/role", {"role": "read_only"})
    ).status_code == 200

    # with the other admin gone again, boss is the only one left; nobody else can remove them
    await post(app_client, f"{USERS}/{second}/role", {"role": "admin"})
    await as_user(app_client, "second")
    assert (await post(app_client, f"{USERS}/{boss}/deactivate")).status_code == 200
    await as_user(app_client, "second")
    assert (
        await post(app_client, f"{USERS}/{uid(app_client, 'second')}/deactivate")
    ).status_code == 409
    actives = db_rows(
        app_client, select(User).where(User.role == Role.admin, User.is_active.is_(True))
    )
    assert [u.username for u in actives] == ["second"]
    denied = [
        r
        for r in db_rows(app_client, select(AuditLog))
        if r.outcome == "denied" and r.action.startswith("user.")
    ]
    reasons = {r.detail["reason"] for r in denied if r.detail}
    # "last_admin" only arises when two admins act at the same moment; see _protect_admins
    assert reasons == {"self"}


async def test_reset_password_forces_change_and_ends_sessions(
    app_client: httpx.AsyncClient,
) -> None:
    await make_user(app_client, "boss", Role.admin)
    await make_user(app_client, "ann", Role.read_only)
    await as_user(app_client, "ann")
    await as_user(app_client, "boss")
    ann = uid(app_client, "ann")
    r = await post(app_client, f"{USERS}/{ann}/reset-password")
    temp = r.json()["temporary_password"]
    assert r.status_code == 200 and r.json()["user"]["must_change_password"] is True
    assert r.json()["user"]["sessions"] == 0
    assert (await login(app_client, "ann", PASSWORD)).status_code == 401
    limiter.reset()
    await as_user(app_client, "ann", temp)
    assert (await app_client.get("/api/v1/firewalls")).json()[
        "detail"
    ] == "password_change_required"
    blob = " ".join(str(x.detail) for x in db_rows(app_client, select(AuditLog)))
    assert temp not in blob


async def test_reset_mfa_needs_admins_own_password_and_code(app_client: httpx.AsyncClient) -> None:
    await make_user(app_client, "boss", Role.admin)
    await make_user(app_client, "ann", Role.read_only)
    await enrol(app_client, "boss")
    ann = uid(app_client, "ann")
    with app_client.app.state.sessionmaker() as s:  # type: ignore[attr-defined]
        s.execute(update(User).where(User.username == "ann").values(mfa_enabled=True))
        s.add(MfaRecoveryCode(user_id=uuid.UUID(ann), code_hash="x" * 64))
        s.commit()
    path = f"{USERS}/{ann}/reset-mfa"
    assert (await post(app_client, path, {"password": "wrong-wrong-wrong"})).status_code == 401
    assert (await post(app_client, path, {"password": PASSWORD})).status_code == 401  # no code
    assert (
        await post(app_client, path, {"password": PASSWORD, "code": "000000"})
    ).status_code == 401
    assert db_rows(app_client, select(User.mfa_enabled).where(User.username == "ann")) == [True]
    done = await post(
        app_client, path, {"password": PASSWORD, "code": current_code(app_client, "boss")}
    )
    assert done.status_code == 200 and done.json()["mfa_enabled"] is False
    assert (
        db_rows(
            app_client, select(MfaRecoveryCode).where(MfaRecoveryCode.user_id == uuid.UUID(ann))
        )
        == []
    )
    actions = {r.action for r in db_rows(app_client, select(AuditLog))}
    assert "user.mfa_reset" in actions


async def test_wrong_confirmations_feed_the_lockout(app_client: httpx.AsyncClient) -> None:
    await make_user(app_client, "boss", Role.admin)
    await make_user(app_client, "ann", Role.read_only)
    await as_user(app_client, "boss")
    override(app_client, login_lockout_threshold=2, login_lockout_base_seconds=60)
    ann = uid(app_client, "ann")
    for _ in range(2):
        assert (
            await post(app_client, f"{USERS}/{ann}/reset-mfa", {"password": "wrong-wrong-wrong"})
        ).status_code == 401
    assert (
        await post(app_client, f"{USERS}/{ann}/reset-mfa", {"password": PASSWORD})
    ).status_code == 429
    assert get_settings().login_lockout_threshold == 50  # the override was per-test


async def test_pending_password_session_reaches_only_password_me_logout(
    app_client: httpx.AsyncClient,
) -> None:
    await make_user(app_client, "boss", Role.admin)
    await as_user(app_client, "boss")
    temp = (await post(app_client, USERS, {"username": "fresh", "role": "admin"})).json()[
        "temporary_password"
    ]
    await as_user(app_client, "fresh", temp)
    allowed = {
        ("GET", "/api/v1/auth/me"),
        ("POST", "/api/v1/auth/logout"),
        ("POST", "/api/v1/auth/password"),
    }
    sample = str(uuid.uuid4())
    checked = 0
    for route in _flatten_routes(app_client.app.routes):  # type: ignore[attr-defined]
        dependant = getattr(route, "dependant", None)
        if dependant is None or not (_dependant_calls(dependant) & RBAC_DEPENDENCIES):
            continue
        path = route.path
        for token in ("{firewall_id}", "{change_id}", "{uuid}", "{id}", "{user_id}"):
            path = path.replace(token, sample)
        for method in route.methods or ():
            if (method, route.path) in allowed or "{" in path:
                continue
            resp = await app_client.request(
                method, path, headers=csrf_headers(app_client), json={} if method != "GET" else None
            )
            assert (
                resp.status_code == 403 and resp.json().get("detail") == "password_change_required"
            ), (method, path, resp.status_code)
            checked += 1
    assert checked > 40
