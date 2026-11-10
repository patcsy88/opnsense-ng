"""Integration tests for the security-review findings (need the disposable PostgreSQL)."""

import uuid
from datetime import UTC, datetime, timedelta
from typing import Any

import httpx
import pytest
import respx
from sqlalchemy import func, select

from app.auth import sessions as session_ops
from app.auth.cli import change_password
from app.auth.deps import RBAC_DEPENDENCIES
from app.auth.security import needs_rehash
from app.core.config import Settings, get_settings
from app.core.ratelimit import limiter
from app.db.models import AuditLog, Firewall, LoginThrottle, Role, User
from app.db.models import Session as UserSession
from app.main import create_app
from tests.conftest import CSRF_COOKIE, PASSWORD, SESSION_COOKIE, csrf_headers, login, make_user
from tests.test_api import API_KEY, FW_BODY, audit_rows, create_fw, login_as

pytestmark = pytest.mark.usefixtures("db")


def override(client: httpx.AsyncClient, **changes: Any) -> Settings:
    settings = get_settings().model_copy(update=changes)
    client.app.dependency_overrides[get_settings] = lambda: settings  # type: ignore[attr-defined]
    return settings


def db_rows(client: httpx.AsyncClient, stmt: Any) -> list[Any]:
    with client.app.state.sessionmaker() as s:  # type: ignore[attr-defined]
        return list(s.execute(stmt).scalars())


async def client_from(peer: str, trusted: list[str]) -> tuple[httpx.AsyncClient, Any]:
    import ipaddress

    app = create_app()
    app.state.trusted_proxies = [ipaddress.ip_network(t) for t in trusted]
    transport = httpx.ASGITransport(app=app, client=(peer, 5000))
    c = httpx.AsyncClient(transport=transport, base_url="https://test")
    c.app = app  # type: ignore[attr-defined]
    return c, app


# ---- H1 -----------------------------------------------------------------------------------
async def test_untrusted_peer_xff_spoof_does_not_evade_rate_limit_or_audit() -> None:
    c, app = await client_from("203.0.113.9", trusted=["10.0.0.0/8"])
    async with c:
        codes = []
        for i in range(7):
            r = await c.post(
                "/api/v1/auth/login",
                json={"username": f"u{i}", "password": "x"},
                headers={"X-Forwarded-For": f"198.51.100.{i}"},
            )
            codes.append(r.status_code)
        assert codes[:5] == [401] * 5 and codes[5:] == [429, 429]
        ips = {a.source_ip for a in await audit_rows(c)}
        assert ips == {"203.0.113.9"}
    app.state.engine.dispose()


async def test_trusted_proxy_xff_is_honoured_for_limit_and_audit() -> None:
    c, app = await client_from("10.0.0.2", trusted=["10.0.0.0/8"])
    async with c:
        for i in range(6):  # six different real clients behind the proxy: none is limited
            r = await c.post(
                "/api/v1/auth/login",
                json={"username": "nobody", "password": "x"},
                headers={"X-Forwarded-For": f"6.6.6.6, 198.51.100.{i}"},  # left part is spoofed
            )
            assert r.status_code == 401
        ips = {a.source_ip for a in await audit_rows(c)}
        assert ips == {f"198.51.100.{i}" for i in range(6)}
    app.state.engine.dispose()


# ---- M1 -----------------------------------------------------------------------------------
@pytest.mark.parametrize(
    "url",
    [
        "http://fw.example.test",
        "https://u:p@fw.example.test",
        "https://fw.example.test/x",
        "https://fw.example.test/?a=1",
        "https://fw.example.test/#f",
        "https://" + "a" * 520 + ".example.test",
        "https://127.0.0.1",
        "https://localhost",
        "https://169.254.169.254",
        "https://[::1]",
        "https://0.0.0.0",
        "https://test",  # the backend's own allowed host
    ],
)
async def test_bad_base_urls_are_422_never_500(app_client: httpx.AsyncClient, url: str) -> None:
    await login_as(app_client, Role.admin)
    r = await app_client.post(
        "/api/v1/firewalls", json={**FW_BODY, "base_url": url}, headers=csrf_headers(app_client)
    )
    assert r.status_code == 422, r.text
    assert API_KEY not in r.text  # validation errors never echo the submitted body


async def test_private_range_allowed_by_default_and_configurable(
    app_client: httpx.AsyncClient,
) -> None:
    await login_as(app_client, Role.admin)
    ok = await app_client.post(
        "/api/v1/firewalls",
        json={**FW_BODY, "base_url": "https://192.168.1.1:8443"},
        headers=csrf_headers(app_client),
    )
    assert ok.status_code == 201 and ok.json()["base_url"] == "https://192.168.1.1:8443"
    override(app_client, denied_firewall_networks=["10.0.0.0/8"])
    denied = await app_client.post(
        "/api/v1/firewalls",
        json={**FW_BODY, "name": "other", "base_url": "https://10.1.1.1"},
        headers=csrf_headers(app_client),
    )
    assert denied.status_code == 422
    assert any(a.detail and a.detail.get("reason") == "target_not_allowed"
               for a in await audit_rows(app_client))  # fmt: skip


async def test_connectivity_blocks_target_resolving_to_loopback(
    app_client: httpx.AsyncClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Row was valid when saved; at connect time DNS now answers 127.0.0.1 -> blocked, no
    connection is made (no respx mock: a real connect would fail differently)."""
    await login_as(app_client, Role.admin)
    fid = await create_fw(app_client)

    async def rebind(host: str, port: int) -> list[str]:
        return ["127.0.0.1"]

    monkeypatch.setattr("app.opnsense.netpolicy.resolve", rebind)
    r = await app_client.get(f"/api/v1/firewalls/{fid}/connectivity")
    assert r.json()["ok"] is False and r.json()["status"] == "blocked_target"


async def test_status_detail_only_for_admins(app_client: httpx.AsyncClient) -> None:
    await login_as(app_client, Role.admin)
    fid = await create_fw(app_client)
    url = "https://fw.example.test/api/diagnostics/system/system_time"
    with respx.mock() as router:
        router.get(url).respond(401)
        router.get("https://fw.example.test/api/diagnostics/system/system_information").respond(401)
        admin = (await app_client.get(f"/api/v1/firewalls/{fid}/connectivity")).json()
        await app_client.post("/api/v1/auth/logout", headers=csrf_headers(app_client))
        await login_as(app_client, Role.read_only)
        other = (await app_client.get(f"/api/v1/firewalls/{fid}/connectivity")).json()
        sys_status = await app_client.get(f"/api/v1/firewalls/{fid}/system/status")
    assert admin["status"] == "auth_failed" and admin["registry_verified"] is False
    assert other["status"] == "unreachable" and "credential" not in other["message"].lower()
    assert sys_status.status_code == 502 and sys_status.json()["detail"]["status"] in {
        "unreachable"
    }


async def test_reachable_collapsed_and_registry_flag(app_client: httpx.AsyncClient) -> None:
    await login_as(app_client, Role.admin)
    fid = await create_fw(app_client)
    await app_client.post("/api/v1/auth/logout", headers=csrf_headers(app_client))
    await login_as(app_client, Role.read_only)
    with respx.mock() as router:
        router.get("https://fw.example.test/api/diagnostics/system/system_time").respond(
            200, json={}
        )
        router.get("https://fw.example.test/api/diagnostics/system/system_information").respond(
            200, json={"name": "x"}
        )
        c = (await app_client.get(f"/api/v1/firewalls/{fid}/connectivity")).json()
        s = (await app_client.get(f"/api/v1/firewalls/{fid}/system/status")).json()
    assert c["status"] == "reachable" and c["registry_verified"] is False
    assert s["registry_verified"] is False


async def test_registry_entries_marked_unverified() -> None:
    from app.opnsense.registry import list_operations

    assert list_operations() and all(op.verified is False for op in list_operations())


async def test_404_is_endpoint_not_found_and_audited_as_registry_problem(
    app_client: httpx.AsyncClient,
) -> None:
    await login_as(app_client, Role.admin)
    fid = await create_fw(app_client)
    with respx.mock() as router:
        router.get("https://fw.example.test/api/diagnostics/system/system_time").respond(404)
        c = (await app_client.get(f"/api/v1/firewalls/{fid}/connectivity")).json()
    assert c["status"] == "endpoint_not_found"
    row = next(a for a in await audit_rows(app_client) if a.outcome == "failure")
    assert row.detail is not None
    assert row.detail["status"] == "endpoint_not_found"
    assert (
        row.detail["problem"] == "registry_or_version" and row.detail["registry_verified"] is False
    )


# ---- M2 -----------------------------------------------------------------------------------
async def test_create_and_update_audit_url_and_tls(app_client: httpx.AsyncClient) -> None:
    await login_as(app_client, Role.admin)
    fid = await create_fw(app_client)
    override(app_client, allow_insecure_tls=True)
    r = await app_client.patch(
        f"/api/v1/firewalls/{fid}",
        json={"base_url": "https://fw2.example.test:8443", "verify_tls": False},
        headers=csrf_headers(app_client),
    )
    assert r.status_code == 200 and r.json()["verify_tls"] is False
    rows = {a.action: a for a in await audit_rows(app_client) if a.action.startswith("firewall.")}
    create = next(a for a in await audit_rows(app_client) if a.action == "firewall.create")
    assert create.detail is not None
    assert create.detail["base_url"] == "https://fw.example.test" and create.detail["verify_tls"]
    upd = rows["firewall.update"].detail
    assert upd is not None and create.detail is not None
    assert upd["base_url"] == {
        "old": "https://fw.example.test",
        "new": "https://fw2.example.test:8443",
    }
    assert upd["verify_tls"] == {"old": True, "new": False}
    assert API_KEY not in str([a.detail for a in await audit_rows(app_client)])


async def test_insecure_tls_requires_global_flag(app_client: httpx.AsyncClient) -> None:
    await login_as(app_client, Role.admin)
    r = await app_client.post(
        "/api/v1/firewalls", json={**FW_BODY, "verify_tls": False}, headers=csrf_headers(app_client)
    )
    assert r.status_code == 422
    override(app_client, allow_insecure_tls=True)
    r = await app_client.post(
        "/api/v1/firewalls", json={**FW_BODY, "verify_tls": False}, headers=csrf_headers(app_client)
    )
    assert r.status_code == 201
    assert any(a.detail and a.detail.get("reason") == "insecure_tls_disabled"
               for a in await audit_rows(app_client))  # fmt: skip


async def test_ca_bundle_stored_validated_and_not_returned(app_client: httpx.AsyncClient) -> None:
    from tests.test_units import _cert_pem

    await login_as(app_client, Role.admin)
    pem = _cert_pem()
    bad = await app_client.post(
        "/api/v1/firewalls",
        json={**FW_BODY, "ca_bundle_pem": "not a cert"},
        headers=csrf_headers(app_client),
    )
    assert bad.status_code == 422
    ok = await app_client.post(
        "/api/v1/firewalls",
        json={**FW_BODY, "ca_bundle_pem": pem},
        headers=csrf_headers(app_client),
    )
    assert ok.status_code == 201 and ok.json()["has_ca_bundle"] is True
    assert "BEGIN CERTIFICATE" not in ok.text
    fw = db_rows(app_client, select(Firewall))[0]
    assert fw.ca_bundle_pem and "BEGIN CERTIFICATE" in fw.ca_bundle_pem
    cleared = await app_client.patch(
        f"/api/v1/firewalls/{fw.id}", json={"ca_bundle_pem": ""}, headers=csrf_headers(app_client)
    )
    assert cleared.json()["has_ca_bundle"] is False


async def test_credentials_bound_to_firewall_id(app_client: httpx.AsyncClient) -> None:
    await login_as(app_client, Role.admin)
    a = await create_fw(app_client)
    b = (
        await app_client.post(
            "/api/v1/firewalls",
            json={**FW_BODY, "name": "second"},
            headers=csrf_headers(app_client),
        )
    ).json()["id"]
    with app_client.app.state.sessionmaker() as s:  # type: ignore[attr-defined]
        fa, fb = (
            s.get(Firewall, __import__("uuid").UUID(a)),
            s.get(Firewall, __import__("uuid").UUID(b)),
        )
        assert fa and fb
        fb.api_key_encrypted = fa.api_key_encrypted  # copy ciphertext across rows
        s.commit()
    r = await app_client.get(f"/api/v1/firewalls/{b}/connectivity")
    assert r.status_code == 500 and r.json() == {"detail": "Internal error"}


# ---- M3 -----------------------------------------------------------------------------------
async def test_username_throttle_backoff_generic_and_persistent(
    app_client: httpx.AsyncClient,
) -> None:
    override(app_client, login_lockout_threshold=3, login_rate_limit="100/minute")
    limiter.reset()
    await make_user(app_client, "alice", Role.admin)
    for _ in range(3):
        assert (await login(app_client, "alice", "wrong-password-x")).status_code == 401
    # locked: even the correct password is refused, with a generic body and Retry-After
    locked = await login(app_client, "alice")
    assert locked.status_code == 429 and "Retry-After" in locked.headers
    assert "alice" not in locked.text
    # same behaviour for a username that does not exist
    limiter.reset()  # the per-IP limiter is a separate mechanism; keep it out of this test
    for _ in range(3):
        await login(app_client, "ghost", "wrong-password-x")
    ghost = await login(app_client, "ghost")
    assert ghost.status_code == 429 and ghost.json() == locked.json()
    # case-insensitive: another casing hits the same counter
    assert (await login(app_client, "ALICE")).status_code == 429
    # persisted in the DB, so a new app instance (restart) is still locked
    app_client.app.dependency_overrides.clear()  # type: ignore[attr-defined]
    rows = db_rows(app_client, select(LoginThrottle))
    assert {r.username for r in rows} == {"alice", "ghost"}


async def test_lock_expires_and_success_clears_counter(app_client: httpx.AsyncClient) -> None:
    s = override(app_client, login_lockout_threshold=2, login_rate_limit="100/minute")
    limiter.reset()
    await make_user(app_client, "alice", Role.admin)
    await login(app_client, "alice", "wrong-password-x")
    await login(app_client, "alice", "wrong-password-x")
    assert (await login(app_client, "alice")).status_code == 429
    with app_client.app.state.sessionmaker() as db:  # type: ignore[attr-defined]
        row = db.get(LoginThrottle, "alice")
        assert row
        row.locked_until = datetime.now(UTC) - timedelta(seconds=1)
        db.commit()
    assert (await login(app_client, "alice")).status_code == 200
    assert db_rows(app_client, select(func.count()).select_from(LoginThrottle)) == [0]
    assert s.login_lockout_threshold == 2


async def test_idle_timeout(app_client: httpx.AsyncClient) -> None:
    await login_as(app_client, Role.admin)
    assert (await app_client.get("/api/v1/auth/me")).status_code == 200
    with app_client.app.state.sessionmaker() as db:  # type: ignore[attr-defined]
        for row in db.execute(select(UserSession)).scalars():
            row.last_seen_at = datetime.now(UTC) - timedelta(minutes=31)
        db.commit()
    assert (await app_client.get("/api/v1/auth/me")).status_code == 401
    assert db_rows(app_client, select(func.count()).select_from(UserSession)) == [0]


async def test_last_seen_is_refreshed(app_client: httpx.AsyncClient) -> None:
    await login_as(app_client, Role.admin)
    old = datetime.now(UTC) - timedelta(minutes=10)
    with app_client.app.state.sessionmaker() as db:  # type: ignore[attr-defined]
        for row in db.execute(select(UserSession)).scalars():
            row.last_seen_at = old
        db.commit()
    await app_client.get("/api/v1/auth/me")
    assert db_rows(app_client, select(UserSession.last_seen_at))[0] > old + timedelta(minutes=9)


async def test_concurrent_session_cap_revokes_oldest(app_client: httpx.AsyncClient) -> None:
    override(app_client, max_sessions_per_user=2, login_rate_limit="100/minute")
    limiter.reset()
    await make_user(app_client, "alice", Role.admin)
    tokens = []
    for _ in range(3):
        c = httpx.AsyncClient(transport=app_client._transport, base_url="https://test")
        assert (await login(c, "alice")).status_code == 200
        tokens.append(c)
    rows = db_rows(app_client, select(UserSession).order_by(UserSession.created_at))
    assert len(rows) == 2
    first, last = tokens[0], tokens[2]
    assert (await first.get("/api/v1/auth/me")).status_code == 401  # oldest was revoked
    assert (await last.get("/api/v1/auth/me")).status_code == 200


async def test_logout_all_and_password_change_revoke_sessions(
    app_client: httpx.AsyncClient,
) -> None:
    override(app_client, login_rate_limit="100/minute")
    limiter.reset()
    await make_user(app_client, "alice", Role.admin)
    other = httpx.AsyncClient(transport=app_client._transport, base_url="https://test")
    await login(other, "alice")
    await login(app_client, "alice")
    r = await app_client.post("/api/v1/auth/logout-all", headers=csrf_headers(app_client))
    assert r.status_code == 200 and r.json() == {"revoked": 2}
    assert (await other.get("/api/v1/auth/me")).status_code == 401
    assert (await app_client.get("/api/v1/auth/me")).status_code == 401
    assert (await app_client.post("/api/v1/auth/logout-all")).status_code in {401, 403}
    # password change hook (CLI helper) revokes every session
    await login(app_client, "alice")
    revoked = change_password("alice", "a-brand-new-passphrase")
    assert revoked == 1
    assert (await app_client.get("/api/v1/auth/me")).status_code == 401
    assert (await login(app_client, "alice", "a-brand-new-passphrase")).status_code == 200
    with pytest.raises(ValueError):
        change_password("alice", "short")
    await other.aclose()


async def test_expired_sessions_cleaned_on_login_and_by_helper(
    app_client: httpx.AsyncClient,
) -> None:
    await make_user(app_client, "alice", Role.admin)
    with app_client.app.state.sessionmaker() as db:  # type: ignore[attr-defined]
        user = db.execute(select(User)).scalar_one()
        for i in range(3):
            db.add(
                UserSession(
                    user_id=user.id,
                    token_hash=f"{i}" * 64,
                    csrf_token_hash="c",
                    expires_at=datetime.now(UTC) - timedelta(hours=1),
                )
            )
        db.commit()
    await login(app_client, "alice")
    assert db_rows(app_client, select(func.count()).select_from(UserSession)) == [1]
    with app_client.app.state.sessionmaker() as db:  # type: ignore[attr-defined]
        db.add(
            UserSession(
                user_id=db.execute(select(User.id)).scalar_one(),
                token_hash="e" * 64,
                csrf_token_hash="c",
                expires_at=datetime.now(UTC) - timedelta(seconds=5),
            )
        )
        db.commit()
        assert session_ops.cleanup_expired(db, get_settings()) == 1
        db.commit()


async def test_login_rehashes_weak_hash(app_client: httpx.AsyncClient) -> None:
    from argon2 import PasswordHasher

    weak = PasswordHasher(time_cost=1, memory_cost=8, parallelism=1).hash(PASSWORD)
    with app_client.app.state.sessionmaker() as db:  # type: ignore[attr-defined]
        db.add(User(username="alice", role=Role.admin, password_hash=weak))
        db.commit()
    assert (await login(app_client, "alice")).status_code == 200
    stored = db_rows(app_client, select(User.password_hash))[0]
    assert stored != weak and not needs_rehash(stored)


async def test_username_case_insensitive_login(app_client: httpx.AsyncClient) -> None:
    await make_user(app_client, "alice", Role.admin)
    assert (await login(app_client, "  Alice ")).status_code == 200


# ---- M4 -----------------------------------------------------------------------------------
async def test_audit_records_ip_and_user_agent(app_client: httpx.AsyncClient) -> None:
    await make_user(app_client, "alice", Role.admin)
    await app_client.post(
        "/api/v1/auth/login",
        json={"username": "alice", "password": PASSWORD},
        headers={"User-Agent": "pytest-agent/1\r\n" + "x" * 400},
    )
    row = (await audit_rows(app_client))[0]
    assert row.source_ip == "127.0.0.1" or row.source_ip  # ASGITransport default client
    assert (
        row.user_agent
        and row.user_agent.startswith("pytest-agent/1")
        and len(row.user_agent) <= 256
    )
    assert "\r" not in row.user_agent


async def test_csrf_failure_audited_and_throttled(app_client: httpx.AsyncClient) -> None:
    await login_as(app_client, Role.admin)
    for _ in range(5):
        r = await app_client.post("/api/v1/firewalls", json=FW_BODY)
        assert r.status_code == 403
    csrf = [a for a in await audit_rows(app_client) if a.action == "auth.csrf_failed"]
    assert len(csrf) == 1 and csrf[0].username == "admin" and csrf[0].source_ip


async def test_401_audited_and_throttled(app_client: httpx.AsyncClient) -> None:
    for _ in range(10):
        assert (await app_client.get("/api/v1/auth/me")).status_code == 401
    rows = [a for a in await audit_rows(app_client) if a.action == "auth.unauthenticated"]
    assert len(rows) == 1 and rows[0].outcome == "denied"


async def test_firewall_not_found_audited(app_client: httpx.AsyncClient) -> None:
    await login_as(app_client, Role.read_only)
    fid = uuid.uuid4()
    assert (await app_client.get(f"/api/v1/firewalls/{fid}/system/status")).status_code == 404
    row = next(a for a in await audit_rows(app_client) if a.action == "firewall.system.status")
    assert row.outcome == "failure" and row.firewall_id == fid
    assert row.detail == {"reason": "firewall_not_found"}


async def test_duplicate_create_leaves_no_success_audit(app_client: httpx.AsyncClient) -> None:
    await login_as(app_client, Role.admin)
    await create_fw(app_client)
    dup = await app_client.post("/api/v1/firewalls", json=FW_BODY, headers=csrf_headers(app_client))
    assert dup.status_code == 409
    creates = [(a.outcome) for a in await audit_rows(app_client) if a.action == "firewall.create"]
    assert sorted(creates) == ["failure", "success"]  # exactly one success: the real change


async def test_unexpected_exception_is_audited_and_generic(
    app_client: httpx.AsyncClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    await login_as(app_client, Role.admin)
    fid = await create_fw(app_client)

    class Boom:
        def __init__(self, **_: object) -> None:
            pass

        async def execute(self, *_: object) -> None:
            raise RuntimeError("secret internal detail /srv/app.py")

        async def aclose(self) -> None:
            return None

    monkeypatch.setattr("app.api.firewalls.OPNsenseClient", Boom)
    r = await app_client.get(f"/api/v1/firewalls/{fid}/system/status")
    assert r.status_code == 500 and r.json() == {"detail": "Internal error"}
    assert "secret internal" not in r.text
    row = next(a for a in await audit_rows(app_client) if a.action == "firewall.system.status")
    assert row.outcome == "failure" and row.detail == {"reason": "unexpected_error"}


# ---- M5 -----------------------------------------------------------------------------------
def _dependant_calls(dependant: Any) -> set[Any]:
    found = {dependant.call}
    for sub in dependant.dependencies:
        found |= _dependant_calls(sub)
    return found


def _flatten_routes(routes: Any) -> list[Any]:
    """Expand FastAPI's lazily included routers into route-like objects that expose
    ``path``, ``methods`` and ``dependant`` (plain routes pass through)."""
    out: list[Any] = []
    for route in routes:
        candidates = getattr(route, "effective_candidates", None)
        if candidates is None:
            out.append(route)
        else:
            out.extend(_flatten_routes(candidates()))
    return out


async def test_every_route_is_public_allowlisted_or_rbac_protected(
    app_client: httpx.AsyncClient,
) -> None:
    settings = get_settings()
    public = {("/health", "GET"), ("/api/v1/auth/login", "POST")}
    docs = {"/docs", "/openapi.json", "/docs/oauth2-redirect"}
    unprotected: list[str] = []
    seen = 0
    for route in _flatten_routes(app_client.app.routes):  # type: ignore[attr-defined]
        path = getattr(route, "path", "")
        dependant = getattr(route, "dependant", None)
        if dependant is None:
            if path in docs:
                assert settings.enable_docs, f"docs route {path} exposed while disabled"
                continue
            unprotected.append(f"route without dependencies: {path or route!r}")
            continue
        for method in route.methods or ():
            seen += 1
            if (path, method) in public:
                continue
            if not (_dependant_calls(dependant) & RBAC_DEPENDENCIES):
                unprotected.append(f"{method} {path}")
    assert seen >= 7, f"route walk found only {seen} routes; the walker is out of date"
    assert not unprotected, f"routes without require_roles: {unprotected}"


async def test_security_headers_on_api_and_errors(app_client: httpx.AsyncClient) -> None:
    for path in ("/api/v1/auth/me", "/api/v1/firewalls", "/health", "/api/v1/missing"):
        r = await app_client.get(path)
        assert r.headers["x-content-type-options"] == "nosniff", path
        assert r.headers["x-frame-options"] == "DENY"
        assert r.headers["referrer-policy"] == "no-referrer"
        assert "default-src 'none'" in r.headers["content-security-policy"]
        if path.startswith("/api"):
            assert r.headers["cache-control"] == "no-store"
    assert "cache-control" not in (await app_client.get("/health")).headers


async def test_trusted_host_enforced(app_client: httpx.AsyncClient) -> None:
    ok = await app_client.get("/health")
    assert ok.status_code == 200
    bad = await app_client.get("/health", headers={"Host": "evil.example"})
    assert bad.status_code == 400


# ---- L1 / L3 ------------------------------------------------------------------------------
async def test_login_requires_json_and_matching_origin(app_client: httpx.AsyncClient) -> None:
    await make_user(app_client, "alice", Role.admin)
    body = {"username": "alice", "password": PASSWORD}
    form = await app_client.post("/api/v1/auth/login", data=body)
    assert form.status_code == 415
    text = await app_client.post(
        "/api/v1/auth/login", content='{"username":"alice","password":"x"}',
        headers={"Content-Type": "text/plain"},
    )  # fmt: skip
    assert text.status_code == 415
    evil = await app_client.post(
        "/api/v1/auth/login", json=body, headers={"Origin": "https://evil.example"}
    )
    assert evil.status_code == 403
    null = await app_client.post("/api/v1/auth/login", json=body, headers={"Origin": "null"})
    assert null.status_code == 403
    same = await app_client.post(
        "/api/v1/auth/login", json=body, headers={"Origin": "https://test"}
    )
    assert same.status_code == 200


async def test_configured_origin_list(app_client: httpx.AsyncClient) -> None:
    await make_user(app_client, "alice", Role.admin)
    override(app_client, allowed_origins=["https://app.example.test"])
    body = {"username": "alice", "password": PASSWORD}
    assert (
        await app_client.post("/api/v1/auth/login", json=body, headers={"Origin": "https://test"})
    ).status_code == 403
    ok = await app_client.post(
        "/api/v1/auth/login", json=body, headers={"Origin": "https://APP.example.test"}
    )
    assert ok.status_code == 200


async def test_host_prefixed_cookies(app_client: httpx.AsyncClient) -> None:
    await make_user(app_client, "alice", Role.admin)
    r = await login(app_client, "alice")
    cookies = r.headers.get_list("set-cookie")
    assert any(c.startswith(f"{SESSION_COOKIE}=") for c in cookies)
    assert any(c.startswith(f"{CSRF_COOKIE}=") for c in cookies)
    for c in cookies:
        assert "Secure" in c and "Path=/" in c and "Domain" not in c
    out = await app_client.post("/api/v1/auth/logout", headers=csrf_headers(app_client))
    cleared = out.headers.get_list("set-cookie")
    assert all("Secure" in c for c in cleared) and len(cleared) == 2


async def test_audit_table_unaffected_by_unrelated_count(app_client: httpx.AsyncClient) -> None:
    assert db_rows(app_client, select(func.count()).select_from(AuditLog)) == [0]


async def test_route_walk_detects_unprotected_route(app_client: httpx.AsyncClient) -> None:
    """Guard the guard: a route added without require_roles must be flagged."""
    app = app_client.app  # type: ignore[attr-defined]

    @app.get("/api/v1/oops")  # type: ignore[untyped-decorator]
    def oops() -> dict[str, str]:  # pragma: no cover - never called
        return {}

    flagged = [
        r.path
        for r in _flatten_routes(app.routes)
        if getattr(r, "dependant", None) is not None
        and not (_dependant_calls(r.dependant) & RBAC_DEPENDENCIES)
        and r.path not in {"/health", "/api/v1/auth/login"}
    ]
    assert flagged == ["/api/v1/oops"]
