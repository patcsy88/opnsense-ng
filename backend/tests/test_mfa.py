"""TOTP multi-factor authentication (ADR-0012)."""

import base64
import uuid
from datetime import timedelta
from typing import Any

import httpx
import pytest
from sqlalchemy import func, select, update

from app.auth import cli, mfa, totp
from app.auth.deps import RBAC_DEPENDENCIES
from app.core.config import get_settings
from app.core.ratelimit import limiter
from app.db.models import AuditLog, MfaChallenge, MfaRecoveryCode, Role, User, utcnow
from app.db.models import Session as UserSession
from tests.conftest import PASSWORD, csrf_headers, login, make_user
from tests.test_security import _dependant_calls, _flatten_routes, db_rows, override

pytestmark = pytest.mark.usefixtures("db")

MFA = "/api/v1/auth/mfa"
SECRET_B32 = base64.b32encode(b"12345678901234567890").decode().rstrip("=")


def test_totp_matches_rfc_6238_vectors() -> None:
    # RFC 6238 appendix B (SHA-1), last six digits of the published 8-digit values.
    for when, expected in ((59, "287082"), (1111111109, "081804"), (2000000000, "279037")):
        assert totp.code_at(SECRET_B32, when // 30) == expected


def test_totp_window_and_input_checks() -> None:
    now = 1_700_000_000.0
    step = totp.current_step(now)
    assert totp.matching_step(SECRET_B32, totp.code_at(SECRET_B32, step), now) == step
    assert totp.matching_step(SECRET_B32, totp.code_at(SECRET_B32, step - 1), now) == step - 1
    assert totp.matching_step(SECRET_B32, totp.code_at(SECRET_B32, step + 1), now) == step + 1
    assert totp.matching_step(SECRET_B32, totp.code_at(SECRET_B32, step - 2), now) is None
    for bad in ("", "12345", "1234567", "abcdef", "١٢٣٤٥٦"):
        assert totp.matching_step(SECRET_B32, bad, now) is None


def test_secret_uri_and_qr() -> None:
    secret = totp.new_secret()
    assert len(secret) == 32 and secret == secret.upper()
    uri = totp.otpauth_uri(secret, "al ice")
    assert uri.startswith("otpauth://totp/OPNsense%20Manager:al%20ice?secret=")
    assert "issuer=OPNsense%20Manager" in uri and "period=30" in uri
    matrix = totp.qr_matrix(uri)
    assert len(matrix) == len(matrix[0]) >= 21 and any(any(r) for r in matrix)


def current_code(client: httpx.AsyncClient, username: str, *, fresh: bool = True) -> str:
    """A valid code for the user's stored secret. Only three time steps are accepted at a time
    and each is single use, so by default the used-step marker is wound back first."""
    limiter.reset()
    with client.app.state.sessionmaker() as s:  # type: ignore[attr-defined]
        user = s.execute(select(User).where(User.username == username)).scalar_one()
        secret = mfa.load_secret(get_settings(), user)
        step = totp.current_step()
        if fresh:
            user.mfa_last_step = step - 2
            s.commit()
    assert secret is not None
    return totp.code_at(secret, step)


async def enrol(client: httpx.AsyncClient, username: str) -> list[str]:
    """Sign in (restricted or plain), enrol, and return the recovery codes."""
    assert (await login(client, username)).status_code == 200
    start = await client.post(
        f"{MFA}/enrol/start", json={"password": PASSWORD}, headers=csrf_headers(client)
    )
    assert start.status_code == 200, start.text
    code = current_code(client, username)
    done = await client.post(
        f"{MFA}/enrol/confirm", json={"code": code}, headers=csrf_headers(client)
    )
    assert done.status_code == 200, done.text
    return list(done.json()["recovery_codes"])


async def two_step(client: httpx.AsyncClient, username: str, code: str) -> httpx.Response:
    first = await login(client, username)
    assert first.status_code == 200 and first.json()["mfa_required"] is True
    return await client.post(
        "/api/v1/auth/login/mfa", json={"challenge": first.json()["challenge"], "code": code}
    )


def count(client: httpx.AsyncClient, model: Any) -> int:
    return int(db_rows(client, select(func.count()).select_from(model))[0])


async def test_enrolment_then_two_step_login(app_client: httpx.AsyncClient) -> None:
    override(app_client, mfa_required_roles=["admin"])
    await make_user(app_client, "alice", Role.admin)
    first = await login(app_client, "alice")
    assert first.status_code == 200 and first.json()["user"]["mfa_enrolment_required"] is True

    # restricted: me and logout work, everything else is refused
    me = await app_client.get("/api/v1/auth/me")
    assert me.json()["mfa_enrolment_required"] is True and me.json()["mfa_enabled"] is False
    blocked = await app_client.get("/api/v1/firewalls")
    assert blocked.status_code == 403 and blocked.json()["detail"] == "mfa_enrolment_required"

    wrong = await app_client.post(
        f"{MFA}/enrol/start", json={"password": "nope-nope-nope"}, headers=csrf_headers(app_client)
    )
    assert wrong.status_code == 401
    start = await app_client.post(
        f"{MFA}/enrol/start", json={"password": PASSWORD}, headers=csrf_headers(app_client)
    )
    body = start.json()
    assert len(body["secret"]) == 32 and body["otpauth_uri"].startswith("otpauth://totp/")
    assert len(body["qr"]) >= 21
    # the secret is encrypted at rest and never in the audit log
    with app_client.app.state.sessionmaker() as s:  # type: ignore[attr-defined]
        stored = s.execute(select(User.mfa_secret_encrypted)).scalar_one()
    assert stored is not None and body["secret"] not in stored

    bad = await app_client.post(
        f"{MFA}/enrol/confirm", json={"code": "000000"}, headers=csrf_headers(app_client)
    )
    assert bad.status_code == 401
    code = totp.code_at(body["secret"], totp.current_step())
    done = await app_client.post(
        f"{MFA}/enrol/confirm", json={"code": code}, headers=csrf_headers(app_client)
    )
    assert done.status_code == 200
    codes = done.json()["recovery_codes"]
    assert len(codes) == 10 and len(set(codes)) == 10
    assert (await app_client.get("/api/v1/firewalls")).status_code == 200  # no longer restricted
    status = (await app_client.get(MFA)).json()
    assert status == {"enabled": True, "required": True, "recovery_codes_left": 10}
    hashes = {r.code_hash for r in db_rows(app_client, select(MfaRecoveryCode))}
    assert len(hashes) == 10 and not hashes & {c.replace("-", "") for c in codes}

    # a new login now stops at the challenge: no session, no cookies
    app_client.cookies.clear()
    first = await login(app_client, "alice")
    assert first.status_code == 200 and first.json()["mfa_required"] is True
    assert first.json()["user"] is None and first.json()["csrf_token"] is None
    assert "set-cookie" not in first.headers
    assert (await app_client.get("/api/v1/auth/me")).status_code == 401

    wrong_code = await app_client.post(
        "/api/v1/auth/login/mfa", json={"challenge": first.json()["challenge"], "code": "000000"}
    )
    assert wrong_code.status_code == 401
    good = await app_client.post(
        "/api/v1/auth/login/mfa",
        json={"challenge": first.json()["challenge"], "code": current_code(app_client, "alice")},
    )
    assert good.status_code == 200 and good.json()["user"]["mfa_enabled"] is True
    assert (await app_client.get("/api/v1/auth/me")).status_code == 200

    actions = {r.action for r in db_rows(app_client, select(AuditLog))}
    assert {
        "mfa.enrol_start",
        "mfa.enable",
        "auth.mfa_challenge",
        "auth.mfa_login",
        "auth.login",
    } <= actions
    blob = " ".join(str(r.detail) for r in db_rows(app_client, select(AuditLog)))
    assert body["secret"] not in blob and code not in blob and first.json()["challenge"] not in blob


async def test_code_cannot_be_reused_and_challenge_is_single_use(
    app_client: httpx.AsyncClient,
) -> None:
    await make_user(app_client, "bob", Role.network_admin)
    await enrol(app_client, "bob")
    app_client.cookies.clear()
    code = current_code(app_client, "bob")
    assert (await two_step(app_client, "bob", code)).status_code == 200
    app_client.cookies.clear()
    limiter.reset()
    assert (await two_step(app_client, "bob", code)).status_code == 401  # same step: replay

    first = await login(app_client, "bob")
    token = first.json()["challenge"]
    ok = await app_client.post(
        "/api/v1/auth/login/mfa", json={"challenge": token, "code": current_code(app_client, "bob")}
    )
    assert ok.status_code == 200
    again = await app_client.post(
        "/api/v1/auth/login/mfa", json={"challenge": token, "code": current_code(app_client, "bob")}
    )
    assert again.status_code == 401


async def test_challenge_expiry_attempts_and_unknown(app_client: httpx.AsyncClient) -> None:
    await make_user(app_client, "cy", Role.read_only)
    await enrol(app_client, "cy")
    app_client.cookies.clear()
    unknown = await app_client.post(
        "/api/v1/auth/login/mfa", json={"challenge": "x" * 40, "code": "123456"}
    )
    assert unknown.status_code == 401

    first = await login(app_client, "cy")
    token = first.json()["challenge"]
    for _ in range(mfa.CHALLENGE_MAX_ATTEMPTS):
        limiter.reset()
        r = await app_client.post(
            "/api/v1/auth/login/mfa", json={"challenge": token, "code": "000000"}
        )
        assert r.status_code == 401
    assert count(app_client, MfaChallenge) == 0  # exhausted: the challenge is gone
    late = await app_client.post(
        "/api/v1/auth/login/mfa", json={"challenge": token, "code": current_code(app_client, "cy")}
    )
    assert late.status_code == 401

    first = await login(app_client, "cy")
    with app_client.app.state.sessionmaker() as s:  # type: ignore[attr-defined]
        s.execute(update(MfaChallenge).values(expires_at=utcnow() - timedelta(seconds=1)))
        s.commit()
    expired = await app_client.post(
        "/api/v1/auth/login/mfa",
        json={"challenge": first.json()["challenge"], "code": current_code(app_client, "cy")},
    )
    assert expired.status_code == 401


async def test_wrong_codes_feed_the_username_lockout(app_client: httpx.AsyncClient) -> None:
    await make_user(app_client, "dee", Role.admin)
    await enrol(app_client, "dee")
    app_client.cookies.clear()
    override(app_client, login_lockout_threshold=2, login_lockout_base_seconds=60)
    for _ in range(2):
        first = await login(app_client, "dee")
        if first.status_code != 200:
            break
        await app_client.post(
            "/api/v1/auth/login/mfa",
            json={"challenge": first.json()["challenge"], "code": "000000"},
        )
    locked = await login(app_client, "dee")
    assert locked.status_code == 429


async def test_recovery_code_logs_in_once(app_client: httpx.AsyncClient) -> None:
    await make_user(app_client, "eve", Role.admin)
    codes = await enrol(app_client, "eve")
    app_client.cookies.clear()
    used = codes[0]
    ok = await two_step(app_client, "eve", used.lower())
    assert ok.status_code == 200
    app_client.cookies.clear()
    assert (await two_step(app_client, "eve", used)).status_code == 401
    audit = db_rows(app_client, select(AuditLog).where(AuditLog.action == "auth.login"))
    assert any(
        a.detail and a.detail.get("mfa") == "recovery" and a.detail.get("recovery_codes_left") == 9
        for a in audit
    )
    assert used not in " ".join(str(r.detail) for r in db_rows(app_client, select(AuditLog)))


async def test_disable_regenerate_and_required_roles(app_client: httpx.AsyncClient) -> None:
    override(app_client, mfa_required_roles=["admin"])
    await make_user(app_client, "ann", Role.admin)
    await enrol(app_client, "ann")
    refused = await app_client.post(
        f"{MFA}/disable",
        json={"password": PASSWORD, "code": current_code(app_client, "ann")},
        headers=csrf_headers(app_client),
    )
    assert refused.status_code == 403  # required for admins

    other = await app_client.post("/api/v1/auth/logout", headers=csrf_headers(app_client))
    assert other.status_code == 204
    await make_user(app_client, "rob", Role.read_only)
    codes = await enrol(app_client, "rob")  # optional for read_only here
    # a second session of rob is ended when the codes are regenerated from this one
    transport = httpx.ASGITransport(app=app_client.app)  # type: ignore[attr-defined]
    second = httpx.AsyncClient(transport=transport, base_url="https://test")
    async with second:
        second.app = app_client.app  # type: ignore[attr-defined]
        assert (await two_step(second, "rob", codes[0])).status_code == 200
        assert count(app_client, UserSession) == 2
        regen = await app_client.post(
            f"{MFA}/recovery-codes",
            json={"password": PASSWORD, "code": current_code(app_client, "rob")},
            headers=csrf_headers(app_client),
        )
        assert regen.status_code == 200 and len(regen.json()["recovery_codes"]) == 10
        assert set(regen.json()["recovery_codes"]).isdisjoint(codes)
        assert (await second.get("/api/v1/auth/me")).status_code == 401
    bad = await app_client.post(
        f"{MFA}/disable",
        json={"password": "wrong-wrong-wrong", "code": "000000"},
        headers=csrf_headers(app_client),
    )
    assert bad.status_code == 401
    off = await app_client.post(
        f"{MFA}/disable",
        json={"password": PASSWORD, "code": current_code(app_client, "rob")},
        headers=csrf_headers(app_client),
    )
    assert off.status_code == 204
    assert (await app_client.get(MFA)).json()["enabled"] is False
    rob = db_rows(app_client, select(User).where(User.username == "rob"))[0]
    assert (
        db_rows(app_client, select(MfaRecoveryCode).where(MfaRecoveryCode.user_id == rob.id)) == []
    )
    app_client.cookies.clear()
    plain = await login(app_client, "rob")
    assert plain.json()["user"]["username"] == "rob"  # password only again, optional for this role


async def test_mfa_endpoints_need_csrf_and_state(app_client: httpx.AsyncClient) -> None:
    await make_user(app_client, "zed", Role.admin)
    assert (await login(app_client, "zed")).status_code == 200
    assert (
        await app_client.post(f"{MFA}/enrol/start", json={"password": PASSWORD})
    ).status_code == 403
    early = await app_client.post(
        f"{MFA}/enrol/confirm", json={"code": "123456"}, headers=csrf_headers(app_client)
    )
    assert early.status_code == 409
    no_mfa = await app_client.post(
        f"{MFA}/disable",
        json={"password": PASSWORD, "code": "123456"},
        headers=csrf_headers(app_client),
    )
    assert no_mfa.status_code == 409


async def test_restricted_session_reaches_only_enrolment_me_and_logout(
    app_client: httpx.AsyncClient,
) -> None:
    override(app_client, mfa_required_roles=["admin"])
    await make_user(app_client, "ivy", Role.admin)
    assert (await login(app_client, "ivy")).json()["user"]["mfa_enrolment_required"] is True
    allowed = {
        ("GET", "/api/v1/auth/me"),
        ("POST", "/api/v1/auth/logout"),
        ("GET", MFA),
        ("POST", f"{MFA}/enrol/start"),
        ("POST", f"{MFA}/enrol/confirm"),
        ("POST", f"{MFA}/disable"),
        ("POST", f"{MFA}/recovery-codes"),
    }
    sample = uuid.uuid4()
    for route in _flatten_routes(app_client.app.routes):  # type: ignore[attr-defined]
        dependant = getattr(route, "dependant", None)
        if dependant is None or not (_dependant_calls(dependant) & RBAC_DEPENDENCIES):
            continue
        path = route.path.replace("{firewall_id}", str(sample)).replace("{change_id}", str(sample))
        path = path.replace("{uuid}", str(sample)).replace("{id}", str(sample))
        for method in route.methods or ():
            if (method, route.path) in allowed or "{" in path:
                continue
            resp = await app_client.request(
                method, path, headers=csrf_headers(app_client), json={} if method != "GET" else None
            )
            assert (
                resp.status_code == 403 and resp.json().get("detail") == "mfa_enrolment_required"
            ), (method, route.path, resp.status_code)


async def test_cli_reset_clears_mfa_and_sessions(
    app_client: httpx.AsyncClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    await make_user(app_client, "lou", Role.admin)
    await enrol(app_client, "lou")
    monkeypatch.setattr(cli, "make_engine", lambda _url: app_client.app.state.engine)  # type: ignore[attr-defined]
    assert cli.reset_mfa("lou") == 1
    row = db_rows(app_client, select(User).where(User.username == "lou"))[0]
    assert row.mfa_enabled is False and row.mfa_secret_encrypted is None
    assert count(app_client, MfaRecoveryCode) == 0 and count(app_client, UserSession) == 0
    reset = db_rows(app_client, select(AuditLog).where(AuditLog.action == "mfa.cli_reset"))
    assert len(reset) == 1 and reset[0].username == "lou"
    with pytest.raises(LookupError):
        cli.reset_mfa("nobody")


def test_mfa_roles_setting_rejects_unknown_role() -> None:
    from app.core.config import Settings

    with pytest.raises(ValueError):
        Settings.model_validate({**get_settings().model_dump(), "mfa_required_roles": "root"})
