# Backend (FastAPI)

Security boundary between the PWA and OPNsense. Python 3.15, dependencies pinned in `pyproject.toml` (ADR-0003).

## Setup
```sh
uv venv --python 3.15 .venv
uv pip install --python .venv/bin/python -e ".[dev]"   # or install the pinned list directly
```

## Configuration (environment; the app fails fast if a required value is missing)
List values are comma separated (`A,B`) or a JSON list.

| Variable | Notes |
|---|---|
| `DATABASE_URL` | `postgresql://user:pw@host:5432/db` |
| `SESSION_SECRET` | >= 32 chars. Keys the HMAC that binds each session's CSRF token (rotating it invalidates existing CSRF bindings, i.e. users log in again) |
| `CREDENTIAL_ENCRYPTION_KEY` | Fernet key (comma-separated list for rotation, first encrypts). Generate: `python -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"` |
| `SESSION_TTL_MINUTES` | absolute session lifetime |
| `SESSION_IDLE_TIMEOUT_MINUTES` | idle timeout, default 30 |
| `MAX_SESSIONS_PER_USER` | default 5; logging in beyond that revokes the oldest |
| `ALLOWED_HOSTS` | accepted `Host` headers (TrustedHostMiddleware), default `localhost,127.0.0.1`. **Set to your public hostname in production.** Also treated as the backend's own names and refused as firewall targets |
| `ALLOWED_ORIGINS` | allowed `Origin` values for login, e.g. `https://fw-manager.example.com`. Empty = same-origin only (Origin must equal Host) |
| `TRUSTED_PROXIES` | IPs/CIDRs of reverse proxies (e.g. the Caddy container network). Default empty = `X-Forwarded-For` is ignored |
| `COOKIE_SECURE` | default true. `false` is refused unless `DEV_MODE=true` (cookies then lose the `__Host-` prefix) |
| `DEV_MODE` | default false; only for local plain-HTTP development |
| `ALLOW_INSECURE_TLS` | default false; must be true before any firewall may use `verify_tls=false`. Prefer a per-firewall `ca_bundle_pem` |
| `ALLOWED_FIREWALL_NETWORKS` / `DENIED_FIREWALL_NETWORKS` | CIDR lists. Default: RFC1918 and public addresses allowed. A non-empty allow list restricts targets to those networks; the deny list removes ranges. Loopback, link-local (incl. 169.254.169.254), unspecified, multicast and known cloud-metadata addresses are always denied |
| `LOGIN_LOCKOUT_THRESHOLD` / `_BASE_SECONDS` / `_MAX_SECONDS` | per-username backoff, defaults 5 / 30 / 900 |
| optional | `LOGIN_RATE_LIMIT` (`5/minute`), `DEFAULT_RATE_LIMIT` (`120/minute`), `ENABLE_DOCS` (false), `OPNSENSE_*` timeouts/retries |

### Client IP and rate limiting
The rate limiter and the audit log use the *resolved* client IP. By default that is the socket peer.
`X-Forwarded-For` is honoured only when the direct peer is inside `TRUSTED_PROXIES`; the chain is then
read right to left and the first address that is not itself a trusted proxy is the client (so entries
a client prepends cannot choose its identity). Behind Caddy, set `TRUSTED_PROXIES` to the Caddy
network (and make sure the backend is not reachable except through Caddy). Rate-limit counters are
in-memory (single process).

### Login throttling and sessions
* Per-username backoff is stored in PostgreSQL (`login_throttle`), so it survives restarts, covers
  unknown usernames identically, and returns a generic 429 with `Retry-After`. Trade-off: someone can
  deliberately lock a known username for at most `LOGIN_LOCKOUT_MAX_SECONDS`.
* Sessions expire absolutely (`SESSION_TTL_MINUTES`) and after inactivity. Expired sessions are
  purged on every login; you can also run `python -m app.auth.cli cleanup-sessions` from cron.
* `POST /api/v1/auth/logout-all` revokes all of the caller's sessions.
* `python -m app.auth.cli set-password <user>` changes a password and revokes that user's sessions
  (`app.auth.cli.change_password` is the hook for a future change-password endpoint).
* Usernames are stored lowercase; migration 0002 lowercases existing rows (it fails if two accounts
  differ only by case: fix those first).

### Firewall targets and TLS
`base_url` must be `https://host[:port]` (no userinfo, path, query or fragment). The host policy is
checked when saving **and again on every connection**: the name is resolved, every address is
validated, and the connection goes to the validated IP while SNI/certificate verification keep using
the configured hostname (limits DNS rebinding). A per-firewall `ca_bundle_pem` (public CERTIFICATE
blocks only) is trusted instead of the system store. The HTTP client ignores proxy/`SSL_CERT_*`
environment variables. Non-admin roles only see `reachable`/`unreachable`.

## Run
```sh
.venv/bin/alembic upgrade head
.venv/bin/python -m app.auth.cli create <username> admin # bootstrap a user (prompts for password)
.venv/bin/uvicorn --factory app.main:create_app --host 127.0.0.1 --port 8000
```

## Test / lint
Tests need a **disposable** PostgreSQL (the schema is dropped/recreated). DB tests are skipped without `TEST_DATABASE_URL`.
```sh
docker run -d --rm --name opnsense-ng-test-pg -e POSTGRES_PASSWORD=testonly -e POSTGRES_DB=opnsense_test -p 127.0.0.1:55440:5432 postgres:17
export TEST_DATABASE_URL=postgresql://postgres:testonly@127.0.0.1:55440/opnsense_test
.venv/bin/pytest --cov=app
.venv/bin/ruff check . && .venv/bin/ruff format --check .
.venv/bin/mypy app tests
.venv/bin/pip-audit
```
OPNsense is always mocked with respx; no real firewall is contacted.

## Notes
- DB access is synchronous (psycopg, sync endpoints in the threadpool) because SQLAlchemy asyncio needs `greenlet`, which is not an approved dependency.
- Rate limiting uses in-memory storage (single process); see "Client IP and rate limiting" above.
- Registry endpoints in `app/opnsense/registry/entries.py` are unverified against a real OPNsense (`verified=False`; surfaced as `registry_verified` in API responses). An HTTP 404 from OPNsense is reported as `endpoint_not_found` and audited as a registry/version problem.
- Firewall credential ciphertexts are bound to `<firewall id>:<field>`; rows written before this change still decrypt and are re-bound when the credentials are updated via `PATCH /api/v1/firewalls/{id}`.
