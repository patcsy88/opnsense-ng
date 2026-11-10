# Backend (FastAPI)

Security boundary between the PWA and OPNsense. Python 3.15, dependencies pinned in `pyproject.toml` (ADR-0003).

## Setup
```sh
uv venv --python 3.15 .venv
uv pip install --python .venv/bin/python -e ".[dev]"   # or install the pinned list directly
```

## Configuration (environment; the app fails fast if a required value is missing)
| Variable | Notes |
|---|---|
| `DATABASE_URL` | `postgresql://user:pw@host:5432/db` |
| `SESSION_SECRET` | >= 32 chars |
| `CREDENTIAL_ENCRYPTION_KEY` | Fernet key (comma-separated list for rotation, first encrypts). Generate: `python -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"` |
| `SESSION_TTL_MINUTES` | session lifetime |
| optional | `COOKIE_SECURE` (default true), `LOGIN_RATE_LIMIT` (`5/minute`), `DEFAULT_RATE_LIMIT` (`120/minute`), `ENABLE_DOCS` (false), `OPNSENSE_*` timeouts/retries |

## Run
```sh
.venv/bin/alembic upgrade head
.venv/bin/python -m app.auth.cli <username> admin        # bootstrap a user (prompts for password)
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
- Rate limiting uses in-memory storage (single process). Behind Caddy, client-IP handling (trusted proxy headers) must be configured before production.
- Registry endpoints in `app/opnsense/registry/entries.py` are unverified against a real OPNsense; check in a lab.
