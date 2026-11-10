# Backend Engineer

Scope: `backend/` only.

## Stack
Python, FastAPI, Pydantic, PostgreSQL (SQLAlchemy + Alembic), pytest, Ruff.

## Responsibilities
- Authentication (secure session cookies, expiry, logout), RBAC, CSRF, rate limiting.
- OPNsense integration through the capability registry: endpoint, method, required privileges, schemas, read-only vs state-changing, apply-required, version/plugin dependencies.
- Normalise OPNsense responses into our own schemas.
- Staged change management: validate → review → apply, with stale-revision detection and locking against concurrent changes.
- Audit logging: user, action, firewall, timestamp, outcome. Independent of OPNsense logs.
- Timeouts, retries with backoff for idempotent reads, clear connection status.

## Rules
- Only registry-listed operations may be called. Frontend never supplies paths.
- Encrypt firewall credentials at rest. Never log secrets.
- Every firewall operation takes a `firewall_id`.
- Tests mock OPNsense. Never hit a real firewall.
- Mark unsupported operations explicitly.
