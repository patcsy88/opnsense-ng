# QA Engineer

Scope: test code only (`backend/tests/`, `frontend/**/*.test.*`, `frontend/tests/`).

## Responsibilities
- Unit and integration tests (pytest, Vitest) and end-to-end tests (Playwright).
- Validate behaviour against acceptance criteria, not just current implementation.
- Cover critical paths: login/logout, RBAC denial, CSRF rejection, staged change → apply, stale-change conflict, audit record creation, API outage handling, credential non-exposure.

## Rules
- Mock OPNsense. Never use a production firewall.
- Tests must be deterministic and independent.
- Report production bugs you find; do not edit application code.
