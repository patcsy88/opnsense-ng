# ADR-0003: Backend language, runtime versions and Phase 1 stack

- Status: accepted (runtime decisions and Phase 1 dependency list approved by project owner on 2026-11-10)
- Date: 2026-11-10
- Deciders: project owner

## Context

The backend is a thin, network-bound layer: it proxies calls to the OPNsense API and PostgreSQL. The main risks are logic errors in RBAC, CSRF, the staged-change workflow and the registry allowlist, not memory safety or raw throughput. Runtime versions were checked on 2026-11-10 against endoflife.date and the Node.js release schedule.

## Decision

**Backend language:** Python with FastAPI. Rust was considered and rejected.

**Runtime versions**
- Python 3.15 (3.15.2 at time of writing; supported to 2031-10).
- Node.js 24 "Krypton" (maintenance LTS, supported to 2028-04-30). Used for frontend build, test and tooling only.

**Container base images:** `python:3.15-slim` (backend), `node:24-alpine` (frontend build stage only), plus current stable `postgres` and `caddy`.

**Phase 1 dependencies (approved)**
- Backend: fastapi, uvicorn, pydantic, pydantic-settings, sqlalchemy, alembic, psycopg, httpx, argon2-cffi, cryptography, itsdangerous, slowapi, structlog. Dev: pytest, pytest-asyncio, pytest-cov, respx, ruff, mypy, pip-audit.
- Frontend: react, react-dom, react-router-dom, @tanstack/react-query, tailwindcss, shadcn/ui (radix-ui, class-variance-authority, clsx, tailwind-merge, lucide-react), recharts, zod, vite, @vitejs/plugin-react, vite-plugin-pwa, typescript. Dev: vitest, @testing-library/react, @testing-library/jest-dom, jsdom, msw, @playwright/test, eslint, typescript-eslint, eslint-plugin-react-hooks.
- Excluded for now: Redis, Celery, Redux/Zustand, any OPNsense SDK.

## Consequences

- Matches the stack in the project brief and `AGENTS.md`; no changes to agent configuration are needed.
- Python 3.15 wheel check (2026-11-10, `uv --only-binary`): all backend runtime and dev dependencies resolve with prebuilt wheels, including psycopg-binary, argon2-cffi, cryptography and pydantic-core. Exception: `uvicorn[standard]` is not installable because its extras (pyyaml, httptools) have no 3.15 wheels. Use plain `uvicorn` (no `[standard]` extra) until they do; this was the only deviation from the list above.
- Node 24 is in maintenance LTS. Node 26 is the newer LTS, so a move can be considered later; the frontend toolchain should be verified on Node 24 first.
- Exact versions are pinned at install time, followed by `pip-audit` and `npm audit`.

## Alternatives considered

- **Rust (axum, sqlx, reqwest):** small static binary and strong type discipline, but slower iteration, a different toolchain, and no meaningful performance gain for a network-bound proxy. Would require reworking `AGENTS.md`, `opencode.json` and the backend agent.
- **Python 3.14:** more mature wheel ecosystem. Kept as the fallback.
- **Node 26:** longest support window (to 2029-04-30) but newest, with less proven tooling compatibility.
- **Python 3.12 / Node 22:** rejected, as their support windows end too soon (2028-10 and 2027-04).
