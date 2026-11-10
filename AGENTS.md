# OPNsense Firewall Manager – Engineering Instructions

A self-hosted PWA for managing OPNsense firewalls through the OPNsense REST API.
OpenCode is a development-time tool only. It is not a runtime dependency.

## Architecture (non-negotiable)

- **Frontend:** React + TypeScript, Vite PWA/Workbox, Tailwind CSS + shadcn/ui. Located in `frontend/`.
- **Backend:** Python + FastAPI. Located in `backend/`. This is the security boundary.
- **Database:** PostgreSQL (users, sessions, audit log, encrypted firewall credentials).
- **Realtime:** SSE preferred, WebSocket where bidirectional is required.
- **Deployment:** Docker Compose with Caddy as reverse proxy and TLS terminator.
- Browser never talks to OPNsense. Backend only.
- All firewall operations go through the API capability registry (`backend/app/opnsense/registry/`). No arbitrary URL construction, no shell, no direct DB/config.xml manipulation.
- Unsupported operations are listed as unsupported. Do not work around them.
- Design for multiple firewall instances from the start (every operation takes a `firewall_id`).

## Security rules

- Never hardcode secrets. Never read, print or commit `.env*`, API keys or secrets.
- OPNsense credentials are encrypted at rest and never sent to the browser, local storage or service-worker caches.
- Service worker must not cache API responses containing firewall data. Cache static assets only.
- Every state-changing endpoint: authentication, RBAC check, CSRF protection, input validation, audit record.
- Roles: `admin`, `network_admin`, `security_admin`, `read_only`. Default deny.
- Config changes are staged → validated → reviewed → explicitly applied. Use revision/stale checks to prevent concurrent overwrites.
- Destructive actions (reboot, shutdown, firmware upgrade, deleting rules, disabling WAN/LAN/management interfaces) require extra confirmation and elevated privilege.

## Coding standards

- Python: type hints everywhere, Pydantic models for all request/response schemas, Ruff for lint and format, pytest.
- TypeScript: `strict` mode, no `any` without a justifying comment, ESLint, Vitest, Playwright for e2e.
- Small modules, one per functional area (dashboard, interfaces, rules, aliases, nat, logs, vpn, dhcp_dns, services, system).
- Keep changes small and independently testable. Write tests with the change.
- Comment only where behaviour is non-obvious.
- Normalise OPNsense responses in the backend; the frontend consumes our schema, not raw OPNsense JSON.
- Handle timeouts, retries and API outages explicitly. No silent failures.

## Workflow

Understand → Plan → Design → Implement → Test → Review → Validate → Document → Release.

Human approval is required before:
- significant architectural changes (record an ADR in `docs/adr/`)
- security-sensitive changes
- dependency additions or upgrades
- production releases

## Agent boundaries

- Do not run destructive shell commands (`rm -rf`, `git push --force`, `docker system prune`, etc.).
- Do not call a production firewall. Tests use mocked OPNsense responses or a disposable lab instance.
- Delegate to specialised agents (see `opencode.json` and `.opencode/agents/`). Do not coordinate agents unnecessarily for small tasks.

## Commands (fill in as the project is created)

- Backend tests: `cd backend && pytest`
- Backend lint: `cd backend && ruff check . && ruff format --check .`
- Frontend tests: `cd frontend && npm test`
- Frontend lint: `cd frontend && npm run lint && npm run typecheck`
- E2E: `cd frontend && npx playwright test`
- Stack: `docker compose up`

## Reference docs

- `docs/architecture.md`
- `docs/adr/`
- `docs/api-integration.md`
- `docs/security-requirements.md`
- `docs/development-guidelines.md`
- `docs/deployment.md`
- `docs/roadmap.md`
