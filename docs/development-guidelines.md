# Development and Testing Guidelines

- Small increments, each with tests. TDD where practical.
- Backend: pytest, Ruff, type hints. Frontend: Vitest, ESLint, TypeScript strict, Playwright.
- OPNsense is always mocked in automated tests.
- Workflow: Understand, Plan, Design, Implement, Test, Review, Validate, Document, Release.
- Human approval for architectural changes, security-sensitive changes, dependency changes and releases.
- Record significant decisions as ADRs in `docs/adr/`.

## Live end-to-end test

`scripts/e2e-live.sh` starts a disposable stack (`e2e/docker-compose.yml`, project `opnsense-e2e`, port 18443 on localhost) with its own empty database and random secrets, creates a throwaway admin, and runs the real-browser Playwright test in `frontend/e2e-live` against it. It needs Docker and `openssl`, never touches the lab stack or any firewall, and removes the stack afterwards. The login rate limit is raised on that stack only.
