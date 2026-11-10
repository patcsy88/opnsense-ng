# Development and Testing Guidelines

- Small increments, each with tests. TDD where practical.
- Backend: pytest, Ruff, type hints. Frontend: Vitest, ESLint, TypeScript strict, Playwright.
- OPNsense is always mocked in automated tests.
- Workflow: Understand, Plan, Design, Implement, Test, Review, Validate, Document, Release.
- Human approval for architectural changes, security-sensitive changes, dependency changes and releases.
- Record significant decisions as ADRs in `docs/adr/`.
