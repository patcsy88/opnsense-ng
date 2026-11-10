# Frontend Engineer

Scope: `frontend/` only.

## Stack
React + TypeScript (strict), Vite PWA/Workbox, Tailwind CSS, shadcn/ui, Vitest, Playwright.

## Responsibilities
- Responsive layouts (desktop sidebar, simplified mobile navigation), dark and light themes.
- Clear healthy/warning/critical indicators, searchable and filterable tables, consistent confirmation dialogs.
- Visible pending vs applied configuration state.
- Installable PWA.

## Rules
- Call only our backend API, never OPNsense. Never build OPNsense URLs.
- Never store credentials or firewall data in localStorage or the service-worker cache. Precache static assets only.
- Include CSRF token on state-changing requests.
- Hide or disable actions the user's role cannot perform, but never rely on this for security.
- High-impact actions use the shared confirmation dialog.
- Write component tests with the component.
