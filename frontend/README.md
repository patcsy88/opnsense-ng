# Frontend

React + TypeScript PWA for the OPNsense Firewall Manager. It talks only to the backend through relative `/api/...` URLs (one typed client in `src/lib/api.ts`); it never builds OPNsense URLs.

Node 24 is the target (`engines`). Dependencies are pinned exactly (`.npmrc` `save-exact`) and limited to the list in ADR-0003.

## Scripts

| Script | Purpose |
|---|---|
| `npm run dev` | Vite dev server on :5173, proxies `/api` to `http://localhost:8000` |
| `npm run build` | typecheck, production build, then `scripts/check-sw.mjs` |
| `npm test` | Vitest + Testing Library + msw |
| `npm run lint` / `npm run typecheck` | ESLint / `tsc --noEmit` |
| `npm run e2e` | Playwright smoke test (API mocked by route interception; needs `npx playwright install chromium` once) |
| `npm run check:sw` | Assert the built service worker has no `/api` caching |
| `npm run icons` | Regenerate placeholder PNG icons |

## Backend contract

- Cookies: `__Host-session` (HttpOnly) and `__Host-csrf_token`; in DEV_MODE `session` / `csrf_token`. The client echoes the CSRF cookie in `X-CSRF-Token` on POST/PUT/PATCH/DELETE.
- Dev over plain HTTP works because the Vite proxy keeps requests same-origin and the backend falls back to unprefixed cookies when `COOKIE_SECURE=false`.
- Login is JSON only. 401 returns to the login page and clears cached data; 403, 415, 429 (with `Retry-After`) and network errors show distinct messages; failed loads offer Retry.
- Role checks in the UI only hide or disable controls. The backend enforces RBAC.

## Client-side storage

- `localStorage`: only the `theme` preference.
- React Query cache is in memory, cleared on 401/logout. Firewall secrets are never put in React state, query cache or mutation cache (the connections form posts directly and resets the form).
- The service worker precaches static build assets only; `/api/*` is `NetworkOnly` and excluded from the navigation fallback. Offline navigations get `/offline.html`, which contains no firewall data.

## Layout

```
src/lib        api client, zod schemas (mirror backend), theme, error mapping
src/components ui (shadcn-style), layout, protected route
src/features   auth, dashboard, firewalls
src/pages      route pages
scripts        icon generator, service worker check
```

## Container

`Dockerfile` builds with `node:24-alpine` and serves `dist` with `nginxinc/nginx-unprivileged:stable-alpine` on port 8080 (`nginx.conf`: SPA fallback, immutable cache for `/assets/`, no-cache for the shell and service worker). `/api` is not proxied; Caddy routes it.

## Known limits

- The backend's normalised system status has no CPU/memory/disk fields yet; the dashboard says so instead of inventing values.
- The firewall list endpoint is admin-only, so non-admins open the dashboard with `?fw=<id>`.
- There is no delete endpoint for connections; "disable" means turning TLS verification off, which uses the ConfirmDialog.
