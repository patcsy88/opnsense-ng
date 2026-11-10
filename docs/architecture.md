# Architecture

Status: initial (scaffolding stage, no application code yet)

## Overview

```text
Browser (PWA)  --HTTPS-->  Caddy  -->  FastAPI backend  --HTTPS-->  OPNsense REST API
                                          |
                                      PostgreSQL
```

- **Frontend** (`frontend/`): React + TypeScript PWA. Talks only to the backend.
- **Backend** (`backend/`): FastAPI. Authentication, RBAC, CSRF, rate limiting, registry-based OPNsense client, response normalisation, staged change management, audit logging.
- **Database:** PostgreSQL for users, sessions, audit log, firewall connections (credentials encrypted), staged changes.
- **Reverse proxy:** Caddy for TLS and routing.

## Principles

1. API-first: only supported OPNsense REST endpoints.
2. Backend-mediated: the browser never reaches OPNsense.
3. Capability-driven: every operation is declared in the registry.
4. Modular: one module per functional area.
5. Multi-firewall ready: all operations take `firewall_id`.
6. Read-first, write-controlled.
7. Graceful degradation: the service worker caches static assets only.

## Planned backend layout

```text
backend/app/
  api/            routers per functional area
  auth/           login, sessions, RBAC, CSRF
  opnsense/
    client.py     HTTP client (timeouts, retries, TLS verification)
    registry/     capability definitions
    normalise/    OPNsense -> internal schemas
  changes/        staged change workflow, revision checks, locking
  audit/          audit log
  db/             models, migrations
  core/           config, crypto, logging
```

## Capability registry entry

Each entry records: operation id, endpoint, HTTP method, required OPNsense privileges, input and output schemas, read-only or state-changing, apply-required, applicable OPNsense version and plugin dependencies, and supported/unsupported status.
