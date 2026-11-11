# Deployment

Status: Docker Compose stack (`caddy`, `frontend`, `backend`, `postgres`) smoke-tested on 2026-11-10 with Docker Desktop on macOS: all services healthy; SPA and fallback served; `/api` and `/health` routed through Caddy; HTTPS login with `__Host-` cookies; CSRF rejection; logout; audit rows record the real client IP (trusted-proxy handling works); public-IP firewall rejected. Not tested: a real OPNsense, a real certificate authority, or Linux hosts.

## Prerequisites

- Docker with Compose v2
- A hostname for the app (or `localhost` for local testing)
- Network path from the backend container to your OPNsense firewall(s), HTTPS only

## 1. Configure

```
cp .env.example .env
```

Fill in `.env` (never commit it). Generate secrets locally:

```
# SESSION_SECRET and POSTGRES_PASSWORD
python3 -c "import secrets; print(secrets.token_urlsafe(48))"
# CREDENTIAL_ENCRYPTION_KEY (Fernet)
python3 -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"
```

Back up `CREDENTIAL_ENCRYPTION_KEY` separately from the database. Without it, stored firewall credentials cannot be decrypted.

| Variable | Required | Purpose |
|---|---|---|
| `POSTGRES_PASSWORD` | yes | Database password |
| `SESSION_SECRET` | yes | At least 32 characters; keys the CSRF binding |
| `CREDENTIAL_ENCRYPTION_KEY` | yes | Encrypts firewall API credentials at rest |
| `ALLOWED_HOSTS` | yes | Accepted `Host` headers; use the public hostname |
| `SITE_ADDRESS` | yes for TLS | Hostname Caddy serves (default `localhost`) |
| `ALLOWED_ORIGINS` | no | Extra allowed origins for login; empty = same-origin |
| `TRUSTED_PROXIES` | no | Proxy addresses trusted for `X-Forwarded-For` (defaults to the compose subnet) |
| `ALLOWED_FIREWALL_NETWORKS` | no | Replaces the default private-only target policy |
| `ALLOW_INSECURE_TLS` | no | Permit `verify_tls=false` on firewalls (default false) |
| `SESSION_TTL_MINUTES` | no | Absolute session lifetime (default 60) |

More tuning variables (idle timeout, session cap, rate limits, lockout, timeouts) are listed in `backend/README.md`.

## 2. Start

```
docker compose up -d --build
```

The backend runs database migrations (`alembic upgrade head`) on start. `postgres` has a healthcheck and the backend waits for it.

## 3. Create the first user

There is no registration endpoint. Create an admin from the CLI (prompts for a password of 12 to 128 characters):

```
docker compose exec backend python -m app.auth.cli create <username> admin
```

Roles: `admin`, `network_admin`, `security_admin`, `read_only`. Usernames are lowercase.

## 4. Add a firewall

Sign in as an admin, then Administration > Firewall Connections. Use a dedicated OPNsense API user with least-privilege permissions. The secret is stored encrypted and is never shown again. A self-signed firewall certificate should be handled by pasting the CA certificate into the firewall's CA bundle field rather than disabling TLS verification.

Firewall addresses must be in a private range unless `ALLOWED_FIREWALL_NETWORKS` says otherwise.

## Security notes

- Only Caddy publishes ports (80, 443). `backend`, `frontend` and `postgres` are internal only.
- Restrict access to trusted networks or a VPN at the host firewall.
- Cookies use the `__Host-` prefix and require HTTPS. Plain-HTTP development needs `DEV_MODE=true` on the backend and is not for production.
- Registry endpoints marked `verified=False` have not been checked against a real OPNsense. The UI shows an "unverified API mapping" badge.

## Operations

- Logs: `docker compose logs -f backend`
- Remove expired sessions: `docker compose exec backend python -m app.auth.cli cleanup-sessions`
- Migrate only: `docker compose run --rm --entrypoint alembic backend upgrade head`
- Database backup: `docker compose exec postgres pg_dump -U opnsense_mgr opnsense_mgr > backup.sql`

## Known limitations

- Rate-limit counters (per IP) are in memory, so a single backend process is assumed. Per-username lockout is stored in the database.
- Not yet tested against a real OPNsense.
- The Playwright e2e test is written but has not been run (browser binaries not installed).
- The dashboard shows hostname, versions, updates, uptime, load average, CPU and memory. Disk shows only the root filesystem.
