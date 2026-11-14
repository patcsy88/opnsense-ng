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
| `MFA_REQUIRED_ROLES` | no | Roles that must use TOTP, comma separated (default: all four roles). Set it empty to make MFA optional. Users in these roles enrol at first sign-in |
| `AUDIT_RETENTION_DAYS` | no | Audit records older than this can be purged by an admin (default 365, minimum 90). Nothing is deleted automatically |
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
- Remove expired sessions and old login rate-limit counters: `docker compose exec backend python -m app.auth.cli cleanup-sessions`
- Migrate only: `docker compose run --rm --entrypoint alembic backend upgrade head`
- Database backup: `docker compose exec postgres pg_dump -U opnsense_mgr opnsense_mgr > backup.sql`
- Lost authenticator or password: an admin can reset MFA or the password in Administration, Users. The CLI below is the break-glass path when no admin can sign in. Migration `0005` adds `users.must_change_password`; it runs on start
- Lost authenticator and recovery codes (CLI): `docker compose exec backend python -m app.auth.cli reset-mfa <username>` clears the user's MFA and ends their sessions; they enrol again at the next sign-in. Run it from the host, so it needs shell access to the server
- Audit log: admins and security admins view it under Administration, Audit log. Only an admin can purge, and only records older than `AUDIT_RETENTION_DAYS`. Take a backup first if you need to keep them

## Known limitations

- Rate-limit counters (per IP) are in memory, so a single backend process is assumed. Per-username lockout is stored in the database.
- Tested against one lab OPNsense (26.7.8_2) only. Six read-only dashboard operations are verified; see `docs/api-integration.md`.
- The dashboard shows hostname, versions, updates, uptime, load average, CPU, memory and the root filesystem's disk usage.
- Every role can list firewall names (`GET /api/v1/firewalls/options`, id and name only) to pick one on the dashboard. URLs, TLS settings and certificates stay admin-only.
- Deleting a connection (Administration > Firewall Connections) removes its stored credentials. Audit records are kept.

## Optional: country labels on the Logs page (GeoLite2)

The Logs page can label blocked source addresses with a country. It uses the MaxMind GeoLite2-Country database, read offline by the backend. No address is sent anywhere, and only public addresses are looked up (private, loopback, link-local, multicast and documentation ranges are skipped). Labels are approximate and are for display only.

1. Create a free MaxMind account and a licence key (you accept MaxMind's GeoLite2 licence terms; do not redistribute the database).
2. On the host, in the repository directory:

   ```
   MAXMIND_ACCOUNT_ID=<id> MAXMIND_LICENSE_KEY=<key> ./scripts/update-geoip.sh
   ```

   This writes `geoip/GeoLite2-Country.mmdb` (git-ignored). The compose file mounts `./geoip` read-only into the backend and sets `GEOIP_DB_PATH`.
3. Refresh the file regularly (MaxMind updates GeoLite2 twice a week; their terms require you to keep it reasonably current), for example with a weekly cron job running the same command. The backend notices a replaced file and reopens it; no restart is needed.

Without the file the feature is off and the Logs page works as before. The key and account id are only used by the script and are never passed to the backend or committed.
