#!/usr/bin/env bash
# Runs the live browser tests (frontend/e2e-live) against a disposable stack: its own database,
# no firewall record, random secrets generated here and never written to disk or printed.
# It does not touch the lab stack or any OPNsense firewall.
set -euo pipefail

root="$(cd "$(dirname "$0")/.." && pwd)"
export E2E_PORT="${E2E_PORT:-18443}"
export E2E_DB_PASSWORD="$(openssl rand -hex 16)"
export E2E_SESSION_SECRET="$(openssl rand -hex 32)"
export E2E_FERNET_KEY="$(openssl rand -base64 32 | tr '+/' '-_')"
admin_password="$(openssl rand -base64 18 | tr -d '/+=')x1"

compose=(docker compose -f "$root/e2e/docker-compose.yml")
cleanup() { "${compose[@]}" down -v --remove-orphans >/dev/null 2>&1 || true; }
trap cleanup EXIT

"${compose[@]}" up -d --build >/dev/null
for _ in $(seq 1 60); do
  if curl -ks "https://localhost:${E2E_PORT}/health" | grep -q ok; then break; fi
  sleep 2
done
curl -ks "https://localhost:${E2E_PORT}/health" | grep -q ok || { echo "stack did not become healthy" >&2; exit 1; }

printf '%s\n%s\n' "$admin_password" "$admin_password" |
  "${compose[@]}" exec -T backend python -m app.auth.cli create e2e-admin admin >/dev/null

cd "$root/frontend"
E2E_BASE_URL="https://localhost:${E2E_PORT}" E2E_ADMIN_PASSWORD="$admin_password" \
  npx playwright test -c playwright.live.config.ts "$@"
