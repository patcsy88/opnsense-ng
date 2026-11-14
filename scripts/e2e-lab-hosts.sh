#!/usr/bin/env bash
# Lab test for Dnsmasq static hosts (ADR-0017). Drives the running LAB stack (https://localhost)
# through the real UI: creates a temporary admin with a random password, enrols its MFA, makes one
# throwaway host (zz-adr17-test.adr17.test) on the lab firewall, edits it, deletes it, then removes
# the temporary admin. Nothing secret is printed or written to disk.
# Needs: the lab stack up, and allow_writes turned on for the lab firewall.
set -euo pipefail

root="$(cd "$(dirname "$0")/.." && pwd)"
user="lab-e2e-$(openssl rand -hex 3)"
password="$(openssl rand -base64 18 | tr -d '/+=')x1"

cleanup() {
  (cd "$root" && docker compose exec -T postgres \
    psql -q -U opnsense_mgr -d opnsense_mgr -c "delete from users where username = '${user}'" >/dev/null 2>&1) || true
}
trap cleanup EXIT

cd "$root"
printf '%s\n%s\n' "$password" "$password" |
  docker compose exec -T backend python -m app.auth.cli create "$user" admin >/dev/null

cd "$root/frontend"
E2E_BASE_URL="${E2E_BASE_URL:-https://localhost}" \
  E2E_LAB_USER="$user" E2E_LAB_PASSWORD="$password" \
  E2E_LAB_FIREWALL="${E2E_LAB_FIREWALL:-OPNsense.test}" \
  npx playwright test -c playwright.live.config.ts lab-hosts "$@"
