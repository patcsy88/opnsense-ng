#!/usr/bin/env bash
# One-step setup for a Linux host: checks the host, asks for what it cannot know, generates the
# secrets, writes .env (mode 600), builds and starts the stack and creates the first admin.
#
# On a fresh host (needs only bash, curl, tar, openssl and Docker):
#   curl -fsSLO https://raw.githubusercontent.com/patcsy88/opnsense-ng/main/install.sh && bash install.sh
# It downloads the code into ./opnsense-ng (INSTALL_DIR to change) and carries on from there.
# Inside an existing checkout it just runs. Re-running updates the code and keeps .env.
#
#   ./install.sh --dry-run   check the host and show what would happen; writes and starts nothing
#
# Optional answers can be given as environment variables to skip a prompt:
#   INSTALL_BUILD=1 builds the images on the host instead of pulling them.
#   INSTALL_HOSTNAME, INSTALL_TRUSTED_PROXIES, INSTALL_ADMIN_USER, MAXMIND_ACCOUNT_ID, MAXMIND_LICENSE_KEY
#
# This setup is for use behind a TLS-terminating tunnel such as Pangolin (docs/deployment.md).
set -euo pipefail

DRY_RUN=0
case "${1:-}" in
  "") ;;
  --dry-run) DRY_RUN=1 ;;
  -h | --help)
    sed -n 2,12p "$0" | sed 's/^# \{0,1\}//'
    exit 0
    ;;
  *)
    echo "Unknown option: $1 (use --dry-run or --help)" >&2
    exit 2
    ;;
esac

# Bootstrap: on a fresh host this file may be the only thing present. Fetch the code (public
# repository, plain HTTPS, no git or SSH keys needed) and continue from the downloaded copy.
# Re-running the same way updates the code in place and keeps .env, geoip/ and other local files.
REPO_TARBALL="${INSTALL_TARBALL_URL:-https://github.com/patcsy88/opnsense-ng/archive/refs/heads/main.tar.gz}"
here="$(cd "$(dirname "${BASH_SOURCE[0]:-$0}")" 2>/dev/null && pwd || true)"
if [ ! -f "$here/docker-compose.yml" ] || [ ! -f "$here/Caddyfile" ]; then
  target="${INSTALL_DIR:-$PWD/opnsense-ng}"
  for tool in curl tar; do
    command -v "$tool" >/dev/null 2>&1 || {
      echo "ERROR: $tool is required to download the code." >&2
      exit 1
    }
  done
  echo "Downloading the code to $target"
  dl="$(mktemp -d)"
  trap 'rm -rf "$dl"' EXIT
  curl --fail --silent --show-error --location --proto '=https' --tlsv1.2 \
    --output "$dl/src.tar.gz" "$REPO_TARBALL" || {
    echo "ERROR: could not download $REPO_TARBALL" >&2
    exit 1
  }
  mkdir -p "$target"
  tar -xzf "$dl/src.tar.gz" -C "$target" --strip-components=1
  [ -f "$target/docker-compose.yml" ] || {
    echo "ERROR: the download does not look like this project." >&2
    exit 1
  }
  chmod +x "$target/install.sh" "$target"/scripts/*.sh 2>/dev/null || true
  # With "curl ... | bash" stdin is the script itself, so give the prompts the terminal back.
  if [ ! -t 0 ] && [ -r /dev/tty ] && : </dev/tty 2>/dev/null; then
    exec bash "$target/install.sh" "$@" </dev/tty
  fi
  exec bash "$target/install.sh" "$@"
fi

cd "$here"
ENV_FILE=".env"
SUBNET_PREFIX="172.30."

say() { printf '%s\n' "$*"; }
step() { printf '\n== %s\n' "$*"; }
warn() { printf 'WARNING: %s\n' "$*" >&2; }
die() {
  printf 'ERROR: %s\n' "$*" >&2
  exit 1
}
act() { # run a state-changing command, or only announce it in dry-run mode
  if [ "$DRY_RUN" = 1 ]; then say "[dry-run] would run: $*"; else "$@"; fi
}

# ---------------------------------------------------------------- 1. preflight (read-only)
step "1/8 Checking this host"

[ "$(uname -s)" = "Linux" ] || die "This installer is for Linux hosts (found $(uname -s))."
[ -f docker-compose.yml ] && [ -f Caddyfile ] || die "Run this from the repository root (docker-compose.yml not found)."
[ "$(id -u)" -ne 0 ] || warn "Running as root. A normal user in the docker group is preferred."

missing=""
for tool in bash curl openssl; do
  command -v "$tool" >/dev/null 2>&1 || missing="$missing $tool"
done
[ -z "$missing" ] || die "Missing tools:$missing. Install them with your package manager and run again."

if ! command -v docker >/dev/null 2>&1; then
  die "Docker is not installed. Install Docker Engine and the Compose plugin first:
  https://docs.docker.com/engine/install/
This script does not install Docker."
fi
docker compose version >/dev/null 2>&1 || die "Docker Compose v2 is missing ('docker compose version' failed).
  https://docs.docker.com/compose/install/linux/"
docker info >/dev/null 2>&1 || die "Cannot talk to the Docker daemon. Start it, and make sure your user may use it
(for example: sudo usermod -aG docker \"\$USER\", then log in again)."
say "Docker and Compose v2 are working."

caddy_running=0
if [ -n "$(docker compose ps -q caddy 2>/dev/null || true)" ]; then caddy_running=1; fi

if [ "$caddy_running" = 0 ] && command -v ss >/dev/null 2>&1; then
  if ss -H -ltn 'sport = :80' 2>/dev/null | grep -q .; then
    die "Port 80 on this host is already in use. Stop whatever uses it, or change the published port in docker-compose.yml."
  fi
fi

if command -v ip >/dev/null 2>&1; then
  clash="$(ip -4 route 2>/dev/null | grep "^${SUBNET_PREFIX}" | grep -v -E 'dev (br-|docker)' || true)"
  [ -z "$clash" ] || warn "The host has a route inside ${SUBNET_PREFIX}0.0/16 that may clash with the stack's 172.30.0.0/24 network."
fi

avail_kb="$(df -Pk . | awk 'NR==2 {print $4}')"
[ "${avail_kb:-0}" -ge 2097152 ] || warn "Less than 2 GB free here. The images and the database need about that much."
if [ -r /proc/meminfo ]; then
  mem_kb="$(awk '/MemAvailable/ {print $2}' /proc/meminfo)"
  [ "${mem_kb:-0}" -ge 524288 ] || warn "Less than 512 MB of memory available."
fi

# ---------------------------------------------------------------- helpers for .env
env_get() { # value of KEY from the existing .env, or empty
  [ -f "$ENV_FILE" ] || return 0
  grep -E "^$1=" "$ENV_FILE" | tail -n 1 | cut -d= -f2- || true
}

valid_hostname() {
  [[ "$1" =~ ^[a-z0-9]([a-z0-9-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)+$ ]]
}

valid_octets() {
  local ip="$1" o
  [[ "$ip" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]] || return 1
  local IFS=.
  for o in $ip; do [ "$o" -le 255 ] || return 1; done
}

valid_trusted() { # space-separated IPv4 addresses or CIDRs, none wider than /16
  local list="$1" item ip prefix
  [ -n "$list" ] || return 1
  for item in $list; do
    ip="${item%%/*}"
    prefix=32
    [[ "$item" == */* ]] && prefix="${item#*/}"
    valid_octets "$ip" || return 1
    [[ "$prefix" =~ ^[0-9]+$ ]] || return 1
    [ "$prefix" -ge 16 ] && [ "$prefix" -le 32 ] || return 1
  done
}

valid_username() {
  [[ "$1" =~ ^[a-z0-9][a-z0-9._@-]*$ ]] && [ "${#1}" -le 64 ]
}

ask() { # ask <varname> <prompt> <validator> <default> <hint>
  local var="$1" prompt="$2" check="$3" default="$4" hint="$5" reply
  if [ -n "${!var:-}" ]; then
    "$check" "${!var}" || die "$var is not valid: $hint"
    return 0
  fi
  [ -t 0 ] || die "$var is not set and there is no terminal to ask on. Set it in the environment."
  while true; do
    if [ -n "$default" ]; then read -r -p "$prompt [$default]: " reply; else read -r -p "$prompt: " reply; fi
    reply="${reply:-$default}"
    if "$check" "$reply"; then
      printf -v "$var" '%s' "$reply"
      return 0
    fi
    say "  Not valid: $hint"
  done
}

# ---------------------------------------------------------------- 2. questions
step "2/8 Questions"

INSTALL_HOSTNAME="${INSTALL_HOSTNAME:-}"
INSTALL_TRUSTED_PROXIES="${INSTALL_TRUSTED_PROXIES:-}"
INSTALL_ADMIN_USER="${INSTALL_ADMIN_USER:-}"

ask INSTALL_HOSTNAME "Public hostname users will open (the Pangolin resource domain)" valid_hostname \
  "$(env_get ALLOWED_HOSTS)" "a lowercase hostname such as fw.example.com, without https://"
ask INSTALL_TRUSTED_PROXIES "Address or range Caddy sees the tunnel agent (Newt) connect from" valid_trusted \
  "$(env_get CADDY_TRUSTED_PROXIES | grep -v '^127\.0\.0\.1/32$' || true)" \
  "IPv4 addresses or CIDRs separated by spaces, none wider than /16 (0.0.0.0/0 is refused)"
ask INSTALL_ADMIN_USER "Username for the first admin" valid_username "admin" \
  "lowercase letters, digits and . _ @ -, starting with a letter or digit"

MAXMIND_ACCOUNT_ID="${MAXMIND_ACCOUNT_ID:-}"
MAXMIND_LICENSE_KEY="${MAXMIND_LICENSE_KEY:-}"
if [ -z "$MAXMIND_ACCOUNT_ID" ] && [ -t 0 ] && [ ! -f geoip/GeoLite2-Country.mmdb ]; then
  read -r -p "MaxMind account ID for country labels on the Logs page (Enter to skip): " MAXMIND_ACCOUNT_ID
  if [ -n "$MAXMIND_ACCOUNT_ID" ]; then
    read -r -s -p "MaxMind licence key (hidden): " MAXMIND_LICENSE_KEY
    echo
  fi
fi

# ---------------------------------------------------------------- 3. secrets
step "3/8 Secrets"

POSTGRES_PASSWORD="$(env_get POSTGRES_PASSWORD)"
SESSION_SECRET="$(env_get SESSION_SECRET)"
CREDENTIAL_ENCRYPTION_KEY="$(env_get CREDENTIAL_ENCRYPTION_KEY)"
new_secrets=""

if [ -z "$POSTGRES_PASSWORD" ]; then
  POSTGRES_PASSWORD="$(openssl rand -hex 24)"
  new_secrets="$new_secrets POSTGRES_PASSWORD"
fi
if [ -z "$SESSION_SECRET" ]; then
  SESSION_SECRET="$(openssl rand -hex 32)"
  new_secrets="$new_secrets SESSION_SECRET"
fi
if [ -z "$CREDENTIAL_ENCRYPTION_KEY" ]; then
  # A Fernet key is 32 random bytes in URL-safe base64.
  CREDENTIAL_ENCRYPTION_KEY="$(openssl rand -base64 32 | tr '+/' '-_' | tr -d '\n')"
  new_secrets="$new_secrets CREDENTIAL_ENCRYPTION_KEY"
fi
if [ -n "$new_secrets" ]; then
  say "Generated:$new_secrets"
else
  say "Existing secrets in $ENV_FILE are kept."
fi

# ---------------------------------------------------------------- 4. .env
step "4/8 Writing $ENV_FILE"

managed='POSTGRES_PASSWORD|SESSION_SECRET|CREDENTIAL_ENCRYPTION_KEY|ALLOWED_HOSTS|SITE_ADDRESS|CADDY_TRUSTED_PROXIES'
if [ "$DRY_RUN" = 1 ]; then
  say "[dry-run] would write $ENV_FILE (mode 600) with ALLOWED_HOSTS=$INSTALL_HOSTNAME, SITE_ADDRESS=:80,"
  say "[dry-run] CADDY_TRUSTED_PROXIES=$INSTALL_TRUSTED_PROXIES and the three secrets."
else
  tmp="$(umask 077 && mktemp ./.env.new.XXXXXX)"
  trap 'rm -f "$tmp"' EXIT
  {
    echo "# Written by install.sh. Mode 600. Never commit this file."
    echo "POSTGRES_PASSWORD=$POSTGRES_PASSWORD"
    echo "SESSION_SECRET=$SESSION_SECRET"
    echo "CREDENTIAL_ENCRYPTION_KEY=$CREDENTIAL_ENCRYPTION_KEY"
    echo "ALLOWED_HOSTS=$INSTALL_HOSTNAME"
    echo "SITE_ADDRESS=:80"
    echo "CADDY_TRUSTED_PROXIES=$INSTALL_TRUSTED_PROXIES"
    if [ -f "$ENV_FILE" ]; then
      # Keep any other settings the operator added by hand.
      grep -v -E "^(${managed})=|^# Written by install.sh|^$" "$ENV_FILE" || true
    fi
  } >"$tmp"
  chmod 600 "$tmp"
  mv "$tmp" "$ENV_FILE"
  trap - EXIT
  say "$ENV_FILE written (mode 600). Secrets are not shown."
fi

# ---------------------------------------------------------------- 5. build and start
step "5/8 Fetching and starting the stack"

# Published images by default (ADR-0024). INSTALL_BUILD=1 builds them on this host instead,
# which needs about 3 GB of disk, Node and PyPI access, and a few minutes.
if [ "${INSTALL_BUILD:-0}" = 1 ]; then
  act docker compose build
elif [ "$DRY_RUN" = 1 ]; then
  say "[dry-run] would run: docker compose pull"
else
  docker compose pull || die "Could not pull the images from ghcr.io.
  If the packages were only just published, they may still be private: see docs/deployment.md.
  To build on this host instead, run: INSTALL_BUILD=1 bash install.sh"
fi
act docker compose up -d

wait_healthy() { # wait_healthy <service>
  local svc="$1" cid status
  for _ in $(seq 1 60); do
    cid="$(docker compose ps -q "$svc" 2>/dev/null || true)"
    if [ -n "$cid" ]; then
      status="$(docker inspect -f '{{if .State.Health}}{{.State.Health.Status}}{{else}}{{.State.Status}}{{end}}' "$cid" 2>/dev/null || true)"
      case "$status" in healthy | running) return 0 ;; esac
    fi
    sleep 3
  done
  say "---- last log lines of $svc" >&2
  docker compose logs --tail 30 "$svc" >&2 || true
  die "$svc did not become healthy in time."
}

if [ "$DRY_RUN" = 0 ]; then
  wait_healthy postgres
  wait_healthy backend
  ok=0
  for _ in $(seq 1 20); do
    if curl -fsS -o /dev/null -H "Host: $INSTALL_HOSTNAME" http://127.0.0.1/health; then
      ok=1
      break
    fi
    sleep 2
  done
  if [ "$ok" = 1 ]; then
    say "The app answers on http://127.0.0.1/health through Caddy."
  else
    docker compose logs --tail 30 caddy backend >&2 || true
    die "The app did not answer on /health through Caddy."
  fi
fi

# ---------------------------------------------------------------- 6. first admin
step "6/8 First admin"

if [ "$DRY_RUN" = 1 ]; then
  say "[dry-run] would create '$INSTALL_ADMIN_USER' as admin unless it already exists."
else
  exists="$(docker compose exec -T postgres psql -U opnsense_mgr -d opnsense_mgr -tAc \
    "select 1 from users where username = '$INSTALL_ADMIN_USER'" 2>/dev/null | tr -d '[:space:]' || true)"
  if [ "$exists" = "1" ]; then
    say "User '$INSTALL_ADMIN_USER' already exists. Nothing to do."
  elif [ -t 0 ]; then
    say "Choose a password for '$INSTALL_ADMIN_USER'. It is typed here, hidden, and never stored by this script."
    docker compose exec backend python -m app.auth.cli create "$INSTALL_ADMIN_USER" admin ||
      warn "The admin was not created. Run: docker compose exec backend python -m app.auth.cli create $INSTALL_ADMIN_USER admin"
  else
    warn "No terminal for the password prompt. Create the admin later with:
  docker compose exec backend python -m app.auth.cli create $INSTALL_ADMIN_USER admin"
  fi
fi

# ---------------------------------------------------------------- 7. GeoIP
step "7/8 Country labels (optional)"

if [ -n "$MAXMIND_ACCOUNT_ID" ] && [ -n "$MAXMIND_LICENSE_KEY" ]; then
  if [ "$DRY_RUN" = 1 ]; then
    say "[dry-run] would download the GeoLite2 database and restart the backend."
  elif MAXMIND_ACCOUNT_ID="$MAXMIND_ACCOUNT_ID" MAXMIND_LICENSE_KEY="$MAXMIND_LICENSE_KEY" ./scripts/update-geoip.sh; then
    docker compose restart backend >/dev/null
  else
    warn "The GeoIP download failed. The app works without it. Retry later with scripts/update-geoip.sh."
  fi
else
  say "Skipped. See docs/deployment.md to add it later."
fi
unset MAXMIND_LICENSE_KEY

# ---------------------------------------------------------------- 8. summary
step "8/8 Done"

cat <<EOF

The stack is $([ "$DRY_RUN" = 1 ] && echo "NOT started (dry run)" || echo "running").

Pangolin resource
  Target:    http://<this host's address>:80   (plain HTTP; Pangolin presents the HTTPS certificate)
  Domain:    $INSTALL_HOSTNAME
  Pass the original Host header through. Open https://$INSTALL_HOSTNAME once Pangolin routes to it.

Do now
  1. Back up CREDENTIAL_ENCRYPTION_KEY from $ENV_FILE somewhere separate from the database
     (a password manager). Without it, stored firewall credentials cannot be decrypted.
     This script does not print it.
  2. Sign in once, then check Audit log: the client address must be yours, not the tunnel's.
     If it shows the tunnel's address, fix CADDY_TRUSTED_PROXIES in $ENV_FILE and run:
     docker compose up -d
  3. At the host firewall, allow ports 80 only from the tunnel agent and block 443. Anything that
     reaches port 80 directly skips the tunnel login (the app's own sign-in and MFA still apply).
     This script does not change the host firewall.

Everyday commands (run in $(pwd))
  Update:   bash install.sh   (downloads the newest code and keeps .env)
  Logs:     docker compose logs -f backend
  Backup:   docker compose exec -T postgres pg_dump -U opnsense_mgr opnsense_mgr > backup.sql
  Stop:     docker compose down        (add -v only to delete the database)
EOF
