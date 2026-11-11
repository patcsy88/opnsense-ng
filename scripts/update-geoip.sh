#!/usr/bin/env bash
# Download the MaxMind GeoLite2-Country database into ./geoip/ (mounted read-only into the backend).
# Run on the host, not in a container. The licence key never reaches the backend.
#
#   MAXMIND_ACCOUNT_ID=123456 MAXMIND_LICENSE_KEY=... ./scripts/update-geoip.sh
#
# Put the values in your shell or a private file you source; do not commit them.
set -euo pipefail

: "${MAXMIND_ACCOUNT_ID:?set MAXMIND_ACCOUNT_ID}"
: "${MAXMIND_LICENSE_KEY:?set MAXMIND_LICENSE_KEY}"

dest="$(cd "$(dirname "$0")/.." && pwd)/geoip"
mkdir -p "$dest"
tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT

curl --fail --silent --show-error --location --proto '=https' --tlsv1.2 \
  --user "${MAXMIND_ACCOUNT_ID}:${MAXMIND_LICENSE_KEY}" \
  --output "$tmp/db.tar.gz" \
  "https://download.maxmind.com/geoip/databases/GeoLite2-Country/download?suffix=tar.gz"

tar -xzf "$tmp/db.tar.gz" -C "$tmp"
mmdb="$(find "$tmp" -name 'GeoLite2-Country.mmdb' -type f | head -n 1)"
[ -n "$mmdb" ] || { echo "GeoLite2-Country.mmdb not found in the download" >&2; exit 1; }

# Atomic replace so the backend never sees a half-written file.
cp "$mmdb" "$dest/.GeoLite2-Country.mmdb.new"
mv "$dest/.GeoLite2-Country.mmdb.new" "$dest/GeoLite2-Country.mmdb"
chmod 0644 "$dest/GeoLite2-Country.mmdb"
echo "Updated $dest/GeoLite2-Country.mmdb"
