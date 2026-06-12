#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
#
# install.sh — install EP on the ISOLATED host from the bundle. No network.
#
# Run from inside the unpacked bundle directory. Loads images, applies
# migrations, brings up the internal-only stack, and runs verify.sh.
#
# Usage:  ./install.sh

set -euo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$HERE"

echo "▸ Preflight…"
command -v docker >/dev/null || { echo "✗ docker not found on this host"; exit 1; }
docker compose version >/dev/null 2>&1 || { echo "✗ 'docker compose' v2 required"; exit 1; }
[ -f images.tar ] || { echo "✗ images.tar missing — incomplete bundle"; exit 1; }
[ -f .env.airgap ] || { echo "✗ create .env.airgap from .env.airgap.example first"; exit 1; }
if grep -q 'CHANGE_ME' .env.airgap; then
  echo "✗ .env.airgap still contains CHANGE_ME placeholders — fill them in first."; exit 1;
fi

echo "▸ Loading images (offline)…"
docker load -i images.tar

echo "▸ Starting database…"
docker compose --env-file .env.airgap -f docker-compose.airgap.yml up -d db
# Wait for health before migrating.
for i in $(seq 1 40); do
  if docker compose --env-file .env.airgap -f docker-compose.airgap.yml exec -T db pg_isready -q; then break; fi
  sleep 2
done

echo "▸ Applying migrations…"
# shellcheck disable=SC1091
set -a; . ./.env.airgap; set +a
for f in migrations/*.sql; do
  echo "    $f"
  docker compose --env-file .env.airgap -f docker-compose.airgap.yml \
    exec -T db psql -v ON_ERROR_STOP=1 -U "$POSTGRES_USER" -d "$POSTGRES_DB" < "$f"
done

echo "▸ Starting REST + app…"
docker compose --env-file .env.airgap -f docker-compose.airgap.yml up -d rest app

echo "▸ Verifying…"
./verify.sh

echo "✓ EP is running, air-gapped, on http://127.0.0.1:8080"
