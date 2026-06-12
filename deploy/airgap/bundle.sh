#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
#
# bundle.sh — build a self-contained air-gap bundle ON A CONNECTED MACHINE.
#
# Produces a single tarball containing every image, the compose file, the
# migrations, the install/verify scripts, and the env template. Transfer the
# tarball to the isolated host and run install.sh there — no network required at
# install time.
#
# Usage:  deploy/airgap/bundle.sh [version]
# Output: dist/ep-airgap-<version>.tar.gz  (+ .sha256)

set -euo pipefail

VERSION="${1:-$(node -p "require('./package.json').version" 2>/dev/null || echo dev)}"
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$ROOT"

STAGE="$(mktemp -d)"
trap 'rm -rf "$STAGE"' EXIT
OUT="dist"
mkdir -p "$OUT"

APP_IMAGE="emilia-protocol:airgap"
# Images that make up the air-gapped data plane. Pinned by digest in production;
# tags here for readability.
DEP_IMAGES=(
  "postgres:16-alpine"
  "postgrest/postgrest:v12.2.3"
)

echo "▸ Building the EP application image ($APP_IMAGE)…"
docker build -t "$APP_IMAGE" -f Dockerfile .

echo "▸ Pulling dependency images (this is the ONLY networked step)…"
for img in "${DEP_IMAGES[@]}"; do docker pull "$img"; done

echo "▸ Saving images to the bundle…"
docker save "$APP_IMAGE" "${DEP_IMAGES[@]}" -o "$STAGE/images.tar"

echo "▸ Staging compose, migrations, scripts, env template…"
cp deploy/airgap/docker-compose.airgap.yml "$STAGE/"
cp deploy/airgap/install.sh deploy/airgap/verify.sh deploy/airgap/verify-offline.sh "$STAGE/"
cp deploy/airgap/.env.airgap.example "$STAGE/"
cp deploy/airgap/README.md "$STAGE/"
mkdir -p "$STAGE/migrations"
cp supabase/migrations/*.sql "$STAGE/migrations/"
# Offline verification fixtures (the core EP property works with no network).
mkdir -p "$STAGE/conformance"
cp -r conformance/vectors conformance/runners "$STAGE/conformance/" 2>/dev/null || true
cp -r packages/verify "$STAGE/verify-lib"

# A manifest the installer + auditor can check against (no surprise images).
{
  echo "version: $VERSION"
  echo "app_image: $APP_IMAGE"
  printf 'dep_images:\n'; for i in "${DEP_IMAGES[@]}"; do echo "  - $i"; done
} > "$STAGE/MANIFEST.txt"

TARBALL="$OUT/ep-airgap-${VERSION}.tar.gz"
tar -C "$STAGE" -czf "$TARBALL" .
( cd "$OUT" && shasum -a 256 "$(basename "$TARBALL")" > "$(basename "$TARBALL").sha256" )

echo "✓ Bundle: $TARBALL"
echo "  $(cat "$TARBALL.sha256")"
echo "  Transfer the tarball + .sha256 to the isolated host, then run install.sh."
