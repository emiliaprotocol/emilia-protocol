#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
#
# Publish an @emilia-protocol npm package by hand (default: packages/verify).
#
#   scripts/publish-verify.sh                  # publishes packages/verify
#   scripts/publish-verify.sh packages/issue   # or any other package dir
#
# Why this exists: the CI publish workflow needs a valid NPM_TOKEN secret; when
# it's missing/expired, npm publish fails with a misleading "404 ... not in this
# registry" (that is npm's way of saying "auth failed"). This script does the
# manual path safely: web-login if needed, show exactly what will ship, refuse to
# republish an existing version, then publish.
set -euo pipefail

PKG_DIR="${1:-packages/verify}"
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT/$PKG_DIR"

NAME="$(node -p "require('./package.json').name")"
VER="$(node -p "require('./package.json').version")"
echo "==> ${NAME}@${VER}   (${PKG_DIR})"

# 1) Ensure authenticated. `npm login` opens the browser to authorize.
if ! npm whoami >/dev/null 2>&1; then
  echo "==> Not logged in to npm — launching web login (authorize in your browser)..."
  npm login
fi
echo "==> Authenticated as: $(npm whoami)"

# 2) Final eyeball: the exact files that will ship.
npm pack --dry-run

# 3) Refuse to republish an existing version (npm forbids it anyway).
if npm view "${NAME}@${VER}" version >/dev/null 2>&1; then
  echo "!! ${NAME}@${VER} is already published — bump the version in package.json first."
  exit 1
fi

# 4) Publish. Enter your 2FA one-time code if prompted.
npm publish --access public

# A first publish can take minutes to appear on registry reads — a transient 404
# here does NOT mean the publish failed (the PUT 200 above is the source of truth).
LATEST="$(npm view "${NAME}" version 2>/dev/null || true)"
echo "==> Published. Registry 'latest' currently reads: ${LATEST:-"(still propagating — recheck npm view ${NAME} in a few minutes)"}"
