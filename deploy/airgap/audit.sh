#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
#
# audit.sh — STATIC self-containment audit for the air-gap artifact.
#
# Runs with no Docker and no network — a guard you can run in CI. Asserts:
#   1. the stack network is `internal: true` (no egress by construction)
#   2. every compose `image:` is one the bundle builds or vendors (no surprise pulls)
#   3. install.sh performs no outbound network fetch
#   4. the offline-verification inputs the bundle promises are present
#
# Usage: deploy/airgap/audit.sh

set -uo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$HERE/../.." && pwd)"
COMPOSE="$HERE/docker-compose.airgap.yml"
fail=0
ok()   { printf '  ✓ %s\n' "$1"; }
bad()  { printf '  ✗ %s\n' "$1"; fail=1; }

echo "▸ 1/4 Network is internal (no egress)…"
# POSIX classes ([[:space:]]) — portable across GNU and BSD grep.
if grep -qE 'internal:[[:space:]]*true' "$COMPOSE"; then ok "epnet is internal: true"; else bad "epnet is not marked internal: true"; fi

echo "▸ 2/4 Every image is built or vendored (no surprise pulls)…"
# Images the bundle is allowed to ship.
allowed='emilia-protocol:airgap|postgres:16-alpine|postgrest/postgrest:v12.2.3'
while IFS= read -r img; do
  [ -z "$img" ] && continue
  if echo "$img" | grep -qE "^($allowed)$"; then ok "image $img is in the bundle"; else bad "image $img is NOT in the bundle manifest"; fi
done < <(awk '/^[[:space:]]*image:[[:space:]]/{print $2}' "$COMPOSE")

echo "▸ 3/4 install.sh has no outbound network fetch…"
if grep -nE 'curl|wget|npm (install|ci)|docker pull|fetch\(' "$HERE/install.sh" | grep -vqE '^\s*#'; then
  bad "install.sh appears to perform a network fetch:"; grep -nE 'curl|wget|npm (install|ci)|docker pull' "$HERE/install.sh"
else
  ok "install.sh performs no network fetch"
fi

echo "▸ 4/4 Offline-verification inputs present…"
[ -f "$ROOT/conformance/vectors/receipts.v1.json" ] && ok "conformance vectors present" || bad "conformance vectors missing"
[ -f "$ROOT/packages/verify/test.js" ] && ok "verify suite present" || bad "verify suite missing"

echo
if [ "$fail" -eq 0 ]; then echo "✓ Air-gap self-containment audit PASSED"; else echo "✗ Air-gap self-containment audit FAILED"; fi
exit "$fail"
