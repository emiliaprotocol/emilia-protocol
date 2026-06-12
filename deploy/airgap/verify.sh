#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
#
# verify.sh — post-install smoke test on the isolated host.
#   1. the app answers /api/health over loopback
#   2. EP's receipt verification runs with NO network (the core property)
#   3. the app container genuinely has no egress (the air-gap is real)

set -uo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$HERE"
fail=0
say() { printf '  %s %s\n' "$1" "$2"; }

echo "▸ 1/3 App health (loopback)…"
if curl -fsS --max-time 10 http://127.0.0.1:8080/api/health >/dev/null 2>&1; then
  say "✓" "app responds on http://127.0.0.1:8080/api/health"
else
  say "✗" "app did not respond on /api/health"; fail=1
fi

echo "▸ 2/3 Offline receipt verification…"
if [ -d verify-lib ] && node verify-lib/test.js >/dev/null 2>&1; then
  say "✓" "packages/verify suite passes with no network"
else
  say "✗" "offline verification suite failed"; fail=1
fi

echo "▸ 3/3 Egress is blocked (air-gap is real)…"
# From inside the app container, any attempt to reach the outside must fail.
if docker compose --env-file .env.airgap -f docker-compose.airgap.yml \
     exec -T app node -e "fetch('http://1.1.1.1',{signal:AbortSignal.timeout(3000)}).then(()=>process.exit(0)).catch(()=>process.exit(7))" 2>/dev/null; then
  say "✗" "app container reached the internet — network is NOT air-gapped"; fail=1
else
  say "✓" "app container cannot reach the internet (internal network enforced)"
fi

echo
if [ "$fail" -eq 0 ]; then echo "✓ Air-gap verification PASSED"; else echo "✗ Air-gap verification FAILED"; fi
exit "$fail"
