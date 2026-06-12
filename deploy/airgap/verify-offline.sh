#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
#
# verify-offline.sh — prove EP's verification works with ZERO network.
#
# This is the core air-gap property and it is testable anywhere, no Docker
# needed: EP receipts, Merkle anchors, and Class-A signoffs verify with pure
# crypto and no I/O. Runs the JS reference verifier over the canonical vectors
# and the @emilia-protocol/verify suite.
#
# Works both from a checked-out repo and from inside an unpacked bundle
# (which ships conformance/ + verify-lib/).

set -uo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Locate inputs in either layout.
if [ -d "$HERE/verify-lib" ]; then
  VERIFY_TEST="$HERE/verify-lib/test.js"
  VECTORS="$HERE/conformance/vectors/receipts.v1.json"
  JS_RUNNER="$HERE/conformance/runners/run-js.mjs"
else
  ROOT="$(cd "$HERE/../.." && pwd)"
  VERIFY_TEST="$ROOT/packages/verify/test.js"
  VECTORS="$ROOT/conformance/vectors/receipts.v1.json"
  JS_RUNNER="$ROOT/conformance/runners/run-js.mjs"
fi

fail=0
echo "▸ Offline conformance vectors (JS reference verifier)…"
if node "$JS_RUNNER" "$VECTORS" >/dev/null 2>&1; then
  echo "  ✓ canonical receipt vectors verify with no network"
else
  echo "  ✗ conformance verifier failed"; fail=1
fi

echo "▸ @emilia-protocol/verify suite (pure Node crypto)…"
if node --test "$VERIFY_TEST" >/dev/null 2>&1; then
  echo "  ✓ verify suite passes with no network"
else
  echo "  ✗ verify suite failed"; fail=1
fi

echo
if [ "$fail" -eq 0 ]; then
  echo "✓ Offline verification PASSED — receipts verify with zero network access."
else
  echo "✗ Offline verification FAILED"
fi
exit "$fail"
