#!/bin/sh
# SPDX-License-Identifier: Apache-2.0
# CAID cross-language differential fuzz, CI entry point.
#
#   sh caid/fuzz/ci.sh [tree-root] [allow-file]
#
# Runs the full seeded corpus (about 80k cases) against the tree (default:
# this checkout) and exits 1 when any lane's outcome differs from the spec
# oracle in a class whose root cause the allow file does not list. The
# committed allow file is [] (empty), so every difference fails. Requires
# node, go, and the Python named by CAID_PYTHON (default python3).
set -eu
HERE=$(cd "$(dirname "$0")" && pwd)
ROOT=${1:-$(cd "$HERE/../.." && pwd)}
ALLOW=${2:-$HERE/allow.json}
OUT=${OUT:-${RUNNER_TEMP:-${TMPDIR:-/tmp}}/caid-fuzz}
exec node "$HERE/run.mjs" --root "$ROOT" --out "$OUT" --ci --allow "$ALLOW"
