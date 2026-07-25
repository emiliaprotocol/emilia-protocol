#!/usr/bin/env bash
set -euo pipefail

LANE_DIR=$(CDPATH='' cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)

if command -v shellcheck >/dev/null 2>&1; then
  shellcheck \
    "$LANE_DIR/bootstrap-stable.sh" \
    "$LANE_DIR/build-release-images.sh" \
    "$LANE_DIR/deploy.sh" \
    "$LANE_DIR/provision-dedicated-project.sh" \
    "$LANE_DIR/traffic.sh" \
    "$LANE_DIR/test.sh" \
    "$LANE_DIR/lib/common.sh"
else
  printf 'warning: shellcheck not installed; shell lint skipped\n' >&2
fi

PYTHONDONTWRITEBYTECODE=1 \
  python3 -m unittest discover -s "$LANE_DIR/tests" -p 'test_*.py' -v
