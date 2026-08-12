#!/usr/bin/env bash
set -euo pipefail

if [[ "$#" -ne 1 ]]; then
  echo "usage: $0 <destination>" >&2
  exit 2
fi

: "${TLA_VERSION:?TLA_VERSION is required}"
: "${TLA_ASSET_ID:?TLA_ASSET_ID is required}"
: "${TLA_SHA256:?TLA_SHA256 is required}"

script_root="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
release_url="https://github.com/tlaplus/tlaplus/releases/download/${TLA_VERSION}/tla2tools.jar"
asset_url="https://api.github.com/repos/tlaplus/tlaplus/releases/assets/${TLA_ASSET_ID}"
"$script_root/download-pinned-github-asset.sh" \
  "$release_url" \
  "$asset_url" \
  "$TLA_SHA256" \
  "$1"
