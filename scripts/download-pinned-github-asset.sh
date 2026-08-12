#!/usr/bin/env bash
set -euo pipefail

if [[ "$#" -ne 4 ]]; then
  echo "usage: $0 <release-url> <asset-api-url> <sha256> <destination>" >&2
  exit 2
fi

release_url="$1"
asset_url="$2"
expected_sha256="$3"
destination="$4"
download_temp="$(mktemp "${TMPDIR:-/tmp}/emilia-pinned-asset.XXXXXX")"
trap 'rm -f "$download_temp"' EXIT

verify_sha256() {
  local expected="$1"
  local path="$2"

  if command -v sha256sum >/dev/null 2>&1; then
    printf '%s  %s\n' "$expected" "$path" | sha256sum -c -
  elif command -v shasum >/dev/null 2>&1; then
    printf '%s  %s\n' "$expected" "$path" | shasum -a 256 -c -
  else
    echo "no SHA-256 verification tool available" >&2
    return 1
  fi
}

download() {
  local url="$1"
  shift
  curl --fail --silent --show-error --location \
    --retry 3 \
    --retry-delay 2 \
    --retry-all-errors \
    --connect-timeout 20 \
    "$@" \
    -o "$download_temp" \
    "$url"
}

if ! download "$release_url"; then
  echo "primary GitHub release download failed; trying the pinned asset API" >&2
  api_headers=(-H 'Accept: application/octet-stream' -H 'X-GitHub-Api-Version: 2022-11-28')
  if [[ -n "${GH_TOKEN:-}" ]]; then
    api_headers+=(-H "Authorization: Bearer ${GH_TOKEN}")
  elif [[ -n "${GITHUB_TOKEN:-}" ]]; then
    api_headers+=(-H "Authorization: Bearer ${GITHUB_TOKEN}")
  fi
  download "$asset_url" "${api_headers[@]}"
fi

verify_sha256 "$expected_sha256" "$download_temp"
mkdir -p "$(dirname "$destination")"
mv "$download_temp" "$destination"
trap - EXIT
