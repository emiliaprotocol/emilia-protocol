#!/usr/bin/env bash
set -euo pipefail

DTC_PACKAGE_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
DTC_REPOSITORY_ROOT="$(cd "$DTC_PACKAGE_ROOT/../.." && pwd)"
DTC_FORMAL_TEMP="$(mktemp -d /tmp/emilia-dtc-formal.XXXXXX)"
trap 'rm -rf "$DTC_FORMAL_TEMP"' EXIT

TLA_VERSION="v1.7.4"
TLA_SHA256="936a262061c914694dfd669a543be24573c45d5aa0ff20a8b96b23d01e050e88"
ALLOY_VERSION="v6.2.0"
ALLOY_SHA256="6b8c1cb5bc93bedfc7c61435c4e1ab6e688a242dc702a394628d9a9801edb78d"
TLC_OUTPUT="$DTC_FORMAL_TEMP/tlc-output.txt"
ALLOY_OUTPUT="$DTC_FORMAL_TEMP/alloy-output.txt"

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

curl --fail --silent --show-error --location --retry 3 -o "$DTC_FORMAL_TEMP/tla2tools.jar" \
  "https://github.com/tlaplus/tlaplus/releases/download/${TLA_VERSION}/tla2tools.jar"
verify_sha256 "$TLA_SHA256" "$DTC_FORMAL_TEMP/tla2tools.jar"

(
  cd "$DTC_PACKAGE_ROOT/formal"
  java -XX:+UseParallelGC -Xmx1G -jar "$DTC_FORMAL_TEMP/tla2tools.jar" \
    -workers auto \
    -config dtc_base_settlement.cfg \
    dtc_base_settlement.tla 2>&1 | tee "$TLC_OUTPUT"
)

curl --fail --silent --show-error --location --retry 3 -o "$DTC_FORMAL_TEMP/alloy.jar" \
  "https://github.com/AlloyTools/org.alloytools.alloy/releases/download/${ALLOY_VERSION}/org.alloytools.alloy.dist.jar"
verify_sha256 "$ALLOY_SHA256" "$DTC_FORMAL_TEMP/alloy.jar"
javac -d "$DTC_FORMAL_TEMP" \
  -cp "$DTC_FORMAL_TEMP/alloy.jar" \
  "$DTC_REPOSITORY_ROOT/formal/AlloyCheck.java"

(
  cd "$DTC_PACKAGE_ROOT/formal"
  java -cp "$DTC_FORMAL_TEMP/alloy.jar:$DTC_FORMAL_TEMP" AlloyCheck dtc_base_escrow.als \
    2>&1 | tee "$ALLOY_OUTPUT"
)

node "$DTC_PACKAGE_ROOT/scripts/render-formal-results.mjs" \
  --tlc-output "$TLC_OUTPUT" \
  --alloy-output "$ALLOY_OUTPUT" \
  --tla-release "$TLA_VERSION" \
  --tla-sha256 "$TLA_SHA256" \
  --alloy-release "$ALLOY_VERSION" \
  --alloy-sha256 "$ALLOY_SHA256" \
  "$@"
