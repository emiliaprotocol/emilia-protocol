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

curl -fsSL -o "$DTC_FORMAL_TEMP/tla2tools.jar" \
  "https://github.com/tlaplus/tlaplus/releases/download/${TLA_VERSION}/tla2tools.jar"
echo "$TLA_SHA256  $DTC_FORMAL_TEMP/tla2tools.jar" | shasum -a 256 -c -

(
  cd "$DTC_PACKAGE_ROOT/formal"
  java -XX:+UseParallelGC -Xmx1G -jar "$DTC_FORMAL_TEMP/tla2tools.jar" \
    -workers auto \
    -config dtc_base_settlement.cfg \
    dtc_base_settlement.tla
)

curl -fsSL -o "$DTC_FORMAL_TEMP/alloy.jar" \
  "https://github.com/AlloyTools/org.alloytools.alloy/releases/download/${ALLOY_VERSION}/org.alloytools.alloy.dist.jar"
echo "$ALLOY_SHA256  $DTC_FORMAL_TEMP/alloy.jar" | shasum -a 256 -c -
javac -d "$DTC_FORMAL_TEMP" \
  -cp "$DTC_FORMAL_TEMP/alloy.jar" \
  "$DTC_REPOSITORY_ROOT/formal/AlloyCheck.java"

(
  cd "$DTC_PACKAGE_ROOT/formal"
  java -cp "$DTC_FORMAL_TEMP/alloy.jar:$DTC_FORMAL_TEMP" AlloyCheck dtc_base_escrow.als
)
