#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
set -euo pipefail

ROOT=$(cd "$(dirname "$0")/.." && pwd)
DERIVED_DATA=${EMILIA_IOS_SHOWCASE_DERIVED_DATA:-/tmp/emilia-mobile-ios-showcase}
SCREENSHOT=${1:-/tmp/emilia-approver-showcase.png}

DEVICE=$(xcrun simctl list devices available --json | node -e '
let raw = "";
process.stdin.on("data", (chunk) => { raw += chunk; });
process.stdin.on("end", () => {
  const runtimes = Object.entries(JSON.parse(raw).devices)
    .filter(([runtime]) => runtime.includes("iOS"))
    .sort(([a], [b]) => b.localeCompare(a));
  for (const [, devices] of runtimes) {
    const phone = devices.find((item) => item.isAvailable && item.name.includes("iPhone"));
    if (phone) { process.stdout.write(phone.udid); return; }
  }
  process.exit(1);
});')

xcrun simctl boot "$DEVICE" >/dev/null 2>&1 || true
xcrun simctl bootstatus "$DEVICE" -b >/dev/null
xcodebuild \
  -project "$ROOT/examples/mobile-government/ios/EmiliaGovernmentApproval.xcodeproj" \
  -scheme GovernmentApproval \
  -configuration Debug \
  -destination "id=$DEVICE" \
  -derivedDataPath "$DERIVED_DATA" \
  build >/dev/null

APP="$DERIVED_DATA/Build/Products/Debug-iphonesimulator/EMILIA Approver.app"
xcrun simctl terminate "$DEVICE" ai.emiliaprotocol.approver >/dev/null 2>&1 || true
xcrun simctl install "$DEVICE" "$APP"
xcrun simctl launch "$DEVICE" ai.emiliaprotocol.approver --args -emilia-reference-demo >/dev/null
sleep 2
xcrun simctl io "$DEVICE" screenshot "$SCREENSHOT" >/dev/null
printf 'EMILIA iOS reference demo is running. Screenshot: %s\n' "$SCREENSHOT"
