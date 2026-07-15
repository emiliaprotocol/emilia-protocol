# Native government approval reference platform

This reference platform turns an existing government system of record into the
source of exact action and display bytes, then collects a native mobile approval
or denial with a passkey and platform integrity evidence bound to those bytes.

## Included

- [`packages/mobile`](../../packages/mobile): enrollment, profile, challenge,
  verification, consumption, audit, acknowledgement, government controller,
  and strict Fetch-compatible HTTP transport;
- [`ios`](ios): buildable SwiftUI app with passkeys and Apple App Attest;
- [`sdks/kotlin-mobile/sample`](../../sdks/kotlin-mobile/sample): buildable
  Android app with Credential Manager and Google Play Integrity;
- [`mobile/spec`](../../mobile/spec): contract and JSON Schemas; and
- [`docs/mobile`](../../docs/mobile): threat model, deployment boundary, and
  pilot acceptance plan.

## Flow

```text
government system of record
  -> exact action + exact presentation
  -> body-bound mobile challenge
  -> native review + passkey + app/device integrity
  -> pinned server verification
  -> atomic challenge consumption + durable evidence
  -> local government executor authorizes or refuses
```

The native apps never accept caller-provided trust keys or profiles. The
government controller resolves protected content from the system of record and
selects the reliance profile from server configuration. Its mandatory
authorization hook receives the agency-authenticated principal separately from
the request body and refuses before protected work when that principal is not
permitted to act for the requested approver and enrolled device.

## Build

```sh
npm run mobile:conformance

cd examples/mobile-government/ios
xcodegen generate
xcodebuild -project EmiliaGovernmentApproval.xcodeproj \
  -scheme GovernmentApproval -destination 'generic/platform=iOS' \
  CODE_SIGNING_ALLOWED=NO build

cd ../../../sdks/kotlin-mobile
ANDROID_HOME="$HOME/Library/Android/sdk" ./gradlew :sample:assembleDebug
```

The checked-in identifiers and endpoints use `example.gov`. They are
configuration examples, not evidence that any state or agency has adopted or
endorsed the platform.
