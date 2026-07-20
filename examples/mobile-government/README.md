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
  -> server-computed CAID + action digest
  -> challenge v2 signed Action Lock
  -> native review + passkey + app/device integrity
  -> pinned server verification
  -> atomic challenge consumption + durable evidence
  -> aggregate quorum authorization
  -> one-time consequence consumption
  -> executed / refused / indeterminate reconciliation
```

The native apps never accept caller-provided trust keys or profiles. The
government controller resolves protected content from the system of record and
selects the reliance profile from server configuration. Its mandatory
authorization hook receives the agency-authenticated principal separately from
the request body and refuses before protected work when that principal is not
permitted to act for the requested approver and enrolled device.

## Continuity experience

The reference clients consume the same hosted continuity model on iOS and
Android:

- **Action Lock:** the review surface shows a stable fingerprint derived from
  the server-computed CAID. Challenge v2 signs `action_reference`,
  `action_caid`, and `action_digest`; the clients do not invent them.
- **Revision safety:** a successor action receives a new CAID and revision, and
  the app shows every added, changed, or removed material field.
- **Quorum progress:** approved, required, denied, and withdrawn counts are
  presented as one aggregate action state rather than independent assignments.
- **Consequence state:** the app distinguishes authorization from consumption
  and provider outcome. `INDETERMINATE` is shown as “do not retry,” not as a
  denial or a safe retry.
- **Decision passport:** history can display/export the bounded CAID, decision,
  quorum, lifecycle, and evidence-digest summary without raw passkey,
  attestation, or provider evidence.
- **Cross-system alignment:** equivalence is shown only under a named,
  hash-pinned mapping profile with native verification; otherwise the result is
  explicitly indeterminate.
- **Withdrawal:** an approver may withdraw their own approval before
  consequence authority is consumed. There is no claim that withdrawal undoes
  an already consumed or executed effect.

The hosted HTTP contract is documented in
[`openapi.yaml`](../../openapi.yaml). Mobile-session routes provide inbox,
history, passport, and pre-consumption withdrawal. Organization operator routes
provide consumption, outcome reconciliation, supersession, and alignment
recording; executor-key registration requires an organization admin key.

## Build

```sh
npm run mobile:conformance
npm run mobile:release-check

cd examples/mobile-government/ios
xcodegen generate
xcodebuild -project EmiliaGovernmentApproval.xcodeproj \
  -scheme GovernmentApproval -destination 'generic/platform=iOS' \
  CODE_SIGNING_ALLOWED=NO build

cd ../../../sdks/kotlin-mobile
ANDROID_HOME="$HOME/Library/Android/sdk" ./gradlew :sample:assembleDebug
```

## Demo

Run the production-shaped QR/backend demo against a configured deployment:

```sh
EMILIA_API_KEY=... npm run mobile:live-demo -- --scenario grid
```

Run the debug-only iOS showroom of the exact-action review surface:

```sh
npm run mobile:ios-showcase
```

The showroom carries a visible `DEMO` label and is compiled out of Release. It
does not claim a passkey, App Attest, backend consumption, or execution result.
Use the live demo plus a paired physical device for the real ceremony.

The reference apps use the permanent EMILIA identity
`ai.emiliaprotocol.approver` and the API at `www.emiliaprotocol.ai`. They are
open reference clients, not evidence that any state or agency has adopted or
endorsed the platform. Production distribution remains blocked until the
account-owned store, signing, attestation, and privacy steps in
[`docs/mobile/RELEASE.md`](../../docs/mobile/RELEASE.md) are complete.
The continuity migration, web deployment, signed native release, and app-store
publication remain separately verified gates.
