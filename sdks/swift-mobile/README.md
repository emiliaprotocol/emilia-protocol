# EMILIA Mobile for Swift

Native iOS client for `EP-MOBILE-CEREMONY-v1`.

```swift
let passkeys = EmiliaApplePasskeyProvider { window }
let appAttest = EmiliaAppleAppAttestProvider(attestationKeyID: enrolledKeyID)
let coordinator = EmiliaMobileCeremonyCoordinator(
    passkeys: passkeys,
    integrity: appAttest,
    appID: Bundle.main.bundleIdentifier!,
    deviceKeyID: enrolledDeviceKeyID
)
let response = try await coordinator.perform(challengeData: challengeJSON)
```

The coordinator validates action, presentation, context, and attestation hashes
before invoking AuthenticationServices or DeviceCheck. Enrollment uses
`EmiliaAppleAppAttestEnrollment`; the server must verify the attestation and pin
the resulting key separately.

Run `swift test`. Compile the iOS product with:

```sh
xcodebuild -scheme EmiliaMobile -destination 'generic/platform=iOS' \
  CODE_SIGNING_ALLOWED=NO build
```
