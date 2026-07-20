# EMILIA Mobile for Swift

Native iOS client for `EP-MOBILE-CEREMONY-v1` using the
`EP-MOBILE-CHALLENGE-v2` wire contract.

```swift
let passkeys = EmiliaApplePasskeyProvider { window }
let appAttest = EmiliaAppleAppAttestProvider(attestationKeyID: enrolledKeyID)
let coordinator = EmiliaMobileCeremonyCoordinator(
    passkeys: passkeys,
    integrity: appAttest,
    appID: Bundle.main.bundleIdentifier!,
    deviceKeyID: enrolledDeviceKeyID
)
guard let identity = selectedAction.identity else {
    throw EmiliaMobileError.contextMismatch
}
let response = try await coordinator.perform(
    challengeData: challengeJSON,
    requestedDecision: .approved,
    expectedActionReference: selectedAction.actionReference,
    expectedActionIdentity: identity
)
```

The coordinator independently canonicalizes the authoritative action, derives
its action digest and CAID, and then validates the presentation, context, and
attestation hashes before invoking AuthenticationServices or DeviceCheck. The
signed v2 context must carry the selected inbox action reference, CAID, and
action digest, all matching that native derivation.
Enrollment uses
`EmiliaAppleAppAttestEnrollment`; the server must verify the attestation and pin
the resulting key separately.

Run `swift test`. Compile the iOS product with:

```sh
xcodebuild -scheme EmiliaMobile -destination 'generic/platform=iOS' \
  CODE_SIGNING_ALLOWED=NO build
```
