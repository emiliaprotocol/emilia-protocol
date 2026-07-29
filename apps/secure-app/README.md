# EMILIA Secure — Expo boundary shell

This Expo / React Native app is a paired mobile-inbox shell and a local
software-key diagnostic. It is **not** a production Class-A signer.

The app can exchange an administrator-created one-time pairing code for a
server-minted mobile session, store that bearer credential in device-only
`expo-secure-store`, and display the paired approver's hosted mobile inbox. No
bearer token or enrollment credential is read from `EXPO_PUBLIC_*` build-time
configuration.

## Security boundary

| Layer | Current status |
|---|---|
| Canonical action challenge | Implemented and tested: `SHA-256(JCS(context))` matches the verifier's byte contract. |
| Client assurance label | Absent by design. Client evidence contains no `key_class`; the server derives assurance from an active trusted enrollment and verified platform evidence. |
| Pairing/session | Implemented: an authorized tenant administrator creates a one-time code, the server exchanges it for an `ep_mobile_*` session, and the app stores only that runtime response in device-only SecureStore. Pairing authenticates an inbox session; it is not key enrollment. |
| Expo software signer | Explicitly exportable P-256 key generated in JavaScript and serialized through SecureStore. SecureStore protects bytes at rest but does not prove a non-exportable key or Secure Enclave/Android Keystore provenance. |
| User verification | Required policy choice: `biometric_only` disables device-passcode fallback; `biometric_or_device_passcode` allows the OS device-owner policy. In the latter mode Expo does not report which permitted factor succeeded, so the app records only `device_owner_authentication`. |
| WebAuthn UP/UV | The software signer sets neither flag. A separate local-auth prompt is not authenticator-bound WebAuthn evidence, so the Class-A verifier must reject the software result. |
| Live approval submission | Intentionally absent. No function can submit the Expo software key to a live signoff or mobile-ceremony endpoint. |
| Display privacy | Consequential-action details render only after the platform capture guard activates. An inactive/background state presents a neutral full-screen shield for app-switcher snapshots. Capture defenses reduce disclosure but do not prove honest pixels on a compromised device. |
| Hardware-required policy | Fails closed with `hardware_provenance_required`. There is no client override. |

The repository's native Swift and Kotlin mobile SDKs implement the platform
ceremony shape using passkeys plus App Attest or Play Integrity. Their server
acceptance still depends on independently verified enrollment evidence, final
application identity, and physical-device testing. Those native capabilities
are not silently attributed to this Expo shell.

## Why the software signature is not Class A

`expo-secure-store` stores strings in platform-protected storage, but
`@noble/curves` creates and uses the private key in JavaScript. The private key
therefore exists as exportable application memory. Calling a separate Face ID,
fingerprint, or device-passcode prompt before using that key does not turn the
result into a platform-authenticator assertion and cannot truthfully set
WebAuthn user-presence or user-verification flags.

The local diagnostic proves only that the app can bind and sign the canonical
challenge bytes. It is not submitted and is not accepted as Class A.

## Pair and run

```bash
cd apps/secure-app
npm install
npx expo start
```

An authorized tenant administrator must create a one-time mobile pairing code
through the hosted server flow. Enter that code in the app. The code is
single-use; the returned session is checked for exact shape and expiry before
storage or use. Disconnect revokes the server session before deleting the local
copy; if server revocation fails, the local credential is retained so the UI
does not falsely report that access was revoked.

Pairing permits inbox access only. This Expo build cannot complete trusted
mobile enrollment because its existing dependencies do not expose platform
passkey registration plus App Attest/Play Integrity evidence.

## Policy examples

```ts
const localDiagnostic = {
  requiredKeyProvenance: 'software_allowed',
  userVerification: 'biometric_only',
};

const liveHighAssurance = {
  requiredKeyProvenance: 'hardware_attested_required',
  userVerification: 'biometric_only',
};
// Refused by this Expo build before key use.
```

Passcode fallback is never inferred. A policy that intends to permit it must
say `biometric_or_device_passcode` explicitly.

## Tests

```bash
npm test
```

The regression suite covers challenge binding, absence of client-assigned key
class, software-key Class-A refusal, hardware-policy refusal, biometric-only
and passcode-capable OS semantics, malformed/expired session refusal, corrupt
SecureStore cleanup, and absence of bundled-token or live software-submit paths.

## External acceptance gates

Before any production signing claim, a platform-native build must:

1. create a non-exportable platform credential on physical iOS and Android
   devices under the final bundle/package identity;
2. complete the server's two-row trusted enrollment: verified WebAuthn
   registration plus independently verified App Attest or Play Integrity
   evidence bound to the same enrollment request;
3. demonstrate that policies requiring hardware provenance reject this
   software-key shell and every unverified or mismatched enrollment;
4. run biometric-only, explicitly passcode-capable, lockout, re-enrollment,
   revocation, counter, backup/restore, and app-update cases on physical devices;
5. retain the signed artifact identities and server enrollment/audit evidence
   from the release campaign described in `../../docs/mobile/RELEASE.md`.
