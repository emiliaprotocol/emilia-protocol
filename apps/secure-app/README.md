# EMILIA Secure — the signing device

A native (Expo / React Native) app that turns a named human's phone into their
EP signing device. When a high-risk action needs accountable approval, the app
shows the **exact** action, the human approves with Face ID / biometric, and the
device key produces a **Class-A signoff** bound to that action.

The signature this app produces verifies **offline** under the protocol's own
verifier — no special-casing. That round-trip is proven in
[`lib/ep-signoff.test.mjs`](lib/ep-signoff.test.mjs): the app computes the
challenge, signs it WebAuthn-style, and `@emilia-protocol/verify`
`verifyWebAuthnSignoff` accepts it (and rejects a tampered context or a
different key).

## What's real, and the boundary

| Layer | Status |
|---|---|
| Signoff protocol core (`lib/ep-signoff.mjs`) | **real + tested** — challenge = SHA-256(JCS(context)), byte-identical to `@emilia-protocol/verify`; the produced attestation verifies offline (4 round-trip tests, run in CI) |
| Gate client (`lib/ep-client.mjs`) | **real** — list pending / fetch options / submit, injectable fetch |
| Biometric gate + key (`lib/secure-key.js`) | **real** — `expo-local-authentication` ceremony + `expo-secure-store` persistence |
| UI (`App.js`) | **real, runnable** — `npx expo start` runs it in Expo Go / simulator |
| Signing key backing | **boundary** — Expo Go / demo uses a software P-256 key (`@noble/curves`), labeled a demo key. **Production binds the key to the hardware secure enclave via an OS passkey**; that and App Store / Play submission are the native steps that require Xcode/EAS + an Apple/Google account |

> The crypto/protocol core is real and proven; the app runs. What is **not** done
> here is hardware-enclave key attestation and app-store publishing — those need
> a real device, Xcode/EAS, and store accounts. The scaffold is everything up to
> that line.

## Run it

```bash
cd apps/secure-app
npm install
npx expo start            # press i (iOS sim) / a (Android) / scan QR for Expo Go
```

Point it at a tenant by setting build-time env:

```bash
EXPO_PUBLIC_EP_BASE_URL=https://www.emiliaprotocol.ai \
EXPO_PUBLIC_EP_RP_ID=www.emiliaprotocol.ai \
EXPO_PUBLIC_EP_TOKEN=<approver token> npx expo start
```

With no token it shows a demo signoff so you can exercise the Face ID → sign flow
and confirm a verifiable Class-A attestation is produced on-device.

## Test the core

```bash
npm test     # node --test lib/ep-signoff.test.mjs  (the offline-verify round-trip)
```
