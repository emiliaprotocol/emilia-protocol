# EP Mobile Ceremony v1

Status: Implemented reference profile. This document is not an RFC and does not
claim adoption or endorsement by any government entity.

## 1. Purpose

EP-MOBILE-CEREMONY-v1 is a relying-party profile for collecting a native mobile
approval or denial over an exact consequential action. It composes the existing
EP Class-A WebAuthn signoff with independently verified application and device
integrity evidence.

The profile has four artifacts:

- `EP-MOBILE-RELIANCE-PROFILE-v1`: relying-party pins and requirements;
- `AE-CHALLENGE-v1` with `challenge_profile=EP-MOBILE-CHALLENGE-v1`;
- `EP-MOBILE-CEREMONY-v1`: passkey assertion plus platform attestation; and
- optional `EP-MOBILE-ACK-v1`: a signed service acknowledgement after durable
  verification, consumption, and recording.

Enrollment uses `EP-MOBILE-ENROLLMENT-CHALLENGE-v1` and
`EP-MOBILE-ENROLLMENT-v1`. It activates an enrollment only after both the
passkey registration and the platform-key row verify and the directory plus
audit event commit atomically. The server chooses the enrollment
validity boundary, binds it into the enrollment challenge and platform request
hash, and requires the client to echo it exactly.

## 2. Trust roots

The relying party MUST pin:

- the WebAuthn relying-party ID and allowed origins;
- accepted iOS bundle IDs and Android package names;
- each approver's credential ID, P-256 SPKI, device key ID, platform,
  application ID, and attestation key ID;
- enrollment validity and revocation status; and
- the platform-attestation verification policy.

No key or trust status carried only inside a ceremony response establishes its
own authority.

The relying party MUST authenticate callers through its existing identity
system and authorize the exact action reference, approver, profile, app, and
enrolled device before issuing or verifying a ceremony. Enrollment issuance
and completion MUST independently authorize the authenticated caller for the
named approver. A request-body identity is never an acceptance root. Failure or
unavailability of either authorization check MUST refuse.

## 3. Challenge construction

The system of record MUST resolve the protected action and the presentation
shown to the approver. An agent or requester MUST NOT choose those bytes.

The challenge binds:

- canonical action hash;
- canonical presentation hash;
- policy identifier and optional policy hash;
- initiator and approver identifiers;
- terminal decision (`approved` or `denied`);
- nonce and validity interval;
- reliance-profile hash;
- platform, application, device key, credential, and attestation key; and
- the WebAuthn RP ID.

The WebAuthn challenge is the base64url SHA-256 digest of the canonical signed
authorization context. The platform-attestation request hash is the base64url
SHA-256 digest of `EP-MOBILE-ATTESTATION-BINDING-v1`.

## 4. Native ceremony

The native client MUST first recompute the action, presentation, context, and
attestation-binding digests. It MUST refuse a mismatch before invoking a
passkey or integrity provider.

That check binds the signed ceremony to the exact `presentation` object carried
by the challenge. It does not establish that the presentation is a faithful
semantic rendering of the action or that the device displayed those bytes
honestly. This profile does not implement or claim the deterministic rendering
defined by [PIP-010](../../PIPs/PIP-010-wysiwys-execution-integrity.md).

The passkey assertion MUST require user verification. The iOS client uses
AuthenticationServices and App Attest. The Android client uses Credential
Manager and Play Integrity Standard requests.

Client-supplied labels such as `strong_integrity=true` carry no weight. The
server derives integrity status only from independently verified platform
evidence under the pinned profile.

## 5. Verification and consumption

The server verifier MUST fail closed for:

- stale or mismatched profiles;
- absent, failed, or unavailable caller authorization;
- expired or future challenges;
- action, presentation, nonce, decision, context, origin, app, enrollment, or
  key substitution;
- missing user verification;
- missing, stale, unpinned, or insufficient platform evidence;
- authenticator or App Attest counter rollback;
- changed, absent, or previously consumed challenge bodies;
- challenge-store failure; and
- strict audit-log failure.

The service MUST atomically consume the exact registered challenge body. Two
concurrent presentations of one challenge yield at most one verified result.

## 6. Denials

`denied` is a signed terminal outcome over the same action context. It MUST NOT
be relabeled as approval. It does not authorize execution.

## 7. Boundaries

This profile does not prove:

- a person's civil identity or comprehension;
- that the approver perceived the exact bound presentation, or that a
  compromised client rendered the same presentation it signed;
- semantic equivalence between the bound presentation and the protected action;
- the wisdom, legality, or safety of the action;
- physical execution or outcome;
- global non-replay across independent consumption domains; or
- non-bypassability unless every execution path is mediated at the actual
  system of record or actuator.

App Attest and Play Integrity are online verification dependencies at ceremony
time. After the verified Class-A signoff is projected into an EP receipt, the
receipt's offline-verification properties remain those of that receipt profile;
the platform token is not silently reclassified as offline-verifiable evidence.
Platform integrity can reduce the risk of a modified client, but it does not
attest the pixels shown to the approver and does not eliminate PIP-010's
dishonest-display residual.

## 8. Executable evidence

- Server kernel: `packages/mobile/`
- Strict Fetch transport: `packages/mobile/http.js`
- Swift SDK: `sdks/swift-mobile/`
- Android SDK: `sdks/kotlin-mobile/`
- Shared vectors: `mobile/conformance/mobile-core.v1.json`
- Schemas: `mobile/spec/ep-mobile-v1.schema.json` and
  `mobile/spec/ep-mobile-enrollment-v1.schema.json`
- Full gate: `npm run mobile:conformance`
