# EMILIA Mobile

`@emilia-protocol/mobile` is the server-side kernel for native, high-assurance
approval ceremonies. It joins three independently checked facts:

1. a relying-party-created action and presentation;
2. a passkey assertion with user presence and user verification; and
3. Apple App Attest or Google Play Integrity evidence bound to the same request.

The result is the existing EP Class-A signoff shape. The mobile layer does not
invent another receipt format or another signature algorithm.

For regulator-facing exports, `createMobileExecutionRecord()` signs a closed
operator statement that joins a verified ceremony to the exact challenge,
receipt, profile, and atomic audit record. It requires the result returned by
the durable consumption service; a pure `verifyMobileCeremony()` result is not
enough. `verifyMobileExecutionRecord()` verifies that statement offline.

## Server flow

```js
import {
  createGovernmentMobileController,
  createMobileHttpHandler,
  createMobileCeremonyService,
  createMobileRelianceProfile,
} from '@emilia-protocol/mobile';

const profile = createMobileRelianceProfile({
  profileId: 'agency.high-assurance.mobile.v1',
  rpId: 'approve.example.gov',
  allowedOrigins: ['https://approve.example.gov'],
  acceptedApps: { ios: ['gov.example.approvals'], android: ['gov.example.approvals'] },
  enrollments: await enrollmentDirectory.activeMobileEnrollments(),
});

const service = createMobileCeremonyService({
  challengeStore: durableChallengeStore,
  auditLog: strictEvidenceLog,
  counterStore: authenticatorCounterStore,
  attestationVerifier: productionMobileAttestationVerifier,
});

export const controller = createGovernmentMobileController({
  service,
  profiles: new Map([[profile.profile_id, profile]]),
  authorize: ({ caller, approver_id, device_key_id }) =>
    agencyPolicy.mayUseMobileApproval(caller, approver_id, device_key_id),
  resolveRequest: ({ action_reference, approver_id }) =>
    systemOfRecord.resolveApproval(action_reference, approver_id),
});

export const handleMobileRequest = createMobileHttpHandler({
  controller,
  enrollmentService,
  authenticate: (request) => agencySSO.authenticate(request),
  resolveEnrollmentIdentity: ({ caller, approver_id }) =>
    agencyDirectory.mobileEnrollmentIdentity(caller, approver_id),
  enrollmentConfig: {
    rpId: 'approve.example.gov',
    origin: 'https://approve.example.gov',
  },
});
```

The controller accepts an action reference, never caller-authored action or
display bytes. The system of record computes both before the challenge is
registered. Unknown request members are refused. The hosting HTTP service must
pass its authenticated principal separately; the mandatory authorization hook
binds that principal to the action reference, approver, profile, app, and
enrolled device before protected work begins.

`handleMobileRequest` is a Fetch-compatible transport for the four endpoints
used by the native reference apps. It requires HTTPS and agency authentication,
bounds request bodies, rejects duplicate JSON members, and takes enrollment
display identity from the agency directory rather than the mobile request.

## Required production dependencies

- a durable atomic challenge store;
- a strict durable evidence log;
- an enrollment directory with pinned passkey and attestation keys;
- agency authentication plus authorization adapters for ceremony and enrollment;
- official platform-token verification or a cryptographic App Attest verifier;
- strict JSON parsing at the HTTP boundary; and
- complete mediation at the government system of record or actuator.

The included memory backends and simulated attestation callbacks are test tools,
not production configurations.

On Android, the production attestation adapter must load the enrolled P-256
Android Keystore public key, derive and match its
`android-keystore:sha256:<base64url>` identifier, verify
`device_key_signature` over the exact ceremony request hash, and only then
accept Play Integrity evidence for the pinned package and signing certificate.
Play Integrity alone is not a device-key verifier. The same key-binding proof
is mandatory during enrollment, which prevents a synced passkey from being
substituted onto another device.

The execution record is an operator attestation. It does not turn Apple/Google
platform evidence, storage durability, one-time consumption, or physical effect
into independently reproducible offline facts. The Class-A passkey remains
directly verifiable; the runtime statement makes the operator accountable for
the online checks it says passed.

## Security boundary

The ceremony proves that a pinned enrolled key completed a platform-verified
ceremony over exact bytes. It does not prove civil identity, comprehension,
legal sufficiency, safety, or that an operator has no bypass around the gate.
See [`mobile/spec/EP-MOBILE-CEREMONY-v1.md`](../../mobile/spec/EP-MOBILE-CEREMONY-v1.md)
and [`docs/mobile/THREAT-MODEL.md`](../../docs/mobile/THREAT-MODEL.md).

The complete synthetic regulator export is
[`examples/regulatory-mobile-oversight`](../../examples/regulatory-mobile-oversight).
