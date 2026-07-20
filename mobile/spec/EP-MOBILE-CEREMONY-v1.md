# EP Mobile Ceremony v1 with Action Lock

Status: Implemented reference profile. This document is not an RFC and does not
claim adoption or endorsement by any government entity.

## 1. Purpose

EP-MOBILE-CEREMONY-v1 is a relying-party profile for collecting a native mobile
approval or denial over an exact consequential action. It composes the existing
EP Class-A WebAuthn signoff with independently verified application and device
integrity evidence.

The profile has five artifacts:

- `EP-MOBILE-RELIANCE-PROFILE-v1`: relying-party pins and requirements;
- `AE-CHALLENGE-v1` with `challenge_profile=EP-MOBILE-CHALLENGE-v2`;
- `EP-MOBILE-CEREMONY-v1`: passkey assertion plus platform attestation; and
- optional `EP-MOBILE-ACK-v1`: a signed acknowledgement of a valid ceremony
  result; it does not by itself establish durable consumption or recording; and
- optional `EP-MOBILE-EXECUTION-RECORD-v1`: a signed operator runtime statement
  whose creator requires a verified result carrying the reference service's
  consumed-and-audited record, and which binds that claim to the challenge,
  receipt, profile, online check set, and atomic audit-record hash.

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

- the server-resolved action reference;
- the CAID `emilia.mobile.authorized-action.1` computed from the exact
  authoritative action digest;
- that complete authoritative action digest;
- canonical action hash;
- canonical presentation hash;
- policy identifier and optional policy hash;
- initiator and approver identifiers;
- terminal decision (`approved` or `denied`);
- nonce and validity interval;
- reliance-profile hash;
- platform, application, device key, credential, and attestation key; and
- the WebAuthn RP ID.

The action reference, CAID, action digest, action hash, and display hash form the
Action Lock. The WebAuthn challenge is the base64url SHA-256 digest of the
canonical signed authorization context, so the native signature covers the
entire Action Lock. The platform-attestation request hash is the base64url
SHA-256 digest of `EP-MOBILE-ATTESTATION-BINDING-v1`.

## 4. Native ceremony

The native client MUST first recompute the CAID, authoritative action digest,
action hash, presentation hash, signed context hash, and attestation-binding
digest. It MUST compare the signed action reference, CAID, and action digest to
the selected inbox item and refuse a mismatch before invoking a passkey or
integrity provider.

The native ceremony API MUST require the local requested decision as a typed
input. Before invoking a passkey or integrity provider, the client MUST compare
that value to the decision in the validated authorization context. The same
local value MUST select the displayed confirmation control and populate the
ceremony response. An `approved` challenge reached through a local Deny control,
or a `denied` challenge reached through a local Approve control, MUST be refused.

### 4.1 Closed material projection

`EP-MOBILE-PRESENTATION-v1` uses an enforceable closed mapping rather than a
producer assertion that a summary is complete. This version has no independently
pinned, action-specific materiality schema, so every top-level member of
`action` is material. A conforming client MUST enforce all of the following:

1. `action` is a flat object containing between one and 64 members. Each member
   name satisfies the schema's `materialFieldName` rule and each value is a
   string, safe integer, boolean, or `null`. Objects, arrays, non-integer numbers,
   and integers outside the interoperable safe-integer range are refused. A
   future profile is required before any nested mapping can be accepted.
2. `presentation.material_fields` contains exactly the same member names as
   `action`, including structural names such as `@type` and `action_type`. There
   is no metadata exclusion list and no producer-selected subset.
3. Each presentation value is the action value's deterministic lossless text:
   strings unchanged, integers as base-10 with no leading zeroes, booleans as
   `true` or `false`, and `null` as `null`. Each text value is at most 4096 Unicode
   scalar values and contains no disallowed control character.
4. The client displays every controlled member in the confirmation surface.
   `title`, `summary`, `risk`, and `consequence` are supplemental prose and MUST
   NOT replace, rename, or suppress controlled members.

Challenge creation and native validation MUST refuse when a controlled member is
omitted, renamed, added only to one side, changed from the required textual
form, nested, or exceeds the bounded rendering contract. Consequently, adding a
consequential action member without adding its exact visible projection is a
refusal, not a silently hidden field.

These checks establish that the client accepted a complete, lossless projection of
the exact action bytes. They do not prove that an honest display showed those
values or that the approver perceived or understood them. This profile does not
implement or claim the proof of perception that is outside
[PIP-010](../../PIPs/PIP-010-wysiwys-execution-integrity.md).

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

`EP-MOBILE-EXECUTION-RECORD-v1` is an operator attestation about this runtime
path. An offline verifier can authenticate the statement and all of its joins,
but the signature does not independently prove the truth of storage durability,
platform verification, challenge consumption, or downstream physical effect.

## 6. Denials

`denied` is a signed terminal outcome over the same action context. It MUST NOT
be relabeled as approval. It does not authorize execution.

## 7. Durable consequence lifecycle

Authorization and effect are separate states. The reference lifecycle is:

`AWAITING_DECISION`, `QUORUM_PENDING`, `AUTHORIZED`, `DENIED`, `WITHDRAWN`,
`CONSUMED`, `INDETERMINATE`, `EXECUTED`, `REFUSED`, `EXPIRED`, or `CANCELLED`.

An operator MUST atomically consume an authorized action before invoking the
provider. Consumption creates a server-selected nonce and makes blind retry
unsafe. A timeout after invocation MUST transition to `INDETERMINATE`; it MUST
NOT be presented as refusal, success, or permission to retry.

`EXECUTED` or `REFUSED` after an indeterminate result requires an
`EP-MOBILE-PROVIDER-OUTCOME-v1` statement signed by an Ed25519 executor key
pinned by the relying party. The verifier MUST bind the statement to the exact
operation ID, action CAID, action digest, consumption nonce, executor, outcome,
observation time, and provider reference.

An approved decision MAY be withdrawn only before consumption. Supersession
creates an immutable new revision with a complete material-field diff and a new
CAID. Old approvals do not carry across revisions.

`EP-MOBILE-DECISION-PASSPORT-v1` is a bounded export of identity, decision,
quorum, and effect state. It carries digests of decision and provider evidence,
not raw WebAuthn assertions or provider evidence.

Cross-system equivalence is never inferred from matching labels. A positive
alignment requires native verification, a pinned mapping-profile hash, and an
evidence digest; otherwise the normalized verdict is `INDETERMINATE`.

## 8. Boundaries

This profile does not prove:

- a person's civil identity or comprehension;
- that the approver perceived the exact bound presentation, or that a
  compromised client rendered the same presentation it signed;
- the semantic truth of supplemental title, summary, risk, or consequence prose;
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

## 9. Executable evidence

- Server kernel: `packages/mobile/`
- Strict Fetch transport: `packages/mobile/http.js`
- Swift SDK: `sdks/swift-mobile/`
- Android SDK: `sdks/kotlin-mobile/`
- Shared vectors: `mobile/conformance/mobile-core.v1.json`
- Schemas: `mobile/spec/ep-mobile-v1.schema.json` and
  `mobile/spec/ep-mobile-enrollment-v1.schema.json`
- Durable continuity migration:
  `supabase/migrations/20260720181619_mobile_action_continuity.sql`
- Lifecycle and provider-evidence kernel: `lib/mobile/action-continuity.js`
- Mobile history, passport, withdrawal, consumption, reconciliation,
  supersession, and alignment routes: `app/api/v1/mobile/`
- Full gate: `npm run mobile:conformance`
- Regulator export: `examples/regulatory-mobile-oversight/`
