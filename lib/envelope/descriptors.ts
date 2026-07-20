/**
 * EP profile + action-type DESCRIPTORS — the single source of truth for the
 * registry. Pure data, zero imports, so the registry generator (plain Node),
 * the in-process registration (lib/envelope/profiles.js), and the conformance
 * test all read the SAME descriptors and cannot drift.
 *
 * @license Apache-2.0
 *
 * This is the file that makes "profiles are DATA, not code": adding a profile is
 * adding a row here (+ a validateBody bridge), and a third party ships in the
 * reserved `urn:ep:profile:x-<vendor>:*` space the same way.
 */

export const PROFILE_DESCRIPTORS = Object.freeze([
  { profile: 'urn:ep:profile:revocation:v1', wire_tag: 'EP-REVOCATION-v1', spec: 'docs/EP-REVOCATION-SPEC.md', vectors: 'conformance/vectors/revocation.v1.json', summary: 'Portable, offline-verifiable revocation of a prior authorization.' },
  { profile: 'urn:ep:profile:eye-set:v1', wire_tag: 'EP-EYE-SET-v1', spec: 'docs/EP-EYE-SET-SPEC.md', vectors: 'conformance/vectors/eye-set.v1.json', summary: 'Eye continuous-eval posture as a signed RFC 8417 Security Event Token (never a gate).' },
  { profile: 'urn:ep:profile:execution-integrity:v1', wire_tag: 'EP-EXECUTION-INTEGRITY-v1', spec: 'docs/EP-WYSIWYS-SPEC.md', vectors: 'conformance/vectors/execution-integrity.v1.json', summary: 'What executed == what was approved (drift detection).' },
  { profile: 'urn:ep:profile:wysiwys:v1', wire_tag: 'EP-DISPLAY-ATTESTATION-v1', spec: 'docs/EP-WYSIWYS-SPEC.md', vectors: 'conformance/vectors/wysiwys.v1.json', summary: 'What the approver saw == what they signed (display attestation).' },
  { profile: 'urn:ep:profile:provenance-chain:v1', wire_tag: 'EP-PROVENANCE-CHAIN-v1', spec: 'docs/EP-PROVENANCE-RECEIPT-SPEC.md', vectors: 'conformance/vectors/provenance-chains.v1.json', summary: 'Root human signoff → bound delegation chain → per-action approval → execution.' },
  { profile: 'urn:ep:profile:resolution:v1', wire_tag: 'EP-RESOLUTION-v1', spec: 'docs/EP-RESOLUTION-SPEC.md', vectors: 'conformance/vectors/resolution.v1.json', summary: 'Device-signed approved, declined, amended, or rejected resolution of an exact binding-moment envelope and action.' },
]);

// The offline-resolvable action-type vocabulary (mirrors lib/guard-policies.js
// GUARD_ACTION_TYPES). A consequential action is "covered" when an action_type
// here maps to a policy that demands a receipt; new action types are new rows,
// not core changes.
export const ACTION_TYPES = Object.freeze([
  { action_type: 'benefit_bank_account_change', domain: 'government', risk: 'high' },
  { action_type: 'benefit_address_change', domain: 'government', risk: 'high' },
  { action_type: 'caseworker_override', domain: 'government', risk: 'high' },
  { action_type: 'gov.vendor_payment_destination_change', domain: 'government', risk: 'high' },
  { action_type: 'gov.disbursement_release', domain: 'government', risk: 'high' },
  { action_type: 'gov.grant_disbursement', domain: 'government', risk: 'high' },
  { action_type: 'gov.provider_enrollment_change', domain: 'government', risk: 'high' },
  { action_type: 'gov.eligibility_override', domain: 'government', risk: 'high' },
  { action_type: 'vendor_bank_account_change', domain: 'financial', risk: 'high' },
  { action_type: 'beneficiary_creation', domain: 'financial', risk: 'high' },
  { action_type: 'large_payment_release', domain: 'financial', risk: 'high' },
  { action_type: 'ai_agent_payment_action', domain: 'agentic', risk: 'high' },
]);

export const DESCRIPTOR_BY_URN = Object.freeze(
  Object.fromEntries(PROFILE_DESCRIPTORS.map((d) => [d.profile, d])),
);
