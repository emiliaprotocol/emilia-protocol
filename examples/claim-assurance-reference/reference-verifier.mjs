// SPDX-License-Identifier: Apache-2.0
/**
 * Deliberately small verifier used only by the synthetic Claim Assurance
 * reference fixture. Its exact source bytes are SHA-256 pinned by the profile.
 * A relying party supplies this code out of band; the Claim Case cannot select
 * or replace it.
 */

export const REFERENCE_VERIFIER_ID = 'emilia.reference.synthetic-destination';
export const REFERENCE_VERIFIER_VERSION = '1.0.0';

function objectOrEmpty(value) {
  return value !== null && typeof value === 'object' && !Array.isArray(value)
    ? value
    : {};
}

export function createReferenceVerifierRegistration(implementationDigest) {
  return {
    verifier_id: REFERENCE_VERIFIER_ID,
    verifier_version: REFERENCE_VERIFIER_VERSION,
    implementation_digest: implementationDigest,
    verify(input) {
      const artifact = objectOrEmpty(input.artifact);
      const claimValue = objectOrEmpty(input.claim.value);
      const reasons = [];

      if (artifact['@type'] !== 'EMILIA-SYNTHETIC-DESTINATION-EVIDENCE-v1') {
        reasons.push('REFERENCE_ARTIFACT_TYPE_MISMATCH');
      }
      if (artifact.synthetic_reference_only !== true) {
        reasons.push('REFERENCE_ONLY_MARKER_MISSING');
      }
      if (typeof artifact.source_id !== 'string' || !artifact.source_id.startsWith('synthetic:')) {
        reasons.push('SYNTHETIC_SOURCE_ID_REQUIRED');
      }
      if (artifact.subject_digest !== input.subject_digest) reasons.push('SUBJECT_MISMATCH');
      if (artifact.scope_digest !== input.scope_digest) reasons.push('SCOPE_MISMATCH');
      if (artifact.claim_id !== input.claim.claim_id) reasons.push('CLAIM_MISMATCH');
      if (artifact.action_digest !== input.action_digest) reasons.push('ACTION_MISMATCH');
      if (artifact.observed_destination_digest !== claimValue.destination_digest) {
        reasons.push('DESTINATION_MISMATCH');
      }

      return {
        verdict: reasons.length === 0 ? 'VERIFIED' : 'UNVERIFIED',
        relationship: reasons.length === 0 ? 'SUPPORTS' : 'NEUTRAL',
        source_id: typeof artifact.source_id === 'string'
          ? artifact.source_id
          : 'synthetic:invalid-source',
        subject_digest: input.subject_digest,
        scope_digest: input.scope_digest,
        claim_id: input.claim.claim_id,
        observed_at: typeof artifact.observed_at === 'string'
          ? artifact.observed_at
          : input.as_of,
        expires_at: typeof artifact.expires_at === 'string'
          ? artifact.expires_at
          : input.as_of,
        artifact_digest: input.artifact_digest,
        reasons,
      };
    },
  };
}
