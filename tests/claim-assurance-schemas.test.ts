// SPDX-License-Identifier: Apache-2.0
import { readFileSync } from 'node:fs';
import { describe, expect, it } from 'vitest';
import Ajv2020 from 'ajv/dist/2020.js';

import {
  CLAIM_ASSURANCE_PROFILE_VERSION,
  CLAIM_CASE_VERSION,
  claimAssuranceArtifactDigest,
  claimAssuranceProfileHash,
  evaluateClaimAssurance,
  type ClaimAssuranceProfile,
  type ClaimCase,
  type EvidenceVerifierRegistration,
} from '../packages/verify/src/claim-assurance.js';
import {
  CLAIM_ASSURANCE_GATE_PRESENTATION_VERSION,
  createClaimAssuranceAdmissibilityVerifier,
} from '../packages/gate/src/claim-assurance.js';
import { hashCanonical } from '../packages/gate/src/execution-binding.js';

const schemaFiles = [
  'ep-claim-assurance-profile.schema.json',
  'ep-claim-case.schema.json',
  'ep-assurance-record.schema.json',
  'ep-claim-assurance-gate-presentation.schema.json',
  'ep-claim-assurance-admissibility.schema.json',
] as const;

const schemas = schemaFiles.map((name) => JSON.parse(readFileSync(
  new URL(`../public/schemas/${name}`, import.meta.url),
  'utf8',
)));
const ajv = new Ajv2020({ allErrors: true, strict: false, validateFormats: false });
for (const schema of schemas) ajv.addSchema(schema);

const D = (character: string) => `sha256:${character.repeat(64)}` as const;
const ACTION = { action_type: 'finance.vendor_bank_change', vendor_id: 'vendor-1234' };
const ACTION_DIGEST = `sha256:${hashCanonical(ACTION)}` as const;
const AS_OF = '2026-08-23T12:00:00Z';
const EVALUATED_AT = '2026-08-23T12:00:01Z';

function profile(): ClaimAssuranceProfile {
  return {
    '@type': CLAIM_ASSURANCE_PROFILE_VERSION,
    profile_id: 'emilia.finance.vendor-account.v1',
    claim_type: 'finance.vendor-account',
    predicate: 'beneficiary-account-is-approved',
    requirements: [{
      requirement_id: 'bank-confirmation',
      evidence_role: 'BANK_CONFIRMATION',
      verifier: {
        verifier_id: 'reference.bank-confirmation',
        verifier_version: '1.0.0',
        implementation_digest: D('4'),
      },
      minimum_distinct_sources: 1,
      max_age_seconds: 300,
    }],
  };
}

function claimCase(pinnedProfile: ClaimAssuranceProfile, actionDigest = ACTION_DIGEST): ClaimCase {
  const artifact = { source_id: 'bank:reference', relationship: 'SUPPORTS' };
  return {
    '@type': CLAIM_CASE_VERSION,
    subject_digest: D('1'),
    scope_digest: D('2'),
    claim: {
      claim_id: 'claim:vendor:1234',
      claim_type: pinnedProfile.claim_type,
      predicate: pinnedProfile.predicate,
      value: { beneficiary_account_digest: D('5') },
    },
    profile_id: pinnedProfile.profile_id,
    profile_hash: claimAssuranceProfileHash(pinnedProfile),
    action_digest: actionDigest,
    as_of: AS_OF,
    evidence: [{
      evidence_id: 'evidence:1',
      role: 'BANK_CONFIRMATION',
      verifier: pinnedProfile.requirements[0]!.verifier,
      binding: {
        subject_digest: D('1'),
        scope_digest: D('2'),
        claim_id: 'claim:vendor:1234',
        action_digest: actionDigest,
      },
      artifact,
      artifact_digest: claimAssuranceArtifactDigest(artifact),
    }],
  };
}

function registration(pinnedProfile: ClaimAssuranceProfile): EvidenceVerifierRegistration {
  return {
    ...pinnedProfile.requirements[0]!.verifier,
    verify(input) {
      return {
        verdict: 'VERIFIED',
        relationship: 'SUPPORTS',
        source_id: 'bank:reference',
        subject_digest: input.subject_digest,
        scope_digest: input.scope_digest,
        claim_id: input.claim.claim_id,
        observed_at: '2026-08-23T11:59:00Z',
        expires_at: '2026-08-23T12:04:00Z',
        artifact_digest: input.artifact_digest,
        reasons: [],
      };
    },
  };
}

function validates(id: string, value: unknown): boolean {
  const validate = ajv.getSchema(id);
  if (!validate) throw new Error(`schema not registered: ${id}`);
  return validate(value) as boolean;
}

describe('Claim Assurance public schemas', () => {
  it('validate implementation-emitted profile, case, record, presentation, and Gate block', async () => {
    const pinnedProfile = profile();
    const hash = claimAssuranceProfileHash(pinnedProfile);
    const value = claimCase(pinnedProfile);
    const verifier = registration(pinnedProfile);
    const record = evaluateClaimAssurance(value, {
      pinned_profile: pinnedProfile,
      pinned_profile_hash: hash,
      verifier_registry: [verifier],
      evaluated_at: EVALUATED_AT,
      expected_action_digest: ACTION_DIGEST,
    });
    const presentation = {
      '@type': CLAIM_ASSURANCE_GATE_PRESENTATION_VERSION,
      claim_case: value,
    };
    const gateVerifier = createClaimAssuranceAdmissibilityVerifier({
      pinnedProfile,
      pinnedProfileHash: hash,
      evaluateClaimAssurance,
      verifierRegistry: [verifier],
      maxCaseAgeSec: 300,
      now: () => Date.parse(EVALUATED_AT),
    });
    const block = await gateVerifier({
      pinned_profile: { id: pinnedProfile.profile_id, profile_hash: hash },
      presented: presentation,
      observed_action: ACTION,
    });

    expect(validates(schemas[0].$id, pinnedProfile)).toBe(true);
    expect(validates(schemas[1].$id, value)).toBe(true);
    expect(validates(schemas[2].$id, record)).toBe(true);
    expect(validates(schemas[3].$id, presentation)).toBe(true);

    expect(validates(schemas[4].$id, block)).toBe(true);
  });

  it('rejects extensions and any attempt to turn an Assurance Record into authority', () => {
    const pinnedProfile = profile();
    const record = evaluateClaimAssurance(claimCase(pinnedProfile), {
      pinned_profile: pinnedProfile,
      pinned_profile_hash: claimAssuranceProfileHash(pinnedProfile),
      verifier_registry: [registration(pinnedProfile)],
      evaluated_at: EVALUATED_AT,
      expected_action_digest: ACTION_DIGEST,
    });
    const authorityClaim = { ...record, authorizes_action: true };
    expect(validates(schemas[2].$id, authorityClaim)).toBe(false);

    const extended = { ...profile(), presenter_selected_trust: true };
    expect(validates(schemas[0].$id, extended)).toBe(false);
  });
});
