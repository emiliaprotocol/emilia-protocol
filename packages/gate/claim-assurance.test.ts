// SPDX-License-Identifier: Apache-2.0
import { test } from 'node:test';
import assert from 'node:assert/strict';

import {
  CLAIM_ASSURANCE_PROFILE_VERSION,
  CLAIM_CASE_VERSION,
  claimAssuranceArtifactDigest,
  claimAssuranceProfileHash,
  evaluateClaimAssurance,
  type ClaimAssuranceProfile,
  type ClaimCase,
  type EvidenceVerifierRegistration,
} from '../verify/dist/claim-assurance.js';
import {
  CLAIM_ASSURANCE_GATE_PRESENTATION_VERSION,
  CLAIM_ASSURANCE_ADMISSIBILITY_VERSION,
  buildReliancePacket,
  createClaimAssuranceAdmissibilityVerifier,
  createTrustedActionFirewall,
  createEg1Harness,
  EG1_DEFAULT_SELECTOR,
  hashCanonical,
  validateClaimAssuranceAdmissibilityResult,
} from './index.js';

const AS_OF = '2026-08-23T12:00:00Z';
const EVALUATED_AT = '2026-08-23T12:00:01Z';
const SUBJECT = `sha256:${'11'.repeat(32)}` as const;
const SCOPE = `sha256:${'22'.repeat(32)}` as const;
const IMPLEMENTATION = `sha256:${'44'.repeat(32)}` as const;

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
        verifier_id: 'example.bank-confirmation',
        verifier_version: '1.0.0',
        implementation_digest: IMPLEMENTATION,
      },
      minimum_distinct_sources: 1,
      max_age_seconds: 300,
    }],
  };
}

function artifact(sourceId = 'bank:one', relationship = 'SUPPORTS') {
  return { source_id: sourceId, relationship, observed_value: 'acct-ending-1234' };
}

function claimCase(
  pinnedProfile: ClaimAssuranceProfile,
  actionDigest: `sha256:${string}`,
  artifacts = [artifact()],
  asOf = AS_OF,
): ClaimCase {
  return {
    '@type': CLAIM_CASE_VERSION,
    subject_digest: SUBJECT,
    scope_digest: SCOPE,
    claim: {
      claim_id: 'claim:vendor:1234',
      claim_type: pinnedProfile.claim_type,
      predicate: pinnedProfile.predicate,
      value: { beneficiary_account_digest: `sha256:${'55'.repeat(32)}` },
    },
    profile_id: pinnedProfile.profile_id,
    profile_hash: claimAssuranceProfileHash(pinnedProfile),
    action_digest: actionDigest,
    as_of: asOf,
    evidence: artifacts.map((value, index) => ({
      evidence_id: `evidence:${index + 1}`,
      role: 'BANK_CONFIRMATION',
      verifier: {
        verifier_id: 'example.bank-confirmation',
        verifier_version: '1.0.0',
        implementation_digest: IMPLEMENTATION,
      },
      binding: {
        subject_digest: SUBJECT,
        scope_digest: SCOPE,
        claim_id: 'claim:vendor:1234',
        action_digest: actionDigest,
      },
      artifact: value,
      artifact_digest: claimAssuranceArtifactDigest(value),
    })),
  };
}

function registration(): EvidenceVerifierRegistration {
  return {
    verifier_id: 'example.bank-confirmation',
    verifier_version: '1.0.0',
    implementation_digest: IMPLEMENTATION,
    verify(input) {
      const body = input.artifact as ReturnType<typeof artifact>;
      return {
        verdict: 'VERIFIED',
        relationship: body.relationship as 'SUPPORTS' | 'CONTRADICTS',
        source_id: body.source_id,
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

function presentation(value: ClaimCase) {
  return {
    '@type': CLAIM_ASSURANCE_GATE_PRESENTATION_VERSION,
    claim_case: value,
  };
}

function verifierFor(pinnedProfile: ClaimAssuranceProfile, overrides: Record<string, unknown> = {}) {
  return createClaimAssuranceAdmissibilityVerifier({
    pinnedProfile,
    pinnedProfileHash: claimAssuranceProfileHash(pinnedProfile),
    evaluateClaimAssurance,
    verifierRegistry: [registration()],
    maxCaseAgeSec: 300,
    now: () => Date.parse(EVALUATED_AT),
    ...overrides,
  });
}

test('requires the reviewed evaluator as an explicit deployment trust input', () => {
  const pinnedProfile = profile();
  assert.throws(() => createClaimAssuranceAdmissibilityVerifier({
    pinnedProfile,
    pinnedProfileHash: claimAssuranceProfileHash(pinnedProfile),
    evaluateClaimAssurance: null as unknown as typeof evaluateClaimAssurance,
    verifierRegistry: [registration()],
    maxCaseAgeSec: 300,
  }), /evaluateClaimAssurance must be a reviewed function/);
});

test('re-performs a Claim Case and returns an exact-action, non-authorizing admissibility block', async () => {
  const harness = createEg1Harness();
  const pinnedProfile = profile();
  const actionDigest = `sha256:${hashCanonical(harness.action)}` as const;
  const verify = verifierFor(pinnedProfile);
  const block = await verify({
    pinned_profile: {
      id: pinnedProfile.profile_id,
      profile_hash: claimAssuranceProfileHash(pinnedProfile),
    },
    presented: presentation(claimCase(pinnedProfile, actionDigest)),
    receipt: harness.mint(),
    selector: EG1_DEFAULT_SELECTOR,
    observed_action: harness.action,
  });

  assert.equal(block.verdict, 'admissible');
  assert.equal(block.claim_assurance_verdict, 'VERIFIED');
  assert.equal(block.action_digest, actionDigest);
  assert.equal(block.authorizes_action, false);
  assert.match(block.assurance_record_digest, /^sha256:[0-9a-f]{64}$/);
  assert.match(block.claim_case_digest, /^sha256:[0-9a-f]{64}$/);
  assert.equal(validateClaimAssuranceAdmissibilityResult(block).ok, true);

  for (const invalidId of ['not a schema identifier', `a${'b'.repeat(128)}`]) {
    const invalid = {
      ...block,
      admissibility_profile: { ...block.admissibility_profile, id: invalidId },
    };
    assert.equal(validateClaimAssuranceAdmissibilityResult(invalid).ok, false);
  }
});

test('verified claim evidence remains additional evidence and cannot replace a receipt', async () => {
  const harness = createEg1Harness();
  const pinnedProfile = profile();
  const profileHash = claimAssuranceProfileHash(pinnedProfile);
  const actionDigest = `sha256:${hashCanonical(harness.action)}` as const;
  let verifierCalls = 0;
  const trustedVerifier = verifierFor(pinnedProfile);
  const gate = createTrustedActionFirewall({
    trustedKeys: [harness.publicKey],
    approverKeys: harness.approverKeys,
    rpId: harness.rpId,
    allowedOrigins: harness.allowedOrigins,
    requiredAdmissibilityProfile: { id: pinnedProfile.profile_id, profile_hash: profileHash },
    verifyAdmissibilityPacket: async (input) => {
      verifierCalls += 1;
      return trustedVerifier(input);
    },
    allowEphemeralStore: true,
  });
  let ran = false;
  const out = await gate.run(
    {
      selector: EG1_DEFAULT_SELECTOR,
      receipt: null,
      observedAction: harness.action,
      admissibility: presentation(claimCase(pinnedProfile, actionDigest)),
    },
    async () => { ran = true; },
  );

  assert.equal(out.ok, false);
  assert.equal(out.authorization.reason, 'receipt_required');
  assert.equal(verifierCalls, 0, 'authority must fail before claim evaluation');
  assert.equal(ran, false);
});

test('exact-action substitution refuses before receipt consumption and a corrected retry succeeds', async () => {
  const harness = createEg1Harness();
  const pinnedProfile = profile();
  const profileHash = claimAssuranceProfileHash(pinnedProfile);
  const actionDigest = `sha256:${hashCanonical(harness.action)}` as const;
  const gate = createTrustedActionFirewall({
    trustedKeys: [harness.publicKey],
    approverKeys: harness.approverKeys,
    rpId: harness.rpId,
    allowedOrigins: harness.allowedOrigins,
    requiredAdmissibilityProfile: { id: pinnedProfile.profile_id, profile_hash: profileHash },
    verifyAdmissibilityPacket: verifierFor(pinnedProfile),
    allowEphemeralStore: true,
  });
  const receipt = harness.mint();
  let ran = false;
  const substituted = await gate.run(
    {
      selector: EG1_DEFAULT_SELECTOR,
      receipt,
      observedAction: harness.action,
      admissibility: presentation(claimCase(pinnedProfile, `sha256:${'99'.repeat(32)}`)),
    },
    async () => { ran = true; },
  );
  assert.equal(substituted.ok, false);
  assert.equal(substituted.authorization.reason, 'admissibility_verification_failed');
  assert.equal(ran, false);

  const corrected = await gate.run(
    {
      selector: EG1_DEFAULT_SELECTOR,
      receipt,
      observedAction: harness.action,
      admissibility: presentation(claimCase(pinnedProfile, actionDigest)),
    },
    async () => ({ ran: true }),
  );
  assert.equal(corrected.ok, true, 'failed claim verification must not burn the receipt');
  assert.equal(corrected.authorization.evidence.admissibility.authorizes_action, false);
  assert.equal(corrected.packet.admissibility.authorizes_action, false);
  assert.equal(validateClaimAssuranceAdmissibilityResult(corrected.packet.admissibility).ok, true);
  assert.equal(Object.hasOwn(corrected.packet.admissibility, 'admissible'), false);
  assert.equal(corrected.packet.admissibility_evaluation.admissible, true);
});

test('closed claim states map to fail-closed Gate admissibility states', async () => {
  const harness = createEg1Harness();
  const pinnedProfile = profile();
  const actionDigest = `sha256:${hashCanonical(harness.action)}` as const;
  const verify = verifierFor(pinnedProfile);
  const base = {
    pinned_profile: {
      id: pinnedProfile.profile_id,
      profile_hash: claimAssuranceProfileHash(pinnedProfile),
    },
    receipt: harness.mint(),
    selector: EG1_DEFAULT_SELECTOR,
    observed_action: harness.action,
  };

  const missing = await verify({
    ...base,
    presented: presentation(claimCase(pinnedProfile, actionDigest, [])),
  });
  assert.equal(missing.claim_assurance_verdict, 'INDETERMINATE');
  assert.equal(missing.verdict, 'missing_evidence');

  const diverged = await verify({
    ...base,
    presented: presentation(claimCase(pinnedProfile, actionDigest, [
      artifact('bank:one', 'SUPPORTS'),
      artifact('bank:two', 'CONTRADICTS'),
    ])),
  });
  assert.equal(diverged.claim_assurance_verdict, 'DIVERGED');
  assert.equal(diverged.verdict, 'conflicted');
});

test('an otherwise verified but old Claim Case maps to stale', async () => {
  const harness = createEg1Harness();
  const pinnedProfile = profile();
  const actionDigest = `sha256:${hashCanonical(harness.action)}` as const;
  const verify = verifierFor(pinnedProfile, {
    maxCaseAgeSec: 30,
    now: () => Date.parse('2026-08-23T12:01:00Z'),
  });
  const block = await verify({
    pinned_profile: {
      id: pinnedProfile.profile_id,
      profile_hash: claimAssuranceProfileHash(pinnedProfile),
    },
    presented: presentation(claimCase(pinnedProfile, actionDigest)),
    receipt: harness.mint(),
    selector: EG1_DEFAULT_SELECTOR,
    observed_action: harness.action,
  });
  assert.equal(block.claim_assurance_verdict, 'VERIFIED');
  assert.equal(block.verdict, 'stale');
  assert.ok(block.reasons.includes('CLAIM_CASE_STALE'));
});

test('conflict outranks staleness so an old divergent case remains a valid typed result', async () => {
  const harness = createEg1Harness();
  const pinnedProfile = profile();
  const actionDigest = `sha256:${hashCanonical(harness.action)}` as const;
  const verify = verifierFor(pinnedProfile, {
    maxCaseAgeSec: 30,
    now: () => Date.parse('2026-08-23T12:01:00Z'),
  });
  const block = await verify({
    pinned_profile: {
      id: pinnedProfile.profile_id,
      profile_hash: claimAssuranceProfileHash(pinnedProfile),
    },
    presented: presentation(claimCase(pinnedProfile, actionDigest, [
      artifact('bank:one', 'SUPPORTS'),
      artifact('bank:two', 'CONTRADICTS'),
    ], AS_OF)),
    receipt: harness.mint(),
    selector: EG1_DEFAULT_SELECTOR,
    observed_action: harness.action,
  });
  assert.equal(block.claim_assurance_verdict, 'DIVERGED');
  assert.equal(block.verdict, 'conflicted');
  assert.ok(block.reasons.includes('CLAIM_CASE_STALE'));
  assert.equal(validateClaimAssuranceAdmissibilityResult(block).ok, true);
});

test('a claim-shaped admissibility block missing the non-authority bit fails reliance closed', async () => {
  const packet = await buildReliancePacket({
    decision: { allow: true, evidence: { hash: 'decision-hash' } },
    execution: { kind: 'execution', authorizes_decision: 'decision-hash' },
    evidence: { ok: true },
    admissibility: {
      '@type': CLAIM_ASSURANCE_ADMISSIBILITY_VERSION,
      admissibility_profile: { id: 'emilia.finance.vendor-account.v1', version: '1' },
      profile_hash: `sha256:${'aa'.repeat(32)}`,
      verdict: 'admissible',
      replay_digest: `sha256:${'bb'.repeat(32)}`,
    },
  });
  assert.equal(packet.admissibility, null);
  assert.equal(packet.admissibility_evaluation.admissible, false);
  assert.match(packet.admissibility_evaluation.validation_error, /shape|authorizes_action/);
  assert.equal(packet.verdict, 'do_not_rely');
});

test('Gate refuses forged Claim Assurance results before execution or receipt consumption', async () => {
  const harness = createEg1Harness();
  const pinnedProfile = profile();
  const profileHash = claimAssuranceProfileHash(pinnedProfile);
  const actionDigest = `sha256:${hashCanonical(harness.action)}` as const;
  const trustedVerifier = verifierFor(pinnedProfile);
  let forgedResult: Record<string, unknown> | null = null;
  const gate = createTrustedActionFirewall({
    trustedKeys: [harness.publicKey],
    approverKeys: harness.approverKeys,
    rpId: harness.rpId,
    allowedOrigins: harness.allowedOrigins,
    requiredAdmissibilityProfile: { id: pinnedProfile.profile_id, profile_hash: profileHash },
    verifyAdmissibilityPacket: async (input) => forgedResult ?? trustedVerifier(input),
    allowEphemeralStore: true,
  });
  const receipt = harness.mint();
  const valid = await trustedVerifier({
    pinned_profile: { id: pinnedProfile.profile_id, profile_hash: profileHash },
    presented: presentation(claimCase(pinnedProfile, actionDigest)),
    receipt,
    selector: EG1_DEFAULT_SELECTOR,
    observed_action: harness.action,
  });

  const attacks = [
    { name: 'authority bit', patch: { authorizes_action: true } },
    { name: 'profile id', patch: { admissibility_profile: { id: 'attacker-profile', version: '1' } } },
    { name: 'profile hash', patch: { profile_hash: `sha256:${'88'.repeat(32)}` } },
    { name: 'action digest', patch: { action_digest: `sha256:${'99'.repeat(32)}` } },
    { name: 'record digest', patch: { assurance_record_digest: 'sha256:not-a-digest' } },
    { name: 'evaluation time', patch: { evaluated_at: 'not-an-instant' } },
    { name: 'claim verdict', patch: { claim_assurance_verdict: 'DIVERGED' } },
    { name: 'profile satisfaction', patch: { profile_satisfied: false } },
    { name: 'unknown extension', patch: { attacker_extension: true } },
  ];

  for (const attack of attacks) {
    forgedResult = { ...valid, ...attack.patch };
    let ran = false;
    const refused = await gate.run(
      {
        selector: EG1_DEFAULT_SELECTOR,
        receipt,
        observedAction: harness.action,
        admissibility: presentation(claimCase(pinnedProfile, actionDigest)),
      },
      async () => { ran = true; },
    );
    assert.equal(refused.ok, false, `${attack.name} forgery must fail closed`);
    assert.match(refused.authorization.reason, /^claim_assurance_result_invalid:/);
    assert.equal(ran, false, `${attack.name} forgery must not reach execution`);
  }

  forgedResult = null;
  const corrected = await gate.run(
    {
      selector: EG1_DEFAULT_SELECTOR,
      receipt,
      observedAction: harness.action,
      admissibility: presentation(claimCase(pinnedProfile, actionDigest)),
    },
    async () => ({ ran: true }),
  );
  assert.equal(corrected.ok, true, 'forged results must be rejected before receipt reservation');
});

test('reliance packet refuses a Claim Assurance block with authority or invalid action/profile data', async () => {
  const harness = createEg1Harness();
  const pinnedProfile = profile();
  const actionDigest = `sha256:${hashCanonical(harness.action)}` as const;
  const valid = await verifierFor(pinnedProfile)({
    pinned_profile: {
      id: pinnedProfile.profile_id,
      profile_hash: claimAssuranceProfileHash(pinnedProfile),
    },
    presented: presentation(claimCase(pinnedProfile, actionDigest)),
    receipt: harness.mint(),
    selector: EG1_DEFAULT_SELECTOR,
    observed_action: harness.action,
  });

  for (const forged of [
    { ...valid, authorizes_action: true },
    { ...valid, action_digest: 'sha256:not-a-digest' },
    { ...valid, admissibility_profile: { id: '', version: '1' } },
    { ...valid, verdict: 'stale', profile_satisfied: false },
    {
      ...valid,
      verdict: 'unverifiable',
      claim_assurance_verdict: 'DIVERGED',
      profile_satisfied: false,
    },
  ]) {
    const packet = await buildReliancePacket({
      decision: { allow: true, evidence: { hash: 'decision-hash' } },
      execution: { kind: 'execution', authorizes_decision: 'decision-hash' },
      evidence: { ok: true },
      admissibility: forged,
    });
    assert.equal(packet.admissibility, null);
    assert.equal(packet.admissibility_evaluation.admissible, false);
    assert.equal(packet.verdict, 'do_not_rely');
  }
});
