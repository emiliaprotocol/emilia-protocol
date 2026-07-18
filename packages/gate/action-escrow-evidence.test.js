// SPDX-License-Identifier: Apache-2.0
import assert from 'node:assert/strict';
import test from 'node:test';
import {
  ACTION_ESCROW_EVIDENCE_PACKAGE_VERSION,
  buildActionEscrowEvidencePackage,
  parseActionEscrowEvidencePackage,
  verifyActionEscrowEvidencePackage,
} from './action-escrow-evidence.js';

const NOW = '2026-07-17T12:00:00.000Z';
const PDF = Buffer.from('%PDF-1.7\nfinal contractor agreement\n%%EOF', 'utf8');
const BINDING_DIGEST = `sha256:${'11'.repeat(32)}`;
const ACTION_DIGEST = `sha256:${'22'.repeat(32)}`;
const PROFILE_DIGEST = `sha256:${'55'.repeat(32)}`;

function inputs(stage = 'released') {
  return {
    agreementId: 'agreement-kitchen-001',
    stage,
    binding: {
      version: 'EP-DOCUMENT-ACTION-BINDING-v1',
      binding_id: 'binding-001',
      payload: { immutable: true },
    },
    documentBytes: PDF,
    documentFileName: 'change-order-3.pdf',
    documentExecution: { token: 'provider-executed' },
    agreementAcceptances: [
      { party_id: 'homeowner-1', role: 'customer', evidence: { token: 'agreement-homeowner-ok' } },
      { party_id: 'contractor-1', role: 'contractor', evidence: { token: 'agreement-contractor-ok' } },
    ],
    releaseApprovals: [
      { party_id: 'homeowner-1', role: 'customer', evidence: { token: 'release-homeowner-ok' } },
      { party_id: 'contractor-1', role: 'contractor', evidence: { token: 'release-contractor-ok' } },
    ],
    fundingStatement: { token: 'funded' },
    milestones: [
      { milestone_id: 'rough-in', evidence: { digest: `sha256:${'33'.repeat(32)}` }, resolution: { token: 'accepted' } },
    ],
    release: {
      reservation: { token: 'reserved' },
      provider_request: { token: 'requested' },
      provider_statement: { token: 'released' },
      execution_record: { token: 'recorded', at: NOW },
    },
    stateRecord: {
      snapshot: { token: stage },
      statement: { token: `signed-${stage}` },
    },
    amendments: [],
    verificationProfile: { id: 'contractor.v1', digest: `sha256:${'44'.repeat(32)}` },
  };
}

function verifiers(overrides = {}) {
  return {
    verifyBinding: async (_binding, context) => ({
      valid: true,
      agreement_id: context.expectedAgreementId,
      document_digest: context.expectedDocumentDigest,
      binding_digest: BINDING_DIGEST,
      action_digest: ACTION_DIGEST,
      supersedes_digest: null,
      required_parties: [
        { party_id: 'homeowner-1', role: 'customer' },
        { party_id: 'contractor-1', role: 'contractor' },
      ],
    }),
    verifyProfile: async (_profile, context) => ({
      valid: true,
      agreement_id: context.agreementId,
      binding_digest: context.bindingDigest,
      action_digest: context.actionDigest,
      profile_digest: PROFILE_DIGEST,
      required_release_parties: [
        { party_id: 'homeowner-1', role: 'customer' },
        { party_id: 'contractor-1', role: 'contractor' },
      ],
    }),
    verifyState: async (_state, context) => ({
      valid: true,
      agreement_id: context.agreementId,
      binding_digest: context.bindingDigest,
      action_digest: context.actionDigest,
      profile_digest: context.profileDigest,
      state: context.stage,
      revision: 0,
      amendment_digests: context.amendmentDigests,
    }),
    verifyDocumentExecution: async (_execution, context) => ({
      valid: true,
      authorizes_action: false,
      agreement_id: context.agreementId,
      binding_digest: context.bindingDigest,
      document_digest: context.documentDigest,
      state: 'executed',
    }),
    verifyAgreementAcceptance: async (evidence, context) => ({
      valid: evidence?.token?.startsWith('agreement-') === true,
      accepts_agreement: true,
      authorizes_action: false,
      agreement_id: context.agreementId,
      party_id: context.partyId,
      role: context.role,
      binding_digest: context.bindingDigest,
      document_digest: context.documentDigest,
      principal_key_id: `agreement-key:${context.partyId}`,
    }),
    verifyReleaseApproval: async (evidence, context) => ({
      valid: evidence?.token?.startsWith('release-') === true,
      authorizes_action: true,
      outcome: 'approved',
      agreement_id: context.agreementId,
      party_id: context.partyId,
      role: context.role,
      binding_digest: context.bindingDigest,
      action_digest: context.actionDigest,
      milestone_evidence_digests: context.milestoneEvidenceDigests,
      principal_key_id: `release-key:${context.partyId}`,
      issued_at: '2026-07-17T11:56:00.000Z',
      expires_at: '2026-07-17T12:30:00.000Z',
      admitted_at: NOW,
    }),
    verifyFunding: async (_statement, context) => ({
      valid: true,
      agreement_id: context.agreementId,
      binding_digest: context.bindingDigest,
      action_digest: context.actionDigest,
      state: 'funded',
    }),
    verifyMilestone: async (milestone, context) => ({
      valid: true,
      agreement_id: context.agreementId,
      milestone_id: milestone.milestone_id,
      binding_digest: context.bindingDigest,
      action_digest: context.actionDigest,
      evidence_digest: milestone.evidence.digest,
    }),
    verifyAmendment: async () => ({ valid: false, reason: 'unexpected_amendment' }),
    verifyRelease: async (_release, context) => ({
      valid: true,
      agreement_id: context.agreementId,
      binding_digest: context.bindingDigest,
      action_digest: context.actionDigest,
      state: context.stage === 'release_indeterminate'
        ? 'indeterminate'
        : context.stage === 'release_reserved' ? 'reserved' : 'released',
    }),
    ...overrides,
  };
}

async function verify(pkg, extra = {}) {
  return verifyActionEscrowEvidencePackage(pkg, {
    documentBytes: PDF,
    expectedAgreementId: 'agreement-kitchen-001',
    now: NOW,
    ...verifiers(),
    ...extra,
  });
}

test('released package re-performs every trust boundary', async () => {
  const pkg = buildActionEscrowEvidencePackage(inputs(), { now: NOW });
  assert.equal(pkg.version, ACTION_ESCROW_EVIDENCE_PACKAGE_VERSION);
  const result = await verify(pkg);
  assert.equal(result.valid, true);
  assert.equal(result.reason, 'verified');
  assert.deepEqual(Object.values(result.checks), Array(Object.keys(result.checks).length).fill(true));
});

test('builder snapshots caller objects before hashing', async () => {
  const source = inputs();
  const pkg = buildActionEscrowEvidencePackage(source, { now: NOW });
  source.binding.payload.immutable = false;
  source.releaseApprovals[0].party_id = 'attacker';
  assert.equal(pkg.binding.payload.immutable, true);
  assert.equal(pkg.release_approvals[0].party_id, 'homeowner-1');
  assert.equal((await verify(pkg)).valid, true);
});

test('changed document bytes are refused before component verification', async () => {
  const pkg = buildActionEscrowEvidencePackage(inputs(), { now: NOW });
  const result = await verifyActionEscrowEvidencePackage(pkg, {
    documentBytes: Buffer.from('%PDF-1.7\npay attacker\n%%EOF'),
    now: NOW,
    ...verifiers(),
  });
  assert.equal(result.valid, false);
  assert.equal(result.reason, 'document_bytes_mismatch');
});

test('tampered package cannot carry its old digest', async () => {
  const pkg = structuredClone(buildActionEscrowEvidencePackage(inputs(), { now: NOW }));
  pkg.stage = 'completed';
  const result = await verify(pkg);
  assert.equal(result.valid, false);
  assert.equal(result.reason, 'package_digest_mismatch');
});

test('provider completion cannot substitute for a party approval', async () => {
  const source = inputs();
  source.releaseApprovals[0].evidence = { token: 'esign-provider-complete' };
  const pkg = buildActionEscrowEvidencePackage(source, { now: NOW });
  const result = await verify(pkg);
  assert.equal(result.valid, false);
  assert.equal(result.reason, 'release_approval_verification_failed');
});

test('document execution, agreement acceptance, and release approval are non-substitutable rows', async (t) => {
  for (const [name, mutate, reason] of [
    [
      'document execution as agreement acceptance',
      (source) => {
        source.agreementAcceptances[0].evidence = source.documentExecution;
      },
      'agreement_acceptance_verification_failed',
    ],
    [
      'release approval as agreement acceptance',
      (source) => {
        source.agreementAcceptances[0].evidence = { token: 'release-homeowner-ok' };
      },
      'agreement_acceptance_verification_failed',
    ],
    [
      'agreement acceptance as release approval',
      (source) => {
        source.releaseApprovals[0].evidence = { token: 'agreement-homeowner-ok' };
      },
      'release_approval_verification_failed',
    ],
  ]) {
    await t.test(name, async () => {
      const source = inputs();
      mutate(source);
      const result = await verify(buildActionEscrowEvidencePackage(source, { now: NOW }));
      assert.equal(result.valid, false);
      assert.equal(result.reason, reason);
    });
  }

  await t.test('one key cannot fill two release seats', async () => {
    const pkg = buildActionEscrowEvidencePackage(inputs(), { now: NOW });
    const result = await verify(pkg, {
      verifyReleaseApproval: async (_evidence, context) => ({
        valid: true,
        authorizes_action: true,
        outcome: 'approved',
        agreement_id: context.agreementId,
        party_id: context.partyId,
        role: context.role,
        binding_digest: context.bindingDigest,
        action_digest: context.actionDigest,
        milestone_evidence_digests: context.milestoneEvidenceDigests,
        principal_key_id: 'shared-release-key',
        issued_at: '2026-07-17T11:56:00.000Z',
        expires_at: '2026-07-17T12:30:00.000Z',
        admitted_at: NOW,
      }),
    });
    assert.equal(result.valid, false);
    assert.equal(result.reason, 'release_approval_verification_failed');
  });
});

test('missing, duplicate, extra, and wrong-role approvals are refused', async (t) => {
  for (const [name, mutate] of [
    ['missing', (source) => source.releaseApprovals.pop()],
    ['duplicate', (source) => { source.releaseApprovals[1] = structuredClone(source.releaseApprovals[0]); }],
    ['extra', (source) => source.releaseApprovals.push({ party_id: 'observer', role: 'observer', evidence: { token: 'release-observer-ok' } })],
    ['wrong role', (source) => { source.releaseApprovals[0].role = 'contractor'; }],
  ]) {
    await t.test(name, async () => {
      const source = inputs();
      mutate(source);
      const result = await verify(buildActionEscrowEvidencePackage(source, { now: NOW }));
      assert.equal(result.valid, false);
      assert.equal(result.reason, 'release_approval_verification_failed');
    });
  }
});

test('binding, profile, state, funding, milestone, and release substitutions each fail closed', async (t) => {
  const cases = [
    ['binding', { verifyBinding: async () => ({ valid: false, reason: 'wrong_document' }) }, 'binding_verification_failed'],
    ['profile', { verifyProfile: async () => ({ valid: false, reason: 'profile_unpinned' }) }, 'verification_profile_failed'],
    ['state', { verifyState: async () => ({ valid: false, reason: 'stale_revision' }) }, 'state_record_verification_failed'],
    ['funding', { verifyFunding: async () => ({ valid: false, reason: 'not_funded' }) }, 'funding_statement_verification_failed'],
    ['milestone', { verifyMilestone: async () => ({ valid: false, reason: 'wrong_milestone' }) }, 'milestone_verification_failed'],
    ['release', { verifyRelease: async () => ({ valid: false, reason: 'webhook_only' }) }, 'release_verification_failed'],
  ];
  for (const [name, override, reason] of cases) {
    await t.test(name, async () => {
      const pkg = buildActionEscrowEvidencePackage(inputs(), { now: NOW });
      const result = await verify(pkg, override);
      assert.equal(result.valid, false);
      assert.equal(result.reason, reason);
    });
  }
});

test('component verifiers must echo the exact agreement, binding, and action they checked', async (t) => {
  const cases = [
    ['profile agreement', 'verifyProfile', 'agreement_id', 'verification_profile_failed'],
    ['profile binding', 'verifyProfile', 'binding_digest', 'verification_profile_failed'],
    ['profile action', 'verifyProfile', 'action_digest', 'verification_profile_failed'],
    ['agreement acceptance agreement', 'verifyAgreementAcceptance', 'agreement_id', 'agreement_acceptance_verification_failed'],
    ['funding action', 'verifyFunding', 'action_digest', 'funding_statement_verification_failed'],
    ['milestone agreement', 'verifyMilestone', 'agreement_id', 'milestone_verification_failed'],
    ['milestone action', 'verifyMilestone', 'action_digest', 'milestone_verification_failed'],
    ['release approval agreement', 'verifyReleaseApproval', 'agreement_id', 'release_approval_verification_failed'],
  ];
  for (const [name, verifierName, field, reason] of cases) {
    await t.test(name, async () => {
      const verifier = verifiers()[verifierName];
      const result = await verify(
        buildActionEscrowEvidencePackage(inputs(), { now: NOW }),
        {
          [verifierName]: async (...args) => {
            const verified = await verifier(...args);
            return { ...verified, [field]: 'attacker-controlled-value' };
          },
        },
      );
      assert.equal(result.valid, false);
      assert.equal(result.reason, reason);
    });
  }

  await t.test('omitted agreement echo is also refused', async () => {
    const verifier = verifiers().verifyAgreementAcceptance;
    const result = await verify(
      buildActionEscrowEvidencePackage(inputs(), { now: NOW }),
      {
        verifyAgreementAcceptance: async (...args) => {
          const verified = await verifier(...args);
          delete verified.agreement_id;
          return verified;
        },
      },
    );
    assert.equal(result.valid, false);
    assert.equal(result.reason, 'agreement_acceptance_verification_failed');
  });
});

test('verified amendment chain must terminate at the current binding and match state', async () => {
  const source = inputs('effective');
  source.releaseApprovals = [];
  source.fundingStatement = null;
  source.milestones = [];
  source.release = null;
  source.amendments = [{ amendment_id: 'amendment-1' }];
  const pkg = buildActionEscrowEvidencePackage(source, { now: NOW });
  const previous = `sha256:${'66'.repeat(32)}`;
  const amendmentDigest = `sha256:${'77'.repeat(32)}`;

  const result = await verify(pkg, {
    verifyBinding: async (_binding, context) => ({
      valid: true,
      agreement_id: context.expectedAgreementId,
      document_digest: context.expectedDocumentDigest,
      binding_digest: BINDING_DIGEST,
      action_digest: ACTION_DIGEST,
      supersedes_digest: previous,
      required_parties: [
        { party_id: 'homeowner-1', role: 'customer' },
        { party_id: 'contractor-1', role: 'contractor' },
      ],
    }),
    verifyAmendment: async (_amendment, context) => ({
      valid: true,
      amendment_digest: amendmentDigest,
      previous_binding_digest: previous,
      next_binding_digest: context.expectedNextBindingDigest,
    }),
    verifyState: async (_state, context) => ({
      valid: true,
      agreement_id: context.agreementId,
      binding_digest: context.bindingDigest,
      action_digest: context.actionDigest,
      profile_digest: context.profileDigest,
      state: context.stage,
      revision: 1,
      amendment_digests: context.amendmentDigests,
    }),
  });
  assert.equal(result.valid, true);

  const broken = await verify(pkg, {
    verifyBinding: async (_binding, context) => ({
      valid: true,
      agreement_id: context.expectedAgreementId,
      document_digest: context.expectedDocumentDigest,
      binding_digest: BINDING_DIGEST,
      action_digest: ACTION_DIGEST,
      supersedes_digest: previous,
      required_parties: [
        { party_id: 'homeowner-1', role: 'customer' },
        { party_id: 'contractor-1', role: 'contractor' },
      ],
    }),
    verifyAmendment: async () => ({
      valid: true,
      amendment_digest: amendmentDigest,
      previous_binding_digest: previous,
      next_binding_digest: `sha256:${'88'.repeat(32)}`,
    }),
  });
  assert.equal(broken.valid, false);
  assert.equal(broken.reason, 'amendment_chain_verification_failed');
});

test('indeterminate release remains a distinct verified state', async () => {
  const source = inputs('release_indeterminate');
  const pkg = buildActionEscrowEvidencePackage(source, { now: NOW });
  const result = await verify(pkg);
  assert.equal(result.valid, true);
  assert.equal(result.reason, 'verified');
});

test('early-stage package cannot smuggle funding or release artifacts', async () => {
  const source = inputs('awaiting_acceptance');
  source.documentExecution = null;
  source.agreementAcceptances = [];
  source.releaseApprovals = [];
  source.fundingStatement = null;
  source.milestones = [];
  source.release = null;
  const pkg = buildActionEscrowEvidencePackage(source, { now: NOW });
  assert.equal((await verify(pkg)).valid, true);

  const tamperedSource = inputs('awaiting_acceptance');
  tamperedSource.documentExecution = null;
  tamperedSource.agreementAcceptances = [];
  tamperedSource.releaseApprovals = [];
  tamperedSource.milestones = [];
  tamperedSource.release = null;
  const smuggled = buildActionEscrowEvidencePackage(tamperedSource, { now: NOW });
  const result = await verify(smuggled);
  assert.equal(result.valid, false);
  assert.equal(result.reason, 'unexpected_funding_statement');

  const releaseSmuggling = inputs('awaiting_acceptance');
  releaseSmuggling.documentExecution = null;
  releaseSmuggling.agreementAcceptances = [];
  releaseSmuggling.releaseApprovals = [];
  releaseSmuggling.fundingStatement = null;
  releaseSmuggling.milestones = [];
  const releaseResult = await verify(
    buildActionEscrowEvidencePackage(releaseSmuggling, { now: NOW }),
  );
  assert.equal(releaseResult.valid, false);
  assert.equal(releaseResult.reason, 'release_artifacts_not_allowed_for_stage');
});

test('hostile values and throwing verifiers return typed refusal, never throw', async () => {
  for (const hostile of [null, [], 'package', 1]) {
    const result = await verifyActionEscrowEvidencePackage(hostile, {});
    assert.equal(result.valid, false);
    assert.equal(result.reason, 'malformed_evidence_package');
  }

  const pkg = buildActionEscrowEvidencePackage(inputs(), { now: NOW });
  const result = await verify(pkg, {
    verifyBinding: async () => { throw new Error('secret provider body'); },
  });
  assert.equal(result.valid, false);
  assert.equal(result.reason, 'binding_verification_failed');
  assert.doesNotMatch(JSON.stringify(result), /secret provider body/);
});

test('raw parser refuses duplicate members, invalid Unicode, and oversized input', () => {
  assert.deepEqual(parseActionEscrowEvidencePackage('{"stage":"released","stage":"draft"}'), {
    ok: false,
    reason: 'duplicate object member name',
    value: null,
  });
  assert.equal(parseActionEscrowEvidencePackage('{"x":"\\ud800"}').reason, 'unpaired high surrogate escape');
  assert.equal(
    parseActionEscrowEvidencePackage(`{"x":"${String.fromCharCode(0xd800)}"}`).reason,
    'unpaired Unicode surrogate',
  );
  assert.equal(parseActionEscrowEvidencePackage('{"x":"12345"}', { maxBytes: 4 }).reason, 'package_exceeds_size_limit');
  assert.equal(parseActionEscrowEvidencePackage(JSON.stringify({ version: 'test' })).ok, true);
});
