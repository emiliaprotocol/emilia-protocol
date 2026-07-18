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
    approvals: [
      { party_id: 'homeowner-1', role: 'customer', resolution: { token: 'homeowner-ok' } },
      { party_id: 'contractor-1', role: 'contractor', resolution: { token: 'contractor-ok' } },
    ],
    fundingStatement: { token: 'funded' },
    milestones: [
      { milestone_id: 'rough-in', evidence: { digest: `sha256:${'33'.repeat(32)}` }, resolution: { token: 'accepted' } },
    ],
    release: {
      reservation: { token: 'reserved' },
      provider_request: { token: 'requested' },
      provider_statement: { token: 'released' },
      execution_record: { token: 'recorded' },
    },
    stateRecord: { token: stage },
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
      required_parties: [
        { party_id: 'homeowner-1', role: 'customer' },
        { party_id: 'contractor-1', role: 'contractor' },
      ],
    }),
    verifyState: async (_state, context) => ({
      valid: true,
      agreement_id: context.agreementId,
      binding_digest: context.bindingDigest,
      action_digest: context.actionDigest,
      state: context.stage,
    }),
    verifyApproval: async (resolution, context) => ({
      valid: resolution?.token?.endsWith('-ok') === true,
      authorizes_action: true,
      outcome: 'approved',
      party_id: context.partyId,
      role: context.role,
      binding_digest: context.bindingDigest,
      action_digest: context.actionDigest,
    }),
    verifyFunding: async (_statement, context) => ({
      valid: true,
      agreement_id: context.agreementId,
      binding_digest: context.bindingDigest,
      state: 'funded',
    }),
    verifyMilestone: async (milestone, context) => ({
      valid: true,
      milestone_id: milestone.milestone_id,
      binding_digest: context.bindingDigest,
    }),
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
  source.approvals[0].party_id = 'attacker';
  assert.equal(pkg.binding.payload.immutable, true);
  assert.equal(pkg.approvals[0].party_id, 'homeowner-1');
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
  source.approvals[0].resolution = { token: 'esign-provider-complete' };
  const pkg = buildActionEscrowEvidencePackage(source, { now: NOW });
  const result = await verify(pkg);
  assert.equal(result.valid, false);
  assert.equal(result.reason, 'party_approval_verification_failed');
});

test('missing, duplicate, extra, and wrong-role approvals are refused', async (t) => {
  for (const [name, mutate] of [
    ['missing', (source) => source.approvals.pop()],
    ['duplicate', (source) => { source.approvals[1] = structuredClone(source.approvals[0]); }],
    ['extra', (source) => source.approvals.push({ party_id: 'observer', role: 'observer', resolution: { token: 'observer-ok' } })],
    ['wrong role', (source) => { source.approvals[0].role = 'contractor'; }],
  ]) {
    await t.test(name, async () => {
      const source = inputs();
      mutate(source);
      const result = await verify(buildActionEscrowEvidencePackage(source, { now: NOW }));
      assert.equal(result.valid, false);
      assert.equal(result.reason, 'party_approval_verification_failed');
    });
  }
});

test('binding, state, funding, milestone, and release substitutions each fail closed', async (t) => {
  const cases = [
    ['binding', { verifyBinding: async () => ({ valid: false, reason: 'wrong_document' }) }, 'binding_verification_failed'],
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

test('indeterminate release remains a distinct verified state', async () => {
  const source = inputs('release_indeterminate');
  const pkg = buildActionEscrowEvidencePackage(source, { now: NOW });
  const result = await verify(pkg);
  assert.equal(result.valid, true);
  assert.equal(result.reason, 'verified');
});

test('early-stage package cannot smuggle funding or release artifacts', async () => {
  const source = inputs('awaiting_acceptance');
  source.approvals = [];
  source.fundingStatement = null;
  source.milestones = [];
  source.release = null;
  const pkg = buildActionEscrowEvidencePackage(source, { now: NOW });
  assert.equal((await verify(pkg)).valid, true);

  const tamperedSource = inputs('awaiting_acceptance');
  tamperedSource.approvals = [];
  tamperedSource.milestones = [];
  tamperedSource.release = null;
  const smuggled = buildActionEscrowEvidencePackage(tamperedSource, { now: NOW });
  const result = await verify(smuggled);
  assert.equal(result.valid, false);
  assert.equal(result.reason, 'unexpected_funding_statement');
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
  assert.equal(parseActionEscrowEvidencePackage('{"x":"12345"}', { maxBytes: 4 }).reason, 'package_exceeds_size_limit');
  assert.equal(parseActionEscrowEvidencePackage(JSON.stringify({ version: 'test' })).ok, true);
});
