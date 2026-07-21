// SPDX-License-Identifier: Apache-2.0

import test from 'node:test';
import assert from 'node:assert/strict';
import { generateKeyPairSync } from 'node:crypto';

import {
  TRUST_PROGRAM_VERSION,
  createMemoryTrustProgramStore,
  createTrustProgramKernel,
  trustProgramDigest,
  validateTrustProgram,
  verifyTrustStageReceipt,
} from './trust-program.js';

const NOW = Date.parse('2026-07-21T16:00:00.000Z');
const ROOT_CAID = `caid:1:payment.release.1:jcs-sha256:${'A'.repeat(43)}`;
const ACTION_DIGEST = `sha256:${'a'.repeat(64)}`;
const DIGEST = (char: string) => `sha256:${char.repeat(64)}`;

function requirement(requirementId: string, profile: string, policyChar: string) {
  return {
    requirement_id: requirementId,
    evidence_type: profile,
    verifier_profile: profile,
    policy_digest: DIGEST(policyChar),
    max_age_sec: 900,
    revocation_required: true,
  };
}

function program(overrides: Record<string, any> = {}) {
  return {
    '@version': TRUST_PROGRAM_VERSION,
    program_id: 'tp_treasury_release_1',
    version: 1,
    root_caid: ROOT_CAID,
    action_digest: ACTION_DIGEST,
    valid_from: new Date(NOW - 60_000).toISOString(),
    expires_at: new Date(NOW + 3_600_000).toISOString(),
    stages: [
      {
        stage_id: 'identity',
        depends_on: [],
        rule: { mode: 'all', distinct_subjects: true, distinct_keys: true },
        requirements: [requirement('buyer_handshake', 'ep-handshake', '1')],
      },
      {
        stage_id: 'compliance',
        depends_on: ['identity'],
        rule: { mode: 'any', distinct_subjects: true, distinct_keys: true },
        requirements: [
          requirement('kyc_evidence', 'ep-aec', '2'),
          requirement('regulated_identity', 'external-permit', '3'),
        ],
      },
      {
        stage_id: 'legal',
        depends_on: ['identity'],
        rule: { mode: 'all', distinct_subjects: true, distinct_keys: true },
        requirements: [requirement('counsel_signoff', 'ep-signoff', '4')],
      },
      {
        stage_id: 'finance',
        depends_on: ['compliance', 'legal'],
        rule: {
          mode: 'threshold',
          required: 2,
          distinct_subjects: true,
          distinct_keys: true,
        },
        requirements: [
          requirement('controller', 'ep-quorum', '5'),
          requirement('cfo', 'ep-aec', '6'),
          requirement('director', 'external-permit', '7'),
        ],
      },
    ],
    execution: {
      depends_on: ['finance'],
      consequence_mode: 'receipt-program',
      capability_template_digest: DIGEST('8'),
      escrow_profile_digest: null,
    },
    ...overrides,
  };
}

function verifier() {
  return async ({ artifact }: any) => ({
    valid: artifact?.valid === true,
    reason: artifact?.valid === true ? null : 'artifact_invalid',
    binding_digest: artifact?.binding_digest,
    policy_digest: artifact?.policy_digest,
    subjects: artifact?.subjects ?? [],
    key_fingerprints: artifact?.key_fingerprints ?? [],
    issued_at: artifact?.issued_at,
    expires_at: artifact?.expires_at,
    revocation_checked_at: artifact?.revocation_checked_at,
  });
}

function harness(inputProgram = program()) {
  const receiptKeys = generateKeyPairSync('ed25519');
  const store = createMemoryTrustProgramStore();
  const sharedVerifier = verifier();
  const kernel = createTrustProgramKernel({
    program: inputProgram,
    store,
    verifiers: {
      'ep-handshake': sharedVerifier,
      'ep-quorum': sharedVerifier,
      'ep-aec': sharedVerifier,
      'external-permit': sharedVerifier,
      'ep-signoff': sharedVerifier,
    },
    receiptPrivateKey: receiptKeys.privateKey,
    receiptContext: {
      issuer: 'emilia-test',
      tenant: 'tenant_test',
      environment: 'test',
      audience: 'trust-program-test',
      key_id: 'trust-program-test-key',
    },
    allowEphemeralState: true,
    now: () => NOW,
  });
  return {
    kernel,
    store,
    trustedReceiptKeys: {
      'trust-program-test-key': receiptKeys.publicKey
        .export({ type: 'spki', format: 'der' })
        .toString('base64url'),
    },
  };
}

function artifact(challenge: any, requirementId: string, subject: string, key: string, policyChar: string) {
  return {
    '@version': 'TEST-EVIDENCE-v1',
    evidence_id: `ev_${requirementId}_${subject}`,
    binding_digest: challenge.binding_digest,
    policy_digest: DIGEST(policyChar),
    valid: true,
    subjects: [subject],
    key_fingerprints: [key],
    issued_at: new Date(NOW - 5_000).toISOString(),
    expires_at: new Date(NOW + 60_000).toISOString(),
    revocation_checked_at: new Date(NOW - 1_000).toISOString(),
  };
}

async function admit(
  kernel: any,
  instanceId: string,
  stageId: string,
  requirementId: string,
  subject: string,
  key: string,
  policyChar: string,
) {
  const challenge = await kernel.challenge({
    instanceId,
    stageId,
    requirementId,
  });
  assert.equal(challenge.ok, true);
  return kernel.admit({
    instanceId,
    stageId,
    requirementId,
    artifact: artifact(challenge, requirementId, subject, key, policyChar),
  });
}

test('validates a bounded acyclic program whose every stage contributes to execution', () => {
  const checked = validateTrustProgram(program());
  assert.equal(checked.valid, true);
  assert.equal(checked.digest, trustProgramDigest(program()));

  const cyclic = program();
  cyclic.stages[0].depends_on = ['finance'];
  assert.equal(validateTrustProgram(cyclic).reason, 'program_cycle');

  const disconnected = program();
  disconnected.stages.push({
    stage_id: 'decorative',
    depends_on: [],
    rule: { mode: 'all', distinct_subjects: true, distinct_keys: true },
    requirements: [requirement('unused', 'ep-signoff', 'a')],
  });
  assert.equal(validateTrustProgram(disconnected).reason, 'stage_not_execution_relevant');

  const impossible = program();
  impossible.stages[3].rule.required = 4;
  assert.equal(validateTrustProgram(impossible).reason, 'stage_threshold_invalid');
});

test('starts only root stages and binds every requirement challenge to instance, program, action, stage, and seat', async () => {
  const { kernel } = harness();
  const started = await kernel.start({ instanceId: 'tpi_1' });
  assert.equal(started.ok, true);
  assert.equal(started.state.stages.identity.status, 'collecting');
  assert.equal(started.state.stages.compliance.status, 'locked');
  assert.equal(started.state.execution.status, 'locked');

  const first = await kernel.challenge({
    instanceId: 'tpi_1',
    stageId: 'identity',
    requirementId: 'buyer_handshake',
  });
  assert.equal(first.ok, true);
  assert.equal(first.binding.instance_id, 'tpi_1');
  assert.equal(first.binding.program_digest, kernel.program_digest);
  assert.equal(first.binding.root_caid, ROOT_CAID);
  assert.equal(first.binding.action_digest, ACTION_DIGEST);
  assert.equal(first.binding.stage_id, 'identity');
  assert.equal(first.binding.requirement_id, 'buyer_handshake');

  const other = harness().kernel;
  await other.start({ instanceId: 'tpi_2' });
  const second = await other.challenge({
    instanceId: 'tpi_2',
    stageId: 'identity',
    requirementId: 'buyer_handshake',
  });
  assert.notEqual(first.binding_digest, second.binding_digest);

  const locked = await kernel.challenge({
    instanceId: 'tpi_1',
    stageId: 'finance',
    requirementId: 'cfo',
  });
  assert.deepEqual(locked, { ok: false, reason: 'stage_locked' });
});

test('refuses evidence with wrong binding, policy, freshness, or revocation status without advancing state', async () => {
  const { kernel } = harness();
  await kernel.start({ instanceId: 'tpi_refuse' });
  const challenge = await kernel.challenge({
    instanceId: 'tpi_refuse',
    stageId: 'identity',
    requirementId: 'buyer_handshake',
  });
  const base = artifact(challenge, 'buyer_handshake', 'alice', 'key_alice', '1');

  for (const [mutation, reason] of [
    [{ binding_digest: DIGEST('b') }, 'evidence_binding_mismatch'],
    [{ policy_digest: DIGEST('c') }, 'evidence_policy_mismatch'],
    [{ issued_at: new Date(NOW - 901_000).toISOString() }, 'evidence_stale'],
    [{ revocation_checked_at: null }, 'revocation_check_required'],
  ] as const) {
    const result = await kernel.admit({
      instanceId: 'tpi_refuse',
      stageId: 'identity',
      requirementId: 'buyer_handshake',
      artifact: { ...base, ...mutation, evidence_id: `ev_${reason}` },
    });
    assert.equal(result.reason, reason);
  }
  assert.equal((await kernel.status('tpi_refuse')).state.revision, 0);
});

test('completes stages with signed predecessor-bound receipts and unlocks parallel branches only after their dependencies', async () => {
  const { kernel, trustedReceiptKeys } = harness();
  await kernel.start({ instanceId: 'tpi_flow' });
  const identity = await admit(
    kernel,
    'tpi_flow',
    'identity',
    'buyer_handshake',
    'alice',
    'key_alice',
    '1',
  );
  assert.equal(identity.ok, true);
  assert.equal(identity.stage_completed, true);
  assert.equal(identity.state.stages.compliance.status, 'collecting');
  assert.equal(identity.state.stages.legal.status, 'collecting');
  assert.equal(identity.state.stages.finance.status, 'locked');
  assert.equal(verifyTrustStageReceipt(identity.stage_receipt, {
    trustedKeys: trustedReceiptKeys,
    expected: {
      instance_id: 'tpi_flow',
      program_digest: kernel.program_digest,
      stage_id: 'identity',
      predecessor_receipt_digests: [],
    },
  }).valid, true);

  const compliance = await admit(
    kernel,
    'tpi_flow',
    'compliance',
    'kyc_evidence',
    'kyc-provider',
    'key_kyc',
    '2',
  );
  assert.equal(compliance.stage_completed, true);
  assert.equal(compliance.state.stages.finance.status, 'locked');

  const legal = await admit(
    kernel,
    'tpi_flow',
    'legal',
    'counsel_signoff',
    'counsel',
    'key_counsel',
    '4',
  );
  assert.equal(legal.stage_completed, true);
  assert.equal(legal.state.stages.finance.status, 'collecting');
  assert.deepEqual(
    legal.state.stages.finance.predecessor_receipt_digests,
    [compliance.stage_receipt.receipt_digest, legal.stage_receipt.receipt_digest].sort(),
  );
});

test('heterogeneous threshold stages enforce separation of duties and partial approval grants no execution authority', async () => {
  const { kernel } = harness();
  await kernel.start({ instanceId: 'tpi_threshold' });
  await admit(kernel, 'tpi_threshold', 'identity', 'buyer_handshake', 'alice', 'key_alice', '1');
  await admit(kernel, 'tpi_threshold', 'compliance', 'kyc_evidence', 'kyc', 'key_kyc', '2');
  await admit(kernel, 'tpi_threshold', 'legal', 'counsel_signoff', 'counsel', 'key_counsel', '4');

  const first = await admit(kernel, 'tpi_threshold', 'finance', 'controller', 'controller', 'key_controller', '5');
  assert.equal(first.stage_completed, false);
  assert.equal(first.state.execution.status, 'locked');
  assert.deepEqual(await kernel.claimExecution({ instanceId: 'tpi_threshold' }), {
    ok: false,
    reason: 'execution_locked',
  });

  const duplicateHuman = await admit(kernel, 'tpi_threshold', 'finance', 'cfo', 'controller', 'key_cfo', '6');
  assert.equal(duplicateHuman.reason, 'stage_subject_not_distinct');
  const duplicateKey = await admit(kernel, 'tpi_threshold', 'finance', 'cfo', 'cfo', 'key_controller', '6');
  assert.equal(duplicateKey.reason, 'stage_key_not_distinct');

  const second = await admit(kernel, 'tpi_threshold', 'finance', 'cfo', 'cfo', 'key_cfo', '6');
  assert.equal(second.stage_completed, true);
  assert.equal(second.state.execution.status, 'ready');
});

test('evidence is one-use across seats and verifier failure cannot mutate durable state', async () => {
  const inputProgram = program({
    stages: [{
      stage_id: 'dual',
      depends_on: [],
      rule: { mode: 'all', distinct_subjects: false, distinct_keys: false },
      requirements: [
        requirement('seat_a', 'ep-signoff', 'a'),
        requirement('seat_b', 'ep-signoff', 'b'),
      ],
    }],
    execution: {
      depends_on: ['dual'],
      consequence_mode: 'receipt-program',
      capability_template_digest: DIGEST('8'),
      escrow_profile_digest: null,
    },
  });
  const { kernel } = harness(inputProgram);
  await kernel.start({ instanceId: 'tpi_replay' });
  const a = await kernel.challenge({ instanceId: 'tpi_replay', stageId: 'dual', requirementId: 'seat_a' });
  const acceptedArtifact = artifact(a, 'seat_a', 'alice', 'key_alice', 'a');
  assert.equal((await kernel.admit({
    instanceId: 'tpi_replay', stageId: 'dual', requirementId: 'seat_a', artifact: acceptedArtifact,
  })).ok, true);
  const replay = await kernel.admit({
    instanceId: 'tpi_replay', stageId: 'dual', requirementId: 'seat_b', artifact: acceptedArtifact,
  });
  assert.equal(replay.reason, 'evidence_replayed');
  assert.equal((await kernel.status('tpi_replay')).state.revision, 1);
});

test('execution claim is single-owner; indeterminate finalization freezes replay until authenticated reconciliation', async () => {
  const oneStage = program({
    stages: [{
      stage_id: 'approval',
      depends_on: [],
      rule: { mode: 'all', distinct_subjects: true, distinct_keys: true },
      requirements: [requirement('approver', 'ep-signoff', 'a')],
    }],
    execution: {
      depends_on: ['approval'],
      consequence_mode: 'receipt-program',
      capability_template_digest: DIGEST('8'),
      escrow_profile_digest: null,
    },
  });
  const { kernel } = harness(oneStage);
  await kernel.start({ instanceId: 'tpi_execute' });
  await admit(kernel, 'tpi_execute', 'approval', 'approver', 'alice', 'key_alice', 'a');

  const claim = await kernel.claimExecution({ instanceId: 'tpi_execute' });
  assert.equal(claim.ok, true);
  assert.equal(typeof claim.claim_token, 'string');
  assert.equal((await kernel.claimExecution({ instanceId: 'tpi_execute' })).reason, 'execution_already_claimed');
  assert.equal((await kernel.finalizeExecution({
    instanceId: 'tpi_execute', claimToken: 'wrong', outcome: 'indeterminate', evidenceDigest: DIGEST('d'),
  })).reason, 'execution_claim_mismatch');

  const uncertain = await kernel.finalizeExecution({
    instanceId: 'tpi_execute',
    claimToken: claim.claim_token,
    outcome: 'indeterminate',
    evidenceDigest: DIGEST('d'),
  });
  assert.equal(uncertain.ok, true);
  assert.equal(uncertain.state.execution.status, 'indeterminate');
  assert.equal((await kernel.claimExecution({ instanceId: 'tpi_execute' })).reason, 'execution_indeterminate');

  const reconciled = await kernel.reconcileExecution({
    instanceId: 'tpi_execute',
    outcome: 'executed',
    evidenceDigest: DIGEST('e'),
  });
  assert.equal(reconciled.ok, true);
  assert.equal(reconciled.state.execution.status, 'executed');
  assert.equal((await kernel.reconcileExecution({
    instanceId: 'tpi_execute', outcome: 'refused', evidenceDigest: DIGEST('f'),
  })).reason, 'execution_already_terminal');
});

test('invalidation is terminal and stale concurrent transitions fail closed', async () => {
  const { kernel, store } = harness();
  await kernel.start({ instanceId: 'tpi_invalidated' });
  const snapshot = await kernel.status('tpi_invalidated');
  const invalidated = await kernel.invalidate({
    instanceId: 'tpi_invalidated',
    expectedRevision: snapshot.state.revision,
    reason: 'material_action_amended',
  });
  assert.equal(invalidated.ok, true);
  assert.equal(invalidated.state.status, 'invalidated');
  assert.equal(invalidated.state.stages.identity.status, 'invalidated');

  const challenge = await kernel.challenge({
    instanceId: 'tpi_invalidated', stageId: 'identity', requirementId: 'buyer_handshake',
  });
  assert.equal(challenge.reason, 'program_instance_invalidated');
  const stale = await store.invalidate({
    instanceId: 'tpi_invalidated', expectedRevision: snapshot.state.revision, reason: 'stale', at: NOW,
  });
  assert.equal(stale.reason, 'revision_conflict');
});

test('tampering with a stage receipt or predecessor list is independently detectable', async () => {
  const { kernel, trustedReceiptKeys } = harness();
  await kernel.start({ instanceId: 'tpi_receipt' });
  const completed = await admit(
    kernel, 'tpi_receipt', 'identity', 'buyer_handshake', 'alice', 'key_alice', '1',
  );
  const tampered = structuredClone(completed.stage_receipt);
  tampered.payload.stage_id = 'finance';
  assert.equal(verifyTrustStageReceipt(tampered, { trustedKeys: trustedReceiptKeys }).reason, 'receipt_digest_mismatch');

  const wrongExpected = verifyTrustStageReceipt(completed.stage_receipt, {
    trustedKeys: trustedReceiptKeys,
    expected: { predecessor_receipt_digests: [DIGEST('f')] },
  });
  assert.equal(wrongExpected.reason, 'receipt_expected_binding_mismatch');
});
