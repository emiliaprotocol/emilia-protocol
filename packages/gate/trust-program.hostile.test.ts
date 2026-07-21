// SPDX-License-Identifier: Apache-2.0

import test from 'node:test';
import assert from 'node:assert/strict';
import { generateKeyPairSync } from 'node:crypto';

import {
  TRUST_PROGRAM_VERSION,
  createMemoryTrustProgramStore,
  createTrustProgramKernel,
  validateTrustProgram,
  verifyTrustStageReceipt,
} from './trust-program.js';

const NOW = Date.parse('2026-07-21T17:00:00.000Z');
const HASH = (c: string) => `sha256:${c.repeat(64)}`;
const CAID = `caid:1:payment.release.1:jcs-sha256:${'A'.repeat(43)}`;

function requirement(id: string, policy: string) {
  return {
    requirement_id: id,
    evidence_type: 'ep-signoff',
    verifier_profile: 'ep-signoff',
    policy_digest: HASH(policy),
    max_age_sec: 300,
    revocation_required: true,
  };
}

function profile(requirements = [requirement('approver', 'a')]) {
  return {
    '@version': TRUST_PROGRAM_VERSION,
    program_id: 'tp_hostile',
    version: 1,
    root_caid: CAID,
    action_digest: HASH('1'),
    valid_from: new Date(NOW - 1_000).toISOString(),
    expires_at: new Date(NOW + 60_000).toISOString(),
    stages: [{
      stage_id: 'approval',
      depends_on: [],
      rule: { mode: 'all', distinct_subjects: false, distinct_keys: false },
      requirements,
    }],
    execution: {
      depends_on: ['approval'],
      consequence_mode: 'receipt-program',
      capability_template_digest: HASH('2'),
      escrow_profile_digest: null,
    },
  };
}

function evidence(challenge: any, id: string, policy: string) {
  return {
    evidence_id: id,
    binding_digest: challenge.binding_digest,
    policy_digest: HASH(policy),
    valid: true,
    subjects: [`subject_${id}`],
    key_fingerprints: [`key_${id}`],
    issued_at: new Date(NOW - 1_000).toISOString(),
    expires_at: new Date(NOW + 10_000).toISOString(),
    revocation_checked_at: new Date(NOW - 500).toISOString(),
  };
}

function kernel(options: Record<string, any> = {}) {
  const keys = generateKeyPairSync('ed25519');
  const verifier = async ({ artifact }: any) => ({ ...artifact });
  return createTrustProgramKernel({
    program: options.program ?? profile(),
    store: options.store ?? createMemoryTrustProgramStore(),
    verifiers: { 'ep-signoff': options.verifier ?? verifier },
    receiptPrivateKey: options.receiptSigner ? undefined : keys.privateKey,
    receiptVerificationKey: options.receiptVerificationKey
      ?? ((options.allowEphemeralState ?? true) ? undefined : keys.publicKey),
    receiptSigner: options.receiptSigner,
    receiptContext: {
      issuer: 'hostile-test', tenant: 'tenant', environment: 'test', audience: 'test', key_id: 'key',
    },
    allowEphemeralState: options.allowEphemeralState ?? true,
    reconciliationVerifier: options.reconciliationVerifier,
    actionBindingVerifier: options.actionBindingVerifier,
    executionBindingVerifier: options.executionBindingVerifier,
    executionEvidenceRevalidator: options.executionEvidenceRevalidator,
    executionOutcomeVerifier: options.executionOutcomeVerifier,
    now: options.now ?? (() => NOW),
  });
}

async function completeOne(subject: any, instanceId: string) {
  await subject.start({ instanceId });
  const challenge = await subject.challenge({
    instanceId, stageId: 'approval', requirementId: 'approver',
  });
  return subject.admit({
    instanceId,
    stageId: 'approval',
    requirementId: 'approver',
    artifact: evidence(challenge, `ev_${instanceId}`, 'a'),
  });
}

test('profile is closed and refuses extension fields instead of signing ambiguous policy', () => {
  const unknown = { ...profile(), presenter_selected_key: 'attacker' };
  assert.equal(validateTrustProgram(unknown).valid, false);

  const nested = profile();
  nested.stages[0].requirements[0] = {
    ...nested.stages[0].requirements[0],
    trust_roots: ['presenter-selected'],
  } as any;
  assert.equal(validateTrustProgram(nested).reason, 'stage_requirement_invalid');

  const nestedConsequences = profile();
  nestedConsequences.execution.escrow_profile_digest = HASH('9') as any;
  assert.equal(validateTrustProgram(nestedConsequences).reason, 'program_execution_invalid');

  const hiddenExtension = profile();
  Object.defineProperty(hiddenExtension, 'presenter_selected_key', {
    enumerable: false,
    value: 'attacker',
  });
  assert.equal(validateTrustProgram(hiddenExtension).valid, false);
});

test('constructor-owned trust configuration is snapshotted against later mutation', async () => {
  const keys = generateKeyPairSync('ed25519');
  const verifiers: Record<string, any> = {
    'ep-signoff': async ({ artifact }: any) => ({ ...artifact }),
  };
  const receiptContext: any = {
    issuer: 'hostile-test', tenant: 'tenant-a', environment: 'prod',
    audience: 'executor', key_id: 'key-a',
  };
  const subject = createTrustProgramKernel({
    program: profile(), store: createMemoryTrustProgramStore(), verifiers,
    receiptPrivateKey: keys.privateKey, receiptContext,
    allowEphemeralState: true, now: () => NOW,
  });
  verifiers['ep-signoff'] = async () => ({ valid: false, reason: 'mutated' });
  receiptContext.tenant = 'tenant-b';

  const completed = await completeOne(subject, 'pinned_configuration');
  assert.equal(completed.ok, true);
  assert.equal(completed.stage_receipt.issuer.tenant, 'tenant-a');
});

test('valid evidence for a different action or CAID cannot cross the challenge binding', async () => {
  const first = kernel();
  const changed = profile();
  changed.action_digest = HASH('4');
  changed.root_caid = `caid:1:payment.cancel.1:jcs-sha256:${'B'.repeat(43)}`;
  const second = kernel({ program: changed });
  await first.start({ instanceId: 'bind_a' });
  await second.start({ instanceId: 'bind_b' });
  const wrong = await first.challenge({ instanceId: 'bind_a', stageId: 'approval', requirementId: 'approver' });
  const result = await second.admit({
    instanceId: 'bind_b', stageId: 'approval', requirementId: 'approver',
    artifact: evidence(wrong, 'ev_wrong_action', 'a'),
  });
  assert.equal(result.reason, 'evidence_binding_mismatch');
  assert.equal((await second.status('bind_b')).state.revision, 0);
});

test('signer failure cannot admit evidence or advance a stage', async () => {
  const subject = kernel({ receiptSigner: async () => 'malformed' });
  await subject.start({ instanceId: 'signer_failure' });
  const challenge = await subject.challenge({
    instanceId: 'signer_failure', stageId: 'approval', requirementId: 'approver',
  });
  const result = await subject.admit({
    instanceId: 'signer_failure', stageId: 'approval', requirementId: 'approver',
    artifact: evidence(challenge, 'ev_signer_failure', 'a'),
  });
  assert.deepEqual(result, { ok: false, reason: 'stage_receipt_signing_failed' });
  const after = await subject.status('signer_failure');
  assert.equal(after.state.revision, 0);
  assert.equal(after.state.used_evidence_ids.length, 0);
});

test('a signer using a key outside the pinned verification boundary cannot complete a stage', async () => {
  const wrong = generateKeyPairSync('ed25519');
  const subject = kernel({ receiptVerificationKey: wrong.publicKey });
  const result = await completeOne(subject, 'wrong_signer_key');
  assert.equal(result.reason, 'stage_receipt_self_verification_failed');
  assert.equal((await subject.status('wrong_signer_key')).state.revision, 0);
});

test('stage receipts are closed and independently tenant-bound', async () => {
  const keys = generateKeyPairSync('ed25519');
  const subject = createTrustProgramKernel({
    program: profile(),
    store: createMemoryTrustProgramStore(),
    verifiers: { 'ep-signoff': async ({ artifact }: any) => ({ ...artifact }) },
    receiptPrivateKey: keys.privateKey,
    receiptContext: {
      issuer: 'hostile-test', tenant: 'tenant-a', environment: 'prod',
      audience: 'executor', key_id: 'key-a',
    },
    allowEphemeralState: true,
    now: () => NOW,
  });
  const completed = await completeOne(subject, 'receipt_boundary');
  const trustedKeys = { 'key-a': keys.publicKey };
  const expectedIssuer = {
    issuer: 'hostile-test', tenant: 'tenant-a', environment: 'prod',
    audience: 'executor', key_id: 'key-a',
  };
  assert.equal(verifyTrustStageReceipt(completed.stage_receipt, {
    trustedKeys, expectedIssuer,
  }).valid, true);
  assert.equal(verifyTrustStageReceipt(completed.stage_receipt, {
    trustedKeys, expectedIssuer: { ...expectedIssuer, tenant: 'tenant-b' },
  }).reason, 'receipt_expected_issuer_mismatch');
  assert.equal(verifyTrustStageReceipt({ ...completed.stage_receipt, extension: true }, {
    trustedKeys, expectedIssuer,
  }).reason, 'receipt_structure_invalid');
});

test('separation-of-duties stages refuse empty principal projections', async () => {
  const strict = profile();
  strict.stages[0].rule.distinct_subjects = true;
  strict.stages[0].rule.distinct_keys = true;
  const subject = kernel({ program: strict });
  await subject.start({ instanceId: 'empty_principals' });
  const challenge = await subject.challenge({
    instanceId: 'empty_principals', stageId: 'approval', requirementId: 'approver',
  });
  const result = await subject.admit({
    instanceId: 'empty_principals', stageId: 'approval', requirementId: 'approver',
    artifact: { ...evidence(challenge, 'ev_empty', 'a'), subjects: [], key_fingerprints: [] },
  });
  assert.equal(result.reason, 'evidence_principal_set_invalid');
  assert.equal((await subject.status('empty_principals')).state.revision, 0);
});

test('store failure returns a stable refusal and cannot produce false completion', async () => {
  const backing = createMemoryTrustProgramStore();
  const failing = {
    durable: false,
    create: backing.create,
    get: backing.get,
    invalidate: backing.invalidate,
    async compareAndSwap() { throw new Error('database down'); },
  };
  const subject = kernel({ store: failing });
  await subject.start({ instanceId: 'store_failure' });
  const challenge = await subject.challenge({
    instanceId: 'store_failure', stageId: 'approval', requirementId: 'approver',
  });
  const result = await subject.admit({
    instanceId: 'store_failure', stageId: 'approval', requirementId: 'approver',
    artifact: evidence(challenge, 'ev_store_failure', 'a'),
  });
  assert.deepEqual(result, { ok: false, reason: 'store_unavailable' });
  assert.equal((await subject.status('store_failure')).state.revision, 0);
});

test('a store cannot forge a ready state that skips the approval DAG', async () => {
  const backing = createMemoryTrustProgramStore();
  let tamper = false;
  const corrupting = {
    durable: false,
    create: backing.create,
    compareAndSwap: backing.compareAndSwap,
    invalidate: backing.invalidate,
    async get(instanceId: string) {
      const loaded = await backing.get(instanceId);
      if (!tamper || !loaded.ok) return loaded;
      const state: any = structuredClone(loaded.state);
      state.stages.approval.status = 'satisfied';
      state.stages.approval.receipt = { receipt_digest: HASH('f') };
      state.execution.status = 'ready';
      return { ok: true, state };
    },
  };
  const subject = kernel({ store: corrupting });
  await subject.start({ instanceId: 'forged_ready' });
  tamper = true;
  assert.deepEqual(await subject.claimExecution({ instanceId: 'forged_ready' }), {
    ok: false, reason: 'store_state_invalid',
  });
});

test('a store cannot forge a terminal execution without the recorded transition time', async () => {
  const backing = createMemoryTrustProgramStore();
  let tamper = false;
  const corrupting = {
    durable: false,
    create: backing.create,
    compareAndSwap: backing.compareAndSwap,
    invalidate: backing.invalidate,
    async get(instanceId: string) {
      const loaded = await backing.get(instanceId);
      if (!tamper || !loaded.ok) return loaded;
      const state: any = structuredClone(loaded.state);
      state.execution.status = 'executed';
      state.execution.outcome = 'executed';
      state.execution.evidence_digest = HASH('f');
      state.execution.claim_token_digest = null;
      delete state.execution.finalized_at;
      return { ok: true, state };
    },
  };
  const subject = kernel({ store: corrupting });
  await completeOne(subject, 'forged_terminal');
  await subject.claimExecution({ instanceId: 'forged_terminal' });
  tamper = true;
  assert.deepEqual(await subject.status('forged_terminal'), {
    ok: false, reason: 'store_state_invalid',
  });
});

test('two admissions from one revision have one winner and no double transition', async () => {
  const twoSeats = profile([requirement('seat_a', 'a'), requirement('seat_b', 'b')]);
  let release!: () => void;
  const barrier = new Promise<void>((resolve) => { release = resolve; });
  let entered = 0;
  const verifier = async ({ artifact }: any) => {
    entered += 1;
    if (entered === 2) release();
    await barrier;
    return { ...artifact };
  };
  const subject = kernel({ program: twoSeats, verifier });
  await subject.start({ instanceId: 'race' });
  const a = await subject.challenge({ instanceId: 'race', stageId: 'approval', requirementId: 'seat_a' });
  const b = await subject.challenge({ instanceId: 'race', stageId: 'approval', requirementId: 'seat_b' });
  const results = await Promise.all([
    subject.admit({ instanceId: 'race', stageId: 'approval', requirementId: 'seat_a', artifact: evidence(a, 'ev_a', 'a') }),
    subject.admit({ instanceId: 'race', stageId: 'approval', requirementId: 'seat_b', artifact: evidence(b, 'ev_b', 'b') }),
  ]);
  assert.equal(results.filter((entry) => entry.ok).length, 1);
  assert.equal(results.filter((entry) => entry.reason === 'revision_conflict').length, 1);
  assert.equal((await subject.status('race')).state.revision, 1);
});

test('invalidation after provider claim blocks new authority but preserves in-flight reconciliation', async () => {
  const subject = kernel();
  await completeOne(subject, 'inflight');
  const claim = await subject.claimExecution({ instanceId: 'inflight' });
  const snapshot = await subject.status('inflight');
  const invalidated = await subject.invalidate({
    instanceId: 'inflight', expectedRevision: snapshot.state.revision, reason: 'ancestor_revoked',
  });
  assert.equal(invalidated.state.status, 'invalidated');
  assert.equal(invalidated.state.execution.status, 'claimed');
  assert.equal((await subject.claimExecution({ instanceId: 'inflight' })).reason, 'program_instance_invalidated');

  const uncertain = await subject.finalizeExecution({
    instanceId: 'inflight', claimToken: claim.claim_token,
    outcome: 'indeterminate', evidenceDigest: HASH('d'),
  });
  assert.equal(uncertain.state.execution.status, 'indeterminate');
  const reconciled = await subject.reconcileExecution({
    instanceId: 'inflight', outcome: 'proved_no_effect', evidenceDigest: HASH('e'),
  });
  assert.equal(reconciled.state.execution.status, 'proved_no_effect');
});

test('durable mode requires authenticated reconciliation and caller-stable execution identity', async () => {
  const store = createMemoryTrustProgramStore() as any;
  store.durable = true;
  assert.throws(() => kernel({ store, allowEphemeralState: false }), /production trust verifiers required/);

  const subject = kernel({
    store,
    allowEphemeralState: false,
    actionBindingVerifier: async () => true,
    executionBindingVerifier: async () => true,
    executionEvidenceRevalidator: async () => true,
    executionOutcomeVerifier: async () => true,
    reconciliationVerifier: async () => true,
  });
  await completeOne(subject, 'durable');
  assert.equal((await subject.claimExecution({ instanceId: 'durable' })).reason, 'durable_execution_identity_required');
  const claim = await subject.claimExecution({
    instanceId: 'durable', operationId: 'provider_operation_1', claimToken: 'x'.repeat(48),
  });
  assert.equal(claim.ok, true);
  const retry = await subject.claimExecution({
    instanceId: 'durable', operationId: 'provider_operation_1', claimToken: 'x'.repeat(48),
  });
  assert.equal(retry.ok, true);
  assert.equal(retry.idempotent, true);
});

test('execution rejects evidence that becomes future-dated after a clock rollback', async () => {
  let clock = NOW;
  const wideWindow = profile();
  wideWindow.valid_from = new Date(NOW - 60_000).toISOString();
  const subject = kernel({ program: wideWindow, now: () => clock });
  await completeOne(subject, 'clock_rollback');
  clock = NOW - 2_000;
  assert.equal((await subject.claimExecution({ instanceId: 'clock_rollback' })).reason,
    'clock_regression');
});

test('a small clock rollback is refused before a transition can corrupt durable chronology', async () => {
  let clock = NOW;
  const wideWindow = profile();
  wideWindow.valid_from = new Date(NOW - 60_000).toISOString();
  const subject = kernel({ program: wideWindow, now: () => clock });
  await completeOne(subject, 'clock_regression');
  clock = NOW - 500;
  assert.equal((await subject.claimExecution({ instanceId: 'clock_regression' })).reason,
    'clock_regression');
  assert.equal((await subject.status('clock_regression')).state.execution.status, 'ready');
});

test('production action and terminal-outcome verifiers are mandatory decision gates', async () => {
  const rejectedStore = createMemoryTrustProgramStore() as any;
  rejectedStore.durable = true;
  const actionRejected = kernel({
    store: rejectedStore,
    allowEphemeralState: false,
    actionBindingVerifier: async () => false,
    executionBindingVerifier: async () => true,
    executionEvidenceRevalidator: async () => true,
    executionOutcomeVerifier: async () => true,
    reconciliationVerifier: async () => true,
  });
  assert.equal((await actionRejected.start({ instanceId: 'wrong_action', action: {} })).reason, 'action_binding_invalid');
  assert.equal((await actionRejected.status('wrong_action')).reason, 'instance_not_found');

  const outcomeStore = createMemoryTrustProgramStore() as any;
  outcomeStore.durable = true;
  const outcomeRejected = kernel({
    store: outcomeStore,
    allowEphemeralState: false,
    actionBindingVerifier: async () => true,
    executionBindingVerifier: async () => true,
    executionEvidenceRevalidator: async () => true,
    executionOutcomeVerifier: async () => false,
    reconciliationVerifier: async () => true,
  });
  await completeOne(outcomeRejected, 'unproved_outcome');
  const claim = await outcomeRejected.claimExecution({
    instanceId: 'unproved_outcome', operationId: 'provider_operation_2', claimToken: 'y'.repeat(48),
  });
  const refused = await outcomeRejected.finalizeExecution({
    instanceId: 'unproved_outcome', claimToken: claim.claim_token,
    outcome: 'executed', evidenceDigest: HASH('f'), evidence: { self_asserted: true },
  });
  assert.equal(refused.reason, 'execution_evidence_invalid');
  assert.equal((await outcomeRejected.status('unproved_outcome')).state.execution.status, 'claimed');
});
