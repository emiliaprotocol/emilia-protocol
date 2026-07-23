// SPDX-License-Identifier: Apache-2.0
import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import test from 'node:test';

import {
  createRemedyMemoryStore,
  createRemedyProgramKernel,
} from './remedy-program.js';
import {
  expectedRemedyProgramReceiptBindings,
  issueRemedyProgramReceipt,
} from './remedy-program-receipt.js';
import {
  REMEDY_CASE_SET_VERSION,
  createRemedyCaseSetCoordinator,
} from './remedy-case-set.js';

const NOW = Date.parse('2026-07-22T19:00:00.000Z');
const HASH = (char: string) => `sha256:${char.repeat(64)}`;
const CAID = (char: string, action = 'remedy.perform') => (
  `caid:1:${action}.1:jcs-sha256:${char.repeat(43)}`
);

function keyPair() {
  const pair = crypto.generateKeyPairSync('ed25519');
  return {
    ...pair,
    publicKeyB64u: pair.publicKey.export({ type: 'spki', format: 'der' }).toString('base64url'),
  };
}

function verifierKernel() {
  return createRemedyProgramKernel({
    store: createRemedyMemoryStore(),
    now: () => NOW,
    verifyOriginalEffect: (input: any) => ({
      ok: true,
      ...input.original,
      evidence_digest: input.original.terminal_evidence_digest,
    }),
    verifyRevocation: () => ({ ok: false }),
    verifyDispute: (input: any) => ({
      ok: true,
      ...input.dispute,
      original_operation_id: input.expected.original.operation_id,
      original_action_digest: input.expected.original.action_digest,
    }),
    verifyRemedyAuthorization: (input: any) => ({
      ok: true,
      ...input.authorization,
      dispute_id: input.expected.dispute.dispute_id,
      original_operation_id: input.expected.original.operation_id,
      destination_binding_digest: input.expected.destination_binding_digest,
      unit: input.expected.unit,
    }),
    verifyRemedyOutcome: (input: any) => ({
      ok: true,
      ...input.evidence,
      remedy_operation_id: input.expected.remedy_operation_id,
      remedy_action_digest: input.expected.remedy_action_digest,
      destination_binding_digest: input.expected.destination_binding_digest,
      units: input.expected.units,
      unit: input.expected.unit,
      outcome: input.outcome,
    }),
    verifyOriginalReconciliation: () => ({ ok: false }),
  });
}

async function childCase({
  suffix,
  unit,
  units,
  destinationBindingDigest,
  outcome = 'executed',
}: {
  suffix: string;
  unit: string;
  units: number;
  destinationBindingDigest: string;
  outcome?: 'executed' | 'indeterminate';
}) {
  const subject = verifierKernel();
  const instanceId = `child-${suffix}`;
  const original = {
    caid: CAID(suffix.toUpperCase(), 'commerce.purchase'),
    action_digest: HASH(suffix),
    operation_id: `purchase-${suffix}`,
    consequence_mode: 'receipt-program',
    consequence_digest: HASH('a'),
    terminal_evidence_digest: HASH(suffix === '1' ? 'b' : 'c'),
    outcome: 'executed',
    occurred_at: '2026-07-22T18:00:00.000Z',
  };
  const created = await subject.create({
    tenantId: 'tenant-1',
    instanceId,
    environment: 'production',
    audience: 'merchant-1',
    original,
    remedyProfileDigest: HASH('d'),
    destinationBindingDigest,
    maxRemedyUnits: units,
    unit,
    evidence: { fixture: suffix },
  });
  assert.equal(created.ok, true, created.reason ?? 'case-set creation failed');
  assert.ok(created.state);
  assert.equal((await subject.openDispute({
    tenantId: 'tenant-1',
    instanceId,
    dispute: {
      dispute_id: `dispute-${suffix}`,
      evidence_id: `dispute-evidence-${suffix}`,
      evidence_digest: HASH(suffix === '1' ? 'e' : 'f'),
      challenger_id: 'buyer-1',
      requested_units: units,
      opened_at: '2026-07-22T18:10:00.000Z',
    },
  })).ok, true);
  const remedyOperationId = `remedy-operation-${suffix}`;
  const remedyActionDigest = HASH(suffix === '1' ? '7' : '8');
  const remedyCaid = CAID(suffix === '1' ? 'R' : 'S');
  assert.equal((await subject.authorizeRemedy({
    tenantId: 'tenant-1',
    instanceId,
    authorization: {
      evidence_id: `authorization-${suffix}`,
      evidence_digest: HASH(suffix === '1' ? '2' : '3'),
      remedy_operation_id: remedyOperationId,
      remedy_caid: remedyCaid,
      remedy_action_digest: remedyActionDigest,
      consequence_mode: 'receipt-program',
      capability_template_digest: HASH('4'),
      escrow_profile_digest: null,
      units,
      authorized_at: '2026-07-22T18:20:00.000Z',
    },
  })).ok, true);
  assert.equal((await subject.claimRemedy({
    tenantId: 'tenant-1',
    instanceId,
    remedyOperationId,
    claimToken: `worker-${suffix}`,
  })).ok, true);
  const finalized = await subject.finalizeRemedy({
    tenantId: 'tenant-1',
    instanceId,
    remedyOperationId,
    claimToken: `worker-${suffix}`,
    outcome,
    evidence: {
      evidence_id: `outcome-${suffix}-${outcome}`,
      evidence_digest: HASH(suffix === '1' ? '5' : '6'),
      observed_at: '2026-07-22T18:30:00.000Z',
    },
  });
  assert.equal(finalized.ok, true, finalized.reason);
  return {
    subject,
    state: finalized.state,
    instanceId,
    original,
    remedyOperationId,
    remedyActionDigest,
    remedyCaid,
    destinationBindingDigest,
    units,
    unit,
  };
}

function leg(child: Awaited<ReturnType<typeof childCase>>, legId: string) {
  const expected = expectedRemedyProgramReceiptBindings(child.state, child.remedyOperationId);
  return {
    leg_id: legId,
    child_instance_id: child.instanceId,
    remedy_profile_digest: child.state.remedy_profile_digest,
    destination_binding_digest: child.destinationBindingDigest,
    max_remedy_units: child.units,
    unit: child.unit,
    original: child.original,
    remedy: {
      operation_id: child.remedyOperationId,
      caid: child.remedyCaid,
      action_digest: child.remedyActionDigest,
      owner_mode: expected.owner_mode,
      owner_digest: expected.owner_digest,
    },
  };
}

class DurableCaseSetStore {
  readonly durable = true;
  readonly records = new Map<string, any>();

  key(tenantId: string, caseSetId: string) {
    return `${tenantId}\0${caseSetId}`;
  }

  async create(state: any) {
    const key = this.key(state.tenant_id, state.case_set_id);
    if (this.records.has(key)) return { ok: false, reason: 'case_set_exists' };
    this.records.set(key, structuredClone(state));
    return { ok: true, state: structuredClone(state) };
  }

  async get({ tenantId, caseSetId }: any) {
    const value = this.records.get(this.key(tenantId, caseSetId));
    return value
      ? { ok: true, state: structuredClone(value) }
      : { ok: false, reason: 'case_set_not_found' };
  }

  async compareAndSwap({
    tenantId,
    caseSetId,
    expectedRevision,
    ownerTokenDigest,
    state,
  }: any) {
    const key = this.key(tenantId, caseSetId);
    const current = this.records.get(key);
    if (!current) return { ok: false, reason: 'case_set_not_found' };
    if (current.owner_token_digest !== ownerTokenDigest) {
      return { ok: false, reason: 'ownership_conflict' };
    }
    if (current.revision !== expectedRevision) return { ok: false, reason: 'revision_conflict' };
    this.records.set(key, structuredClone(state));
    return { ok: true, state: structuredClone(state) };
  }
}

async function signedChild(child: Awaited<ReturnType<typeof childCase>>, receiptKey: ReturnType<typeof keyPair>) {
  const context = {
    issuer: 'operator:remedy',
    tenant: 'tenant-1',
    environment: 'production',
    audience: 'merchant-1',
    key_id: 'receipt-key-1',
  };
  const receipt = await issueRemedyProgramReceipt({
    state: child.state,
    remedyOperationId: child.remedyOperationId,
  }, {
    context,
    privateKey: receiptKey.privateKey,
    allowEphemeralState: true,
  });
  return { state: child.state, receipt };
}

function coordinator(store: DurableCaseSetStore, receiptKey: ReturnType<typeof keyPair>) {
  return createRemedyCaseSetCoordinator({
    store,
    tenantId: 'tenant-1',
    trustedReceiptKeys: { 'receipt-key-1': receiptKey.publicKeyB64u },
    expectedReceiptIssuer: {
      issuer: 'operator:remedy',
      tenant: 'tenant-1',
      environment: 'production',
      audience: 'merchant-1',
      key_id: 'receipt-key-1',
    },
    now: () => NOW,
  });
}

test('immutable heterogeneous case set completes only with every exact signed child receipt', async () => {
  const receiptKey = keyPair();
  const store = new DurableCaseSetStore();
  const subject = coordinator(store, receiptKey);
  const physical = await childCase({
    suffix: '1', unit: 'item', units: 1, destinationBindingDigest: HASH('8'),
  });
  const monetary = await childCase({
    suffix: '2', unit: 'USD-cent', units: 10_000, destinationBindingDigest: HASH('9'),
  });
  const created = await subject.create({
    tenantId: 'tenant-1',
    caseSetId: 'case-set-1',
    ownerToken: 'coordinator-A',
    legs: [leg(physical, 'physical-return'), leg(monetary, 'monetary-refund')],
  });
  assert.equal(created.ok, true, created.reason ?? 'case-set creation failed');
  assert.ok(created.state);
  assert.equal(created.state.version, REMEDY_CASE_SET_VERSION);
  const manifestDigest = created.state.manifest_digest;
  const physicalSigned = await signedChild(physical, receiptKey);
  const monetarySigned = await signedChild(monetary, receiptKey);

  const missing = await subject.recordChildren({
    tenantId: 'tenant-1',
    caseSetId: 'case-set-1',
    ownerToken: 'coordinator-A',
    expectedRevision: 0,
    children: [{ legId: 'physical-return', ...physicalSigned }],
  });
  assert.equal(missing.ok, false);
  assert.equal(missing.reason, 'case_set_incomplete');

  const wrong = await subject.recordChildren({
    tenantId: 'tenant-1',
    caseSetId: 'case-set-1',
    ownerToken: 'coordinator-A',
    expectedRevision: 0,
    children: [
      { legId: 'physical-return', ...physicalSigned },
      { legId: 'monetary-refund', ...structuredClone(physicalSigned) },
    ],
  });
  assert.equal(wrong.ok, false);
  assert.equal(wrong.reason, 'child_receipt_binding_mismatch');

  const ownerConflict = await subject.recordChildren({
    tenantId: 'tenant-1',
    caseSetId: 'case-set-1',
    ownerToken: 'coordinator-B',
    expectedRevision: 0,
    children: [
      { legId: 'physical-return', ...physicalSigned },
      { legId: 'monetary-refund', ...monetarySigned },
    ],
  });
  assert.equal(ownerConflict.ok, false);
  assert.equal(ownerConflict.reason, 'ownership_conflict');

  const completed = await subject.recordChildren({
    tenantId: 'tenant-1',
    caseSetId: 'case-set-1',
    ownerToken: 'coordinator-A',
    expectedRevision: 0,
    children: [
      { legId: 'physical-return', ...physicalSigned },
      { legId: 'monetary-refund', ...monetarySigned },
    ],
  });
  assert.equal(completed.ok, true, completed.reason ?? 'case-set completion failed');
  assert.ok(completed.state);
  assert.equal(completed.state.status, 'completed');
  assert.equal(completed.state.manifest_digest, manifestDigest);
  assert.deepEqual(completed.state.manifest, created.state.manifest);

  const stale = await subject.recordChildren({
    tenantId: 'tenant-1',
    caseSetId: 'case-set-1',
    ownerToken: 'coordinator-A',
    expectedRevision: 0,
    children: [
      { legId: 'physical-return', ...physicalSigned },
      { legId: 'monetary-refund', ...monetarySigned },
    ],
  });
  assert.equal(stale.ok, true);
  assert.equal(stale.idempotent, true);
});

test('indeterminate child propagates and only a later authenticated child receipt can complete', async () => {
  const receiptKey = keyPair();
  const store = new DurableCaseSetStore();
  const subject = coordinator(store, receiptKey);
  const physical = await childCase({
    suffix: '1', unit: 'item', units: 1, destinationBindingDigest: HASH('8'),
  });
  const monetary = await childCase({
    suffix: '2', unit: 'USD-cent', units: 10_000, destinationBindingDigest: HASH('9'),
    outcome: 'indeterminate',
  });
  assert.equal((await subject.create({
    tenantId: 'tenant-1',
    caseSetId: 'case-set-2',
    ownerToken: 'coordinator-A',
    legs: [leg(physical, 'physical-return'), leg(monetary, 'monetary-refund')],
  })).ok, true);
  const physicalSigned = await signedChild(physical, receiptKey);
  const uncertainSigned = await signedChild(monetary, receiptKey);
  const uncertain = await subject.recordChildren({
    tenantId: 'tenant-1',
    caseSetId: 'case-set-2',
    ownerToken: 'coordinator-A',
    expectedRevision: 0,
    children: [
      { legId: 'physical-return', ...physicalSigned },
      { legId: 'monetary-refund', ...uncertainSigned },
    ],
  });
  assert.equal(uncertain.ok, true, uncertain.reason ?? 'case-set observation failed');
  assert.ok(uncertain.state);
  assert.equal(uncertain.state.status, 'indeterminate');

  const reconciled = await monetary.subject.reconcileRemedy({
    tenantId: 'tenant-1',
    instanceId: monetary.instanceId,
    remedyOperationId: monetary.remedyOperationId,
    outcome: 'executed',
    evidence: {
      evidence_id: 'monetary-reconciliation',
      evidence_digest: HASH('0'),
      observed_at: '2026-07-22T18:40:00.000Z',
    },
  });
  assert.equal(reconciled.ok, true, reconciled.reason);
  const completedMonetary = { ...monetary, state: reconciled.state };
  const completedSigned = await signedChild(completedMonetary, receiptKey);
  const stale = await subject.recordChildren({
    tenantId: 'tenant-1',
    caseSetId: 'case-set-2',
    ownerToken: 'coordinator-A',
    expectedRevision: 0,
    children: [
      { legId: 'physical-return', ...physicalSigned },
      { legId: 'monetary-refund', ...completedSigned },
    ],
  });
  assert.equal(stale.ok, false);
  assert.equal(stale.reason, 'state_transition_conflict');

  const completed = await subject.recordChildren({
    tenantId: 'tenant-1',
    caseSetId: 'case-set-2',
    ownerToken: 'coordinator-A',
    expectedRevision: 1,
    children: [
      { legId: 'physical-return', ...physicalSigned },
      { legId: 'monetary-refund', ...completedSigned },
    ],
  });
  assert.equal(completed.ok, true, completed.reason ?? 'case-set completion failed');
  assert.ok(completed.state);
  assert.equal(completed.state.status, 'completed');
});
