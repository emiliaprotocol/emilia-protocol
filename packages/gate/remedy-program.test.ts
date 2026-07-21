// SPDX-License-Identifier: Apache-2.0
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import test from 'node:test';
import {
  REMEDY_PROGRAM_VERSION,
  createRemedyMemoryStore,
  createRemedyProgramKernel,
} from './remedy-program.js';

const NOW = Date.parse('2026-07-21T18:30:00.000Z');
const HASH = (char: string) => `sha256:${char.repeat(64)}`;

function digest(value: string) {
  return `sha256:${createHash('sha256').update(value).digest('hex')}`;
}

function original(overrides: Record<string, unknown> = {}) {
  return {
    caid: 'caid:1:payments.refund.1:jcs-sha256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA',
    action_digest: HASH('a'),
    operation_id: 'payment-op-1',
    consequence_mode: 'receipt-program',
    consequence_digest: HASH('b'),
    terminal_evidence_digest: HASH('c'),
    outcome: 'executed',
    occurred_at: '2026-07-21T18:00:00.000Z',
    ...overrides,
  };
}

function createInput(overrides: Record<string, unknown> = {}) {
  return {
    instanceId: 'remedy-1',
    tenantId: 'tenant-1',
    environment: 'production',
    audience: 'merchant-1',
    original: original(),
    remedyProfileDigest: HASH('d'),
    destinationBindingDigest: HASH('e'),
    maxRemedyUnits: 10_000,
    unit: 'USD-cent',
    evidence: { kind: 'receipt-program-certificate' },
    ...overrides,
  };
}

function verifiedOriginal(input: any) {
  return {
    ok: true,
    ...input.original,
    evidence_digest: input.original.terminal_evidence_digest,
  };
}

function verifiedRevocation(input: any) {
  return {
    ok: true,
    evidence_id: input.evidence.id,
    evidence_digest: input.evidence.digest,
    target_operation_id: input.expected.original.operation_id,
    action_digest: input.expected.original.action_digest,
    authority_id: 'issuer-1',
    revoked_at: '2026-07-21T18:15:00.000Z',
  };
}

function verifiedDispute(input: any) {
  return {
    ok: true,
    dispute_id: input.dispute.dispute_id,
    evidence_id: input.dispute.evidence_id,
    evidence_digest: input.dispute.evidence_digest,
    challenger_id: input.dispute.challenger_id,
    original_operation_id: input.expected.original.operation_id,
    original_action_digest: input.expected.original.action_digest,
    requested_units: input.dispute.requested_units,
    opened_at: input.dispute.opened_at,
  };
}

function verifiedAuthorization(input: any) {
  return {
    ok: true,
    evidence_id: input.authorization.evidence_id,
    evidence_digest: input.authorization.evidence_digest,
    dispute_id: input.expected.dispute.dispute_id,
    original_operation_id: input.expected.original.operation_id,
    remedy_operation_id: input.authorization.remedy_operation_id,
    remedy_caid: input.authorization.remedy_caid,
    remedy_action_digest: input.authorization.remedy_action_digest,
    destination_binding_digest: input.expected.destination_binding_digest,
    consequence_mode: input.authorization.consequence_mode,
    capability_template_digest: input.authorization.capability_template_digest,
    escrow_profile_digest: input.authorization.escrow_profile_digest,
    units: input.authorization.units,
    unit: input.expected.unit,
    authorized_at: input.authorization.authorized_at,
  };
}

function verifiedOutcome(input: any) {
  return {
    ok: true,
    evidence_id: input.evidence.evidence_id,
    evidence_digest: input.evidence.evidence_digest,
    remedy_operation_id: input.expected.remedy_operation_id,
    remedy_action_digest: input.expected.remedy_action_digest,
    destination_binding_digest: input.expected.destination_binding_digest,
    units: input.expected.units,
    unit: input.expected.unit,
    outcome: input.outcome,
    observed_at: input.evidence.observed_at,
  };
}

function verifiedOriginalReconciliation(input: any) {
  return {
    ok: true,
    evidence_id: input.evidence.evidence_id,
    evidence_digest: input.evidence.evidence_digest,
    original_operation_id: input.expected.original.operation_id,
    original_action_digest: input.expected.original.action_digest,
    terminal_evidence_digest: input.expected.original.terminal_evidence_digest,
    outcome: input.outcome,
    observed_at: input.evidence.observed_at,
  };
}

function kernel(overrides: Record<string, unknown> = {}) {
  return createRemedyProgramKernel({
    store: createRemedyMemoryStore(),
    verifyOriginalEffect: verifiedOriginal,
    verifyRevocation: verifiedRevocation,
    verifyDispute: verifiedDispute,
    verifyRemedyAuthorization: verifiedAuthorization,
    verifyRemedyOutcome: verifiedOutcome,
    verifyOriginalReconciliation: verifiedOriginalReconciliation,
    now: () => NOW,
    ...overrides,
  } as any);
}

async function createAndDispute(subject: any, input = createInput()) {
  const created = await subject.create(input);
  assert.equal(created.ok, true, created.reason);
  const disputed = await subject.openDispute({
    instanceId: input.instanceId,
    tenantId: input.tenantId,
    dispute: {
      dispute_id: 'dispute-1',
      evidence_id: 'dispute-evidence-1',
      evidence_digest: HASH('f'),
      challenger_id: 'buyer-1',
      requested_units: 10_000,
      opened_at: '2026-07-21T18:20:00.000Z',
    },
  });
  assert.equal(disputed.ok, true, disputed.reason);
  return { input, disputed };
}

async function authorize(
  subject: any,
  units: number,
  suffix = '1',
  overrides: Record<string, unknown> = {},
) {
  const caidChar = suffix === '1' ? 'B' : suffix === '2' ? 'C' : 'D';
  return subject.authorizeRemedy({
    instanceId: 'remedy-1',
    tenantId: 'tenant-1',
    authorization: {
      evidence_id: `authorization-${suffix}`,
      evidence_digest: digest(`authorization-${suffix}`),
      remedy_operation_id: `refund-op-${suffix}`,
      remedy_caid: `caid:1:payments.refund.1:jcs-sha256:${caidChar.repeat(43)}`,
      remedy_action_digest: digest(`refund-action-${suffix}`),
      consequence_mode: 'receipt-program',
      capability_template_digest: HASH('6'),
      escrow_profile_digest: null,
      units,
      authorized_at: '2026-07-21T18:25:00.000Z',
      ...overrides,
    },
  });
}

test('creates one exact post-effect remedy case under constructor-pinned verification', async () => {
  const subject = kernel();
  const result = await subject.create(createInput());
  assert.equal(result.ok, true, result.reason);
  assert.equal(result.state.version, REMEDY_PROGRAM_VERSION);
  assert.equal(result.state.status, 'effect_executed');
  assert.equal(result.state.original.operation_id, 'payment-op-1');
  assert.equal(result.state.remaining_units, 10_000);
  assert.equal(Object.isFrozen(result.state), true);
});

test('refuses unauthenticated, substituted, and indeterminate original effects', async () => {
  for (const [verifier, reason] of [
    [() => ({ ok: false, reason: 'bad_signature' }), 'original_effect_invalid'],
    [() => ({ ...verifiedOriginal(createInput()), action_digest: HASH('0') }), 'original_effect_binding_mismatch'],
  ] as const) {
    const result = await kernel({ verifyOriginalEffect: verifier }).create(createInput());
    assert.equal(result.ok, false);
    assert.equal(result.reason, reason);
  }

  const uncertain = await kernel().create(createInput({
    instanceId: 'uncertain-1',
    original: original({ outcome: 'indeterminate' }),
  }));
  assert.equal(uncertain.ok, true);
  assert.equal(uncertain.state.status, 'effect_indeterminate');
  const injected = await kernel().create({
    ...createInput(), verifyOriginalEffect: () => ({ ok: true }),
  } as any);
  assert.equal(injected.ok, false);
  assert.equal(injected.reason, 'create_input_invalid');
});

test('records late revocation without pretending the executed effect was undone', async () => {
  const subject = kernel();
  await subject.create(createInput());
  const result = await subject.recordRevocation({
    instanceId: 'remedy-1',
    tenantId: 'tenant-1',
    evidence: { id: 'revocation-1', digest: HASH('1') },
  });
  assert.equal(result.ok, true, result.reason);
  assert.equal(result.code, 'late_revocation_recorded');
  assert.equal(result.state.status, 'effect_executed');
  assert.equal(result.state.revocation.effect, 'future_authority_only');

  const replay = await subject.recordRevocation({
    instanceId: 'remedy-1',
    tenantId: 'tenant-1',
    evidence: { id: 'revocation-1', digest: HASH('1') },
  });
  assert.equal(replay.ok, true);
  assert.equal(replay.idempotent, true);
});

test('opens only an exact, fresh, one-use dispute against an executed effect', async () => {
  const subject = kernel();
  const { disputed } = await createAndDispute(subject);
  assert.equal(disputed.state.status, 'disputed');
  assert.equal(disputed.state.dispute.requested_units, 10_000);

  const replay = await subject.openDispute({
    instanceId: 'remedy-1',
    tenantId: 'tenant-1',
    dispute: {
      dispute_id: 'dispute-1', evidence_id: 'dispute-evidence-1', evidence_digest: HASH('f'),
      challenger_id: 'buyer-1', requested_units: 10_000,
      opened_at: '2026-07-21T18:20:00.000Z',
    },
  });
  assert.equal(replay.ok, true);
  assert.equal(replay.idempotent, true);
});

test('authorizes a compensating action, never a rewrite of the original action', async () => {
  const subject = kernel();
  await createAndDispute(subject);
  const result = await authorize(subject, 4_000);
  assert.equal(result.ok, true, result.reason);
  assert.equal(result.state.status, 'remedy_authorized');
  assert.notEqual(result.state.active_remedy.remedy_action_digest, result.state.original.action_digest);
  assert.equal(result.state.active_remedy.destination_binding_digest, HASH('e'));
  assert.equal(result.state.active_remedy.consequence_mode, 'receipt-program');
  assert.equal(result.state.active_remedy.capability_template_digest, HASH('6'));
  assert.equal(result.state.active_remedy.escrow_profile_digest, null);

  const other = kernel();
  await createAndDispute(other);
  const over = await authorize(other, 10_001);
  assert.equal(over.ok, false);
  assert.equal(over.reason, 'remedy_limit_exceeded');
});

test('requires exactly one downstream effect-claim owner for every remedy', async () => {
  const subject = kernel();
  await createAndDispute(subject);

  const mixed = await authorize(subject, 1_000, 'mixed', {
    consequence_mode: 'receipt-program',
    capability_template_digest: HASH('6'),
    escrow_profile_digest: HASH('7'),
  });
  assert.equal(mixed.ok, false);
  assert.equal(mixed.reason, 'remedy_owner_invalid');

  const absent = await authorize(subject, 1_000, 'absent', {
    capability_template_digest: null,
    escrow_profile_digest: null,
  });
  assert.equal(absent.ok, false);
  assert.equal(absent.reason, 'remedy_owner_invalid');
});

test('same remedy operation with a modified request is a hard replay conflict', async () => {
  const subject = kernel();
  await createAndDispute(subject);
  assert.equal((await authorize(subject, 4_000)).ok, true);
  const modified = await authorize(subject, 4_001, '1');
  assert.equal(modified.ok, false);
  assert.equal(modified.reason, 'remedy_operation_replayed');
});

test('concurrent over-budget remedy authorizations linearize to one winner', async () => {
  let entered = 0;
  let releaseBarrier!: () => void;
  const barrier = new Promise<void>((resolve) => { releaseBarrier = resolve; });
  const subject = kernel({
    verifyRemedyAuthorization: async (input: any) => {
      entered += 1;
      if (entered === 2) releaseBarrier();
      await barrier;
      return verifiedAuthorization(input);
    },
  });
  await createAndDispute(subject);
  const [left, right] = await Promise.all([
    authorize(subject, 6_000, '1'),
    authorize(subject, 5_000, '2'),
  ]);
  const results = [left, right];
  assert.equal(results.filter((result) => result.ok).length, 1);
  assert.equal(results.filter((result) => result.reason === 'state_transition_conflict').length, 1);
});

test('accepts an indeterminate original for petition intake and requires authenticated reconciliation', async () => {
  const subject = kernel();
  const input = createInput({
    instanceId: 'uncertain-case',
    original: original({ outcome: 'indeterminate' }),
  });
  await createAndDispute(subject, input);
  const result = await subject.authorizeRemedy({
    instanceId: input.instanceId,
    tenantId: input.tenantId,
    authorization: {
      evidence_id: 'authorization-uncertain',
      evidence_digest: digest('authorization-uncertain'),
      remedy_operation_id: 'refund-op-uncertain',
      remedy_caid: 'caid:1:payments.refund.1:jcs-sha256:BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB',
      remedy_action_digest: digest('refund-action-uncertain'),
      consequence_mode: 'receipt-program',
      capability_template_digest: HASH('6'),
      escrow_profile_digest: null,
      units: 1_000,
      authorized_at: '2026-07-21T18:25:00.000Z',
    },
  });
  assert.equal(result.ok, false);
  assert.equal(result.reason, 'original_effect_indeterminate');

  const reconciled = await subject.reconcileOriginalEffect({
    instanceId: input.instanceId,
    tenantId: input.tenantId,
    outcome: 'executed',
    evidence: {
      evidence_id: 'original-reconciliation-1',
      evidence_digest: HASH('9'),
      observed_at: '2026-07-21T18:26:00.000Z',
    },
  });
  assert.equal(reconciled.ok, true, reconciled.reason);
  assert.equal(reconciled.state.original.outcome, 'indeterminate');
  assert.equal(reconciled.state.original_reconciliation.outcome, 'executed');
  assert.equal(reconciled.state.status, 'disputed');

  const authorized = await subject.authorizeRemedy({
    instanceId: input.instanceId,
    tenantId: input.tenantId,
    authorization: {
      evidence_id: 'authorization-after-reconcile',
      evidence_digest: digest('authorization-after-reconcile'),
      remedy_operation_id: 'refund-op-after-reconcile',
      remedy_caid: 'caid:1:payments.refund.1:jcs-sha256:BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB',
      remedy_action_digest: digest('refund-action-after-reconcile'),
      consequence_mode: 'receipt-program',
      capability_template_digest: HASH('6'),
      escrow_profile_digest: null,
      units: 1_000,
      authorized_at: '2026-07-21T18:27:00.000Z',
    },
  });
  assert.equal(authorized.ok, true, authorized.reason);
});

test('proved-no-effect reconciliation closes an indeterminate original without inventing a return', async () => {
  const subject = kernel();
  const input = createInput({
    instanceId: 'no-original-effect',
    original: original({ outcome: 'indeterminate' }),
  });
  await createAndDispute(subject, input);
  const result = await subject.reconcileOriginalEffect({
    instanceId: input.instanceId,
    tenantId: input.tenantId,
    outcome: 'proved_no_effect',
    evidence: {
      evidence_id: 'original-reconciliation-none',
      evidence_digest: HASH('0'),
      observed_at: '2026-07-21T18:26:00.000Z',
    },
  });
  assert.equal(result.ok, true, result.reason);
  assert.equal(result.state.original.outcome, 'indeterminate');
  assert.equal(result.state.original_reconciliation.outcome, 'proved_no_effect');
  assert.equal(result.state.status, 'original_proved_no_effect');
  assert.equal((await subject.authorizeRemedy({
    instanceId: input.instanceId,
    tenantId: input.tenantId,
    authorization: {
      evidence_id: 'should-not-authorize', evidence_digest: HASH('1'),
      remedy_operation_id: 'should-not-run',
      remedy_caid: 'caid:1:payments.refund.1:jcs-sha256:BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB',
      remedy_action_digest: HASH('2'), consequence_mode: 'receipt-program',
      capability_template_digest: HASH('6'), escrow_profile_digest: null,
      units: 1, authorized_at: '2026-07-21T18:27:00.000Z',
    },
  })).reason, 'remedy_case_terminal');
});

test('keys cases by tenant and instance without cross-tenant existence leakage', async () => {
  const subject = kernel();
  const tenantA = createInput({ instanceId: 'shared-id', tenantId: 'tenant-A' });
  const tenantB = createInput({ instanceId: 'shared-id', tenantId: 'tenant-B' });
  assert.equal((await subject.create(tenantA)).ok, true);
  assert.equal((await subject.create(tenantB)).ok, true);

  const crossTenant = await subject.openDispute({
    instanceId: 'shared-id',
    tenantId: 'tenant-C',
    dispute: {
      dispute_id: 'cross-tenant', evidence_id: 'cross-tenant-evidence', evidence_digest: HASH('8'),
      challenger_id: 'buyer-1', requested_units: 1_000,
      opened_at: '2026-07-21T18:20:00.000Z',
    },
  });
  assert.equal(crossTenant.ok, false);
  assert.equal(crossTenant.reason, 'remedy_case_not_found');
});

test('refuses evidence replay across two cases in the same tenant', async () => {
  const subject = kernel();
  const first = createInput({ instanceId: 'global-evidence-a' });
  const second = createInput({
    instanceId: 'global-evidence-b',
    original: original({
      operation_id: 'payment-op-2',
      action_digest: HASH('2'),
      terminal_evidence_digest: HASH('9'),
    }),
  });
  await subject.create(first);
  await subject.create(second);
  const sharedEvidence = {
    dispute_id: 'dispute-global-a', evidence_id: 'shared-evidence', evidence_digest: HASH('8'),
    challenger_id: 'buyer-1', requested_units: 1_000,
    opened_at: '2026-07-21T18:20:00.000Z',
  };
  assert.equal((await subject.openDispute({
    tenantId: first.tenantId, instanceId: first.instanceId, dispute: sharedEvidence,
  })).ok, true);
  const replay = await subject.openDispute({
    tenantId: second.tenantId,
    instanceId: second.instanceId,
    dispute: { ...sharedEvidence, dispute_id: 'dispute-global-b' },
  });
  assert.equal(replay.ok, false);
  assert.equal(replay.reason, 'evidence_replayed');
});

test('refuses one remedy operation, action, or CAID reused across same-tenant cases', async () => {
  const subject = kernel();
  const first = createInput({ instanceId: 'global-operation-a' });
  const second = createInput({
    instanceId: 'global-operation-b',
    original: original({
      operation_id: 'payment-op-3',
      action_digest: HASH('3'),
      terminal_evidence_digest: HASH('7'),
    }),
  });
  await subject.create(first);
  await subject.create(second);
  await subject.openDispute({
    tenantId: first.tenantId, instanceId: first.instanceId,
    dispute: {
      dispute_id: 'dispute-operation-a', evidence_id: 'dispute-operation-evidence-a',
      evidence_digest: HASH('4'), challenger_id: 'buyer-1', requested_units: 1_000,
      opened_at: '2026-07-21T18:20:00.000Z',
    },
  });
  await subject.openDispute({
    tenantId: second.tenantId, instanceId: second.instanceId,
    dispute: {
      dispute_id: 'dispute-operation-b', evidence_id: 'dispute-operation-evidence-b',
      evidence_digest: HASH('5'), challenger_id: 'buyer-1', requested_units: 1_000,
      opened_at: '2026-07-21T18:20:00.000Z',
    },
  });
  const common = {
    remedy_operation_id: 'globally-one-use-remedy',
    remedy_caid: 'caid:1:payments.refund.1:jcs-sha256:EEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEE',
    remedy_action_digest: HASH('6'), consequence_mode: 'receipt-program',
    capability_template_digest: HASH('a'), escrow_profile_digest: null,
    units: 1_000, authorized_at: '2026-07-21T18:25:00.000Z',
  };
  assert.equal((await subject.authorizeRemedy({
    tenantId: first.tenantId, instanceId: first.instanceId,
    authorization: {
      ...common, evidence_id: 'operation-authorization-a', evidence_digest: HASH('b'),
    },
  })).ok, true);
  const replay = await subject.authorizeRemedy({
    tenantId: second.tenantId, instanceId: second.instanceId,
    authorization: {
      ...common, evidence_id: 'operation-authorization-b', evidence_digest: HASH('d'),
    },
  });
  assert.equal(replay.ok, false);
  assert.equal(replay.reason, 'remedy_operation_replayed');
});

test('claims one remedy owner and exact retries are idempotent', async () => {
  const subject = kernel();
  await createAndDispute(subject);
  await authorize(subject, 4_000);
  const first = await subject.claimRemedy({
    instanceId: 'remedy-1', tenantId: 'tenant-1', remedyOperationId: 'refund-op-1', claimToken: 'worker-A',
  });
  assert.equal(first.ok, true, first.reason);
  assert.equal(first.state.status, 'remedy_claimed');

  const retry = await subject.claimRemedy({
    instanceId: 'remedy-1', tenantId: 'tenant-1', remedyOperationId: 'refund-op-1', claimToken: 'worker-A',
  });
  assert.equal(retry.ok, true);
  assert.equal(retry.idempotent, true);
  assert.equal((await subject.claimRemedy({
    instanceId: 'remedy-1', tenantId: 'tenant-1', remedyOperationId: 'refund-op-1', claimToken: 'worker-B',
  })).reason, 'remedy_claim_owned');
});

test('commits partial and full remedies without exceeding the original effect', async () => {
  const subject = kernel();
  await createAndDispute(subject);
  await authorize(subject, 4_000, '1');
  await subject.claimRemedy({ instanceId: 'remedy-1', tenantId: 'tenant-1', remedyOperationId: 'refund-op-1', claimToken: 'A' });
  const partial = await subject.finalizeRemedy({
    instanceId: 'remedy-1', tenantId: 'tenant-1', remedyOperationId: 'refund-op-1', claimToken: 'A', outcome: 'executed',
    evidence: { evidence_id: 'outcome-1', evidence_digest: HASH('2'), observed_at: '2026-07-21T18:27:00.000Z' },
  });
  assert.equal(partial.ok, true, partial.reason);
  assert.equal(partial.state.status, 'partially_remedied');
  assert.equal(partial.state.remedied_units, 4_000);
  assert.equal(partial.state.remaining_units, 6_000);

  const second = await authorize(subject, 6_000, '2');
  assert.equal(second.ok, true, second.reason);
  await subject.claimRemedy({ instanceId: 'remedy-1', tenantId: 'tenant-1', remedyOperationId: 'refund-op-2', claimToken: 'B' });
  const full = await subject.finalizeRemedy({
    instanceId: 'remedy-1', tenantId: 'tenant-1', remedyOperationId: 'refund-op-2', claimToken: 'B', outcome: 'executed',
    evidence: { evidence_id: 'outcome-2', evidence_digest: HASH('3'), observed_at: '2026-07-21T18:29:00.000Z' },
  });
  assert.equal(full.ok, true, full.reason);
  assert.equal(full.state.status, 'remedied');
  assert.equal(full.state.remedied_units, 10_000);
  assert.equal(full.state.remaining_units, 0);
  assert.equal((await authorize(subject, 1, '3')).reason, 'remedy_limit_exhausted');
});

test('indeterminate remedy freezes replay until authenticated reconciliation', async () => {
  const subject = kernel();
  await createAndDispute(subject);
  await authorize(subject, 10_000);
  await subject.claimRemedy({ instanceId: 'remedy-1', tenantId: 'tenant-1', remedyOperationId: 'refund-op-1', claimToken: 'A' });
  const uncertain = await subject.finalizeRemedy({
    instanceId: 'remedy-1', tenantId: 'tenant-1', remedyOperationId: 'refund-op-1', claimToken: 'A', outcome: 'indeterminate',
    evidence: { evidence_id: 'outcome-1', evidence_digest: HASH('2'), observed_at: '2026-07-21T18:27:00.000Z' },
  });
  assert.equal(uncertain.ok, true, uncertain.reason);
  assert.equal(uncertain.state.status, 'remedy_indeterminate');
  assert.equal((await subject.claimRemedy({
    instanceId: 'remedy-1', tenantId: 'tenant-1', remedyOperationId: 'refund-op-1', claimToken: 'A',
  })).reason, 'remedy_indeterminate');

  const reconciled = await subject.reconcileRemedy({
    instanceId: 'remedy-1', tenantId: 'tenant-1', remedyOperationId: 'refund-op-1', outcome: 'executed',
    evidence: { evidence_id: 'reconcile-1', evidence_digest: HASH('4'), observed_at: '2026-07-21T18:29:00.000Z' },
  });
  assert.equal(reconciled.ok, true, reconciled.reason);
  assert.equal(reconciled.state.status, 'remedied');
});

test('proved-no-effect reconciliation reopens the dispute without consuming remedy units', async () => {
  const subject = kernel();
  await createAndDispute(subject);
  await authorize(subject, 10_000);
  await subject.claimRemedy({ instanceId: 'remedy-1', tenantId: 'tenant-1', remedyOperationId: 'refund-op-1', claimToken: 'A' });
  await subject.finalizeRemedy({
    instanceId: 'remedy-1', tenantId: 'tenant-1', remedyOperationId: 'refund-op-1', claimToken: 'A', outcome: 'indeterminate',
    evidence: { evidence_id: 'outcome-1', evidence_digest: HASH('2'), observed_at: '2026-07-21T18:27:00.000Z' },
  });
  const result = await subject.reconcileRemedy({
    instanceId: 'remedy-1', tenantId: 'tenant-1', remedyOperationId: 'refund-op-1', outcome: 'proved_no_effect',
    evidence: { evidence_id: 'reconcile-1', evidence_digest: HASH('4'), observed_at: '2026-07-21T18:29:00.000Z' },
  });
  assert.equal(result.ok, true, result.reason);
  assert.equal(result.state.status, 'disputed');
  assert.equal(result.state.remaining_units, 10_000);
});

test('a no-remedy resolution is separately verified and terminal', async () => {
  const subject = kernel({
    verifyResolution: (input: any) => ({
      ok: true,
      dispute_id: input.expected.dispute.dispute_id,
      evidence_id: input.resolution.evidence_id,
      evidence_digest: input.resolution.evidence_digest,
      outcome: 'no_remedy',
      resolved_at: input.resolution.resolved_at,
    }),
  });
  await createAndDispute(subject);
  const result = await subject.resolveDispute({
    instanceId: 'remedy-1',
    tenantId: 'tenant-1',
    resolution: {
      evidence_id: 'resolution-1', evidence_digest: HASH('5'),
      outcome: 'no_remedy', resolved_at: '2026-07-21T18:29:00.000Z',
    },
  });
  assert.equal(result.ok, true, result.reason);
  assert.equal(result.state.status, 'resolved_no_remedy');
  assert.equal((await authorize(subject, 1)).reason, 'remedy_case_terminal');
});
