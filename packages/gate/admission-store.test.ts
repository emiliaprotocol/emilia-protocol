// SPDX-License-Identifier: Apache-2.0
import test from 'node:test';
import assert from 'node:assert/strict';
import crypto from 'node:crypto';

import {
  ADMISSION_CURRENTNESS_VERSION,
  AdmissionStoreValidationError,
  createAdmissionSnapshot,
  createMemoryAdmissionStore,
  verifyAdmissionJournal,
  type AdmissionCurrentnessObservation,
  type AdmissionSnapshotInput,
} from './admission-store.js';

const NOW = '2026-07-26T12:00:00.000Z';
const EXPIRES = '2026-07-26T12:10:00.000Z';
const INPUT_EXPIRES = '2026-07-26T12:15:00.000Z';
const MONOTONIC_COUNTER_ID = 'webauthn-sign-count:credential-primary';

function d(label: string): `sha256:${string}` {
  return `sha256:${crypto.createHash('sha256').update(label).digest('hex')}`;
}

function caid(label = 'primary'): string {
  return `caid:1:payment.release.1:jcs-sha256:${crypto.createHash('sha256').update(label).digest('base64url')}`;
}

function owner(n: number): string {
  return `admission-owner:v2:${Buffer.alloc(32, n).toString('base64url')}`;
}

function input(role: AdmissionSnapshotInput['inputs'][number]['role'], suffix: string = role) {
  return {
    role,
    artifact_type: `artifact.${role}`,
    subject: `subject:${suffix}`,
    payload_digest: d(`payload:${suffix}`),
    profile_digest: d(`profile:${role}`),
    verifier_id: `verifier:${role}`,
    trust_configuration_digest: d(`trust:${role}`),
    valid_until: INPUT_EXPIRES,
  };
}

function snapshot(overrides: Partial<AdmissionSnapshotInput> = {}): AdmissionSnapshotInput {
  const admissionId = overrides.admission_id ?? 'admission:001';
  const operationId = overrides.operation_id ?? 'operation:001';
  const candidateManifest = d('candidate-manifest');
  const runtimeMeasurement = d('runtime-measurement');
  const qualificationStatement = d('qualification-statement');
  const statusHead = d('status-head');
  const testResult = d('test-result');
  const agentEvidence = d('agent-evidence');
  return {
    tenant_id: 'tenant:alpha',
    admission_id: admissionId,
    operation_id: operationId,
    candidate_manifest_digest: candidateManifest,
    runtime_measurement_digest: runtimeMeasurement,
    candidate_custody: {
      request_construction: 'EXECUTOR_ADAPTER',
      mutation_credential_custody: 'EXECUTOR_ADAPTER',
      enforcement_placement: 'ACTUATOR',
      evidence_digest: d('custody'),
    },
    assignment_digest: d('assignment'),
    qualification_policy_digest: d('qualification-policy'),
    test_result_payload_digests: [testResult],
    agent_evaluation_evidence_payload_digests: [agentEvidence],
    qualification_statement_payload_digest: qualificationStatement,
    qualification_status: {
      authority_id: 'qualification-authority:primary',
      sequence: 7,
      head_payload_digest: statusHead,
      observed_at: NOW,
      expires_at: INPUT_EXPIRES,
    },
    caid: caid(),
    action_digest: d('action'),
    effect_request_digest: d('effect-request'),
    provider: {
      provider_id: 'provider:example',
      account_id: 'account:merchant',
      environment: 'production',
    },
    executor_adapter_digest: d('adapter'),
    idempotency_key: `idempotency:${operationId}`,
    authorization_policy_digest: d('authorization-policy'),
    trust_epoch: 4,
    trust_configuration_digest: d('trust-configuration'),
    configuration_epoch: 9,
    configuration_digest: d('configuration'),
    inputs: [
      input('authorization'), input('test_result'), input('aeb'),
      input('candidate_manifest'), input('local_policy'),
      input('qualification_statement'), input('runtime_measurement'),
      input('qualification_status'), input('agent_evaluation_evidence'),
      input('aec'),
    ],
    resource_reservations: [
      { kind: 'replay', resource_id: 'receipt:once', reservation_id: `replay:${admissionId}`, digest: d('replay-unit'), expires_at: INPUT_EXPIRES },
      { kind: 'budget', resource_id: 'budget:usd', reservation_id: `budget:${admissionId}`, digest: d('budget-unit'), expires_at: INPUT_EXPIRES },
      { kind: 'provider_operation', resource_id: operationId, reservation_id: `provider:${admissionId}`, digest: d(`provider:${operationId}`), expires_at: INPUT_EXPIRES },
      { kind: 'external_lease', resource_id: 'lease:capability', reservation_id: `lease:${admissionId}`, digest: d('lease'), expires_at: INPUT_EXPIRES },
    ],
    admitted_at: NOW,
    expires_at: EXPIRES,
    supersedes_admission_id: null,
    remedy_for: null,
    ...overrides,
  };
}

function withMonotonicCounter(
  value: AdmissionSnapshotInput,
  expectedValue: number,
  nextValue: number,
): AdmissionSnapshotInput {
  value.resource_reservations.push({
    kind: 'monotonic_counter',
    resource_id: MONOTONIC_COUNTER_ID,
    reservation_id: `counter:${value.admission_id}`,
    digest: d(`counter:${expectedValue}:${nextValue}`),
    expires_at: INPUT_EXPIRES,
    expected_value: expectedValue,
    next_value: nextValue,
  });
  return value;
}

function isolateNonCounterResources(
  value: AdmissionSnapshotInput,
  suffix: string,
): AdmissionSnapshotInput {
  value.resource_reservations = value.resource_reservations.map((resource) => ({
    ...resource,
    resource_id: resource.kind === 'monotonic_counter'
      ? resource.resource_id
      : resource.kind === 'provider_operation'
        ? value.operation_id
        : `${resource.resource_id}:${suffix}`,
    reservation_id: `${resource.kind}:${value.admission_id}:${suffix}`,
    digest: d(`${resource.kind}:${suffix}`),
  }));
  return value;
}

function matchingObservation(value: AdmissionSnapshotInput): AdmissionCurrentnessObservation {
  return {
    '@version': ADMISSION_CURRENTNESS_VERSION,
    observed_at: NOW,
    qualification_status_authority_id: value.qualification_status.authority_id,
    qualification_status_sequence: value.qualification_status.sequence,
    qualification_status_head_digest: value.qualification_status.head_payload_digest,
    qualification_status_expires_at: value.qualification_status.expires_at,
    trust_epoch: value.trust_epoch,
    trust_configuration_digest: value.trust_configuration_digest,
    configuration_epoch: value.configuration_epoch,
    configuration_digest: value.configuration_digest,
    runtime_measurement_digest: value.runtime_measurement_digest,
    candidate_match: 'EXACT_MATCH',
    external_leases: value.resource_reservations.filter((resource) => resource.kind === 'external_lease').map((resource) => ({
      resource_id: resource.resource_id,
      digest: resource.digest,
      expires_at: resource.expires_at,
    })),
  };
}

function currentnessOracle() {
  return {
    read: async (current: ReturnType<typeof createAdmissionSnapshot>) =>
      matchingObservation(current.body),
  };
}

test('snapshot is closed, canonical, sorted, immutable and deadline bounded', () => {
  const a = createAdmissionSnapshot(snapshot());
  const b = createAdmissionSnapshot(snapshot({ inputs: [...snapshot().inputs].reverse() }));
  assert.equal(a.snapshot_digest, b.snapshot_digest);
  assert.deepEqual(a.body.inputs.map((entry) => entry.role), [
    'candidate_manifest', 'runtime_measurement', 'test_result',
    'agent_evaluation_evidence', 'qualification_statement',
    'qualification_status', 'aeb', 'aec', 'local_policy', 'authorization',
  ]);
  assert.throws(() => { (a.body as any).caid = caid('attacker'); }, TypeError);
  assert.throws(
    () => createAdmissionSnapshot(snapshot({ expires_at: '2026-07-26T12:20:00.000Z' })),
    (error: any) => error instanceof AdmissionStoreValidationError && error.code === 'expiration_exceeds_evidence',
  );
});

test('snapshot rejects missing, duplicate and byte-invalid profile roles', () => {
  assert.throws(() => createAdmissionSnapshot(snapshot({
    inputs: snapshot().inputs.filter((entry) => entry.role !== 'authorization'),
  })), /authorization is required/);
  assert.throws(() => createAdmissionSnapshot(snapshot({
    inputs: [...snapshot().inputs, input('aeb', 'duplicate')],
  })), /aeb is singleton/);
  assert.throws(() => createAdmissionSnapshot(snapshot({
    caid: `${caid()}=`,
  })), /caid is invalid/);
});

test('reservation permanently fences tenant operation, admission and resources', async () => {
  let ownerIndex = 1;
  const store = createMemoryAdmissionStore({ now: NOW, ownerTokenFactory: () => owner(ownerIndex++) });
  const first = await store.reserve(snapshot());
  assert.equal(first.ok, true);
  assert.deepEqual(await store.reserve(snapshot()), { ok: false, reason: 'admission_exists' });
  assert.deepEqual(await store.reserve(snapshot({ admission_id: 'admission:002' })), { ok: false, reason: 'operation_exists' });
  const conflict = snapshot({ admission_id: 'admission:003', operation_id: 'operation:003' });
  conflict.resource_reservations = conflict.resource_reservations.map((resource) =>
    resource.kind === 'replay' ? { ...resource, resource_id: 'receipt:once' } : resource);
  assert.deepEqual(await store.reserve(conflict), { ok: false, reason: 'resource_conflict' });
  assert.deepEqual(await store.checkInvariants(), { ok: true, violations: [] });
});

test('an expired pre-invocation reservation can be reaped without its lost owner token', async () => {
  let now = Date.parse(NOW);
  const store = createMemoryAdmissionStore({
    now: () => now,
    ownerTokenFactory: () => owner(1),
  });
  const value = snapshot();
  const reserved = await store.reserve(value);
  assert.equal(reserved.ok, true);
  if (!reserved.ok) return;

  assert.deepEqual(await store.reapExpiredReservation({
    tenant_id: value.tenant_id,
    admission_id: value.admission_id,
    expected_revision: 0,
  }), { ok: false, reason: 'state_conflict' });

  now = Date.parse(EXPIRES) + 1;
  const reaped = await store.reapExpiredReservation({
    tenant_id: value.tenant_id,
    admission_id: value.admission_id,
    expected_revision: 0,
  });
  assert.equal(reaped.ok, true);
  if (!reaped.ok) return;
  assert.equal(reaped.record.state, 'EXPIRED');
  assert.equal(reaped.record.execution_right, 'RELEASED');
  assert.equal(reaped.record.provider_attempt, 'NOT_ENTERED');
  assert.equal(reaped.record.refusal_reason, 'abandoned_before_invocation');
  assert.ok(reaped.record.resources.every((resource) => resource.state === 'RELEASED'));
  assert.deepEqual(await store.reapExpiredReservation({
    tenant_id: value.tenant_id,
    admission_id: value.admission_id,
    expected_revision: 0,
  }), { ok: false, reason: 'revision_conflict' });

  const entries = await store.journal({
    tenant_id: value.tenant_id,
    admission_id: value.admission_id,
  });
  assert.equal(entries.at(-1)?.event, 'ABANDONED_BEFORE_INVOCATION');

  const replacement = snapshot({
    admission_id: 'admission:replacement',
    operation_id: 'operation:replacement',
    expires_at: '2026-07-26T12:12:00.000Z',
  });
  assert.equal((await store.reserve(replacement)).ok, true);
  assert.deepEqual(await store.checkInvariants(), { ok: true, violations: [] });
});

test('the expiry reaper cannot touch an invocation that may have entered the provider', async () => {
  let now = Date.parse(NOW);
  const value = snapshot();
  const store = createMemoryAdmissionStore({
    now: () => now,
    ownerTokenFactory: () => owner(1),
    invocationTokenFactory: () => `admission-invocation:v2:${Buffer.alloc(32, 9).toString('base64url')}`,
    currentnessOracle: { read: async () => matchingObservation(value) },
  });
  const reserved = await store.reserve(value);
  assert.equal(reserved.ok, true);
  if (!reserved.ok) return;
  assert.equal((await store.beginInvocation({
    tenant_id: value.tenant_id,
    admission_id: value.admission_id,
    expected_revision: 0,
    owner_token: reserved.owner_token,
  })).ok, true);

  now = Date.parse(EXPIRES) + 1;
  assert.deepEqual(await store.reapExpiredReservation({
    tenant_id: value.tenant_id,
    admission_id: value.admission_id,
    expected_revision: 1,
  }), { ok: false, reason: 'state_conflict' });
});

test('monotonic counter reserve requires an explicitly provisioned trusted head', async () => {
  const value = withMonotonicCounter(snapshot(), 41, 42);
  const missing = createMemoryAdmissionStore({
    now: NOW,
    ownerTokenFactory: () => owner(1),
  });
  assert.deepEqual(await missing.reserve(value), {
    ok: false,
    reason: 'resource_conflict',
  });

  const provisioned = createMemoryAdmissionStore({
    now: NOW,
    ownerTokenFactory: () => owner(2),
    initialMonotonicCounterHeads: [{
      tenant_id: value.tenant_id,
      resource_id: MONOTONIC_COUNTER_ID,
      current_value: 41,
    }],
  });
  assert.equal((await provisioned.reserve(value)).ok, true);
});

test('beginInvocation atomically rechecks currentness then consumes every right before provider entry', async () => {
  const value = snapshot();
  const store = createMemoryAdmissionStore({
    now: NOW,
    ownerTokenFactory: () => owner(1),
    invocationTokenFactory: () => `admission-invocation:v2:${Buffer.alloc(32, 9).toString('base64url')}`,
    currentnessOracle: { read: async () => matchingObservation(value) },
  });
  const reserved = await store.reserve(value);
  assert.equal(reserved.ok, true);
  if (!reserved.ok) return;
  const begun = await store.beginInvocation({ tenant_id: value.tenant_id, admission_id: value.admission_id, expected_revision: 0, owner_token: reserved.owner_token });
  assert.equal(begun.ok, true);
  if (!begun.ok) return;
  assert.equal(begun.record.execution_right, 'CONSUMED');
  assert.equal(begun.record.provider_attempt, 'INVOKING');
  assert.ok(begun.record.resources.every((resource) => resource.state === 'CONSUMED'));
  assert.equal(begun.snapshot.snapshot_digest, reserved.snapshot.snapshot_digest);
  assert.notEqual(begun.record.invocation_token_digest, begun.invocation_token);
  assert.deepEqual(await store.beginInvocation({ tenant_id: value.tenant_id, admission_id: value.admission_id, expected_revision: 1, owner_token: reserved.owner_token }), { ok: false, reason: 'state_conflict' });
});

test('revoked, stale, reconfigured or candidate-mismatched currentness releases before invocation', async () => {
  const value = snapshot();
  const observation = matchingObservation(value);
  observation.qualification_status_sequence += 1;
  const store = createMemoryAdmissionStore({
    now: NOW,
    ownerTokenFactory: () => owner(1),
    currentnessOracle: { read: async () => observation },
  });
  const reserved = await store.reserve(value);
  assert.equal(reserved.ok, true);
  if (!reserved.ok) return;
  assert.deepEqual(await store.beginInvocation({ tenant_id: value.tenant_id, admission_id: value.admission_id, expected_revision: 0, owner_token: reserved.owner_token }), { ok: false, reason: 'currentness_refused' });
  const record = await store.read({ tenant_id: value.tenant_id, admission_id: value.admission_id });
  assert.equal(record?.state, 'RELEASED');
  assert.equal(record?.execution_right, 'RELEASED');
  assert.ok(record?.resources.every((resource) => resource.state === 'RELEASED'));
});

test('beginInvocation refuses a missing oracle or an over-age observation', async () => {
  const value = snapshot();
  const missing = createMemoryAdmissionStore({
    now: NOW,
    ownerTokenFactory: () => owner(1),
  });
  const missingReserved = await missing.reserve(value);
  assert.equal(missingReserved.ok, true);
  if (!missingReserved.ok) return;
  assert.deepEqual(await missing.beginInvocation({
    tenant_id: value.tenant_id,
    admission_id: value.admission_id,
    expected_revision: 0,
    owner_token: missingReserved.owner_token,
  }), { ok: false, reason: 'currentness_refused' });

  const staleObservation = matchingObservation(value);
  staleObservation.observed_at = '2026-07-26T11:59:50.000Z';
  const stale = createMemoryAdmissionStore({
    now: NOW,
    maxCurrentnessAgeMs: 1_000,
    ownerTokenFactory: () => owner(2),
    currentnessOracle: { read: async () => staleObservation },
  });
  const staleReserved = await stale.reserve(snapshot({
    admission_id: 'admission:stale',
    operation_id: 'operation:stale',
    idempotency_key: 'idempotency:operation:stale',
  }));
  assert.equal(staleReserved.ok, true);
  if (!staleReserved.ok) return;
  assert.deepEqual(await stale.beginInvocation({
    tenant_id: staleReserved.snapshot.body.tenant_id,
    admission_id: staleReserved.snapshot.body.admission_id,
    expected_revision: 0,
    owner_token: staleReserved.owner_token,
  }), { ok: false, reason: 'currentness_refused' });
});

test('supersession changes admission only and retains exact operation identity', async () => {
  let n = 1;
  const store = createMemoryAdmissionStore({ now: NOW, ownerTokenFactory: () => owner(n++), currentnessOracle: currentnessOracle() });
  const predecessor = snapshot();
  const reserved = await store.reserve(predecessor);
  assert.equal(reserved.ok, true);
  if (!reserved.ok) return;
  const successor = snapshot({ admission_id: 'admission:002' });
  successor.resource_reservations = successor.resource_reservations.map((resource) => ({ ...resource, reservation_id: `${resource.kind}:admission:002` }));
  const result = await store.supersede({ tenant_id: predecessor.tenant_id, admission_id: predecessor.admission_id, expected_revision: 0, owner_token: reserved.owner_token, successor });
  assert.equal(result.ok, true);
  if (!result.ok) return;
  assert.equal(result.predecessor_record.state, 'SUPERSEDED');
  assert.equal(result.successor_record.operation_id, predecessor.operation_id);
  assert.equal(result.successor_snapshot.body.caid, predecessor.caid);
  assert.equal(result.successor_snapshot.body.action_digest, predecessor.action_digest);
  assert.equal((await store.readByOperation({ tenant_id: predecessor.tenant_id, operation_id: predecessor.operation_id }))?.admission_id, 'admission:002');
  assert.deepEqual(await store.checkInvariants(), { ok: true, violations: [] });
});

test('supersession owner-token failure leaves predecessor, resources, operation head, and counter unchanged', async () => {
  let ownerCall = 0;
  const store = createMemoryAdmissionStore({
    now: NOW,
    ownerTokenFactory: () => {
      ownerCall += 1;
      if (ownerCall === 2) throw new Error('injected successor owner failure');
      return owner(ownerCall);
    },
    initialMonotonicCounterHeads: [{
      tenant_id: 'tenant:alpha',
      resource_id: MONOTONIC_COUNTER_ID,
      current_value: 41,
    }],
  });
  const predecessor = withMonotonicCounter(snapshot(), 41, 42);
  const reserved = await store.reserve(predecessor);
  assert.equal(reserved.ok, true);
  if (!reserved.ok) return;

  const successor = withMonotonicCounter(snapshot({ admission_id: 'admission:002' }), 42, 43);
  successor.resource_reservations = successor.resource_reservations.map((resource) => ({
    ...resource,
    reservation_id: `${resource.kind}:admission:002`,
  }));
  await assert.rejects(() => store.supersede({
    tenant_id: predecessor.tenant_id,
    admission_id: predecessor.admission_id,
    expected_revision: reserved.record.revision,
    owner_token: reserved.owner_token,
    successor,
  }), /injected successor owner failure/);

  assert.deepEqual(await store.read({
    tenant_id: predecessor.tenant_id,
    admission_id: predecessor.admission_id,
  }), reserved.record);
  assert.deepEqual(await store.readByOperation({
    tenant_id: predecessor.tenant_id,
    operation_id: predecessor.operation_id,
  }), reserved.record);
  assert.equal(await store.read({
    tenant_id: successor.tenant_id,
    admission_id: successor.admission_id,
  }), null);

  const resourceConflict = isolateNonCounterResources(snapshot({
    admission_id: 'admission:resource-probe',
    operation_id: 'operation:resource-probe',
    idempotency_key: 'idempotency:operation:resource-probe',
  }), 'resource-probe');
  resourceConflict.resource_reservations[0] = {
    ...resourceConflict.resource_reservations[0],
    resource_id: predecessor.resource_reservations[0].resource_id,
  };
  assert.deepEqual(await store.reserve(resourceConflict), {
    ok: false,
    reason: 'resource_conflict',
  });

  const counterProbe = isolateNonCounterResources(withMonotonicCounter(snapshot({
    admission_id: 'admission:counter-probe',
    operation_id: 'operation:counter-probe',
    idempotency_key: 'idempotency:operation:counter-probe',
  }), 42, 43), 'counter-probe');
  assert.equal((await store.reserve(counterProbe)).ok, true);
  assert.deepEqual(await store.checkInvariants(), { ok: true, violations: [] });
});

test('supersession refuses action/request substitution and every post-INVOKING state', async () => {
  let n = 1;
  const store = createMemoryAdmissionStore({ now: NOW, ownerTokenFactory: () => owner(n++), currentnessOracle: currentnessOracle() });
  const value = snapshot();
  const reserved = await store.reserve(value);
  assert.equal(reserved.ok, true);
  if (!reserved.ok) return;
  assert.deepEqual(await store.supersede({
    tenant_id: value.tenant_id, admission_id: value.admission_id,
    expected_revision: 0, owner_token: reserved.owner_token,
    successor: snapshot({ admission_id: 'admission:bad', caid: caid('different') }),
  }), { ok: false, reason: 'operation_conflict' });
  const begun = await store.beginInvocation({ tenant_id: value.tenant_id, admission_id: value.admission_id, expected_revision: 0, owner_token: reserved.owner_token });
  assert.equal(begun.ok, true);
  assert.deepEqual(await store.supersede({
    tenant_id: value.tenant_id, admission_id: value.admission_id,
    expected_revision: 1, owner_token: reserved.owner_token,
    successor: snapshot({ admission_id: 'admission:late' }),
  }), { ok: false, reason: 'state_conflict' });
});

test('provider commitment and observed effect remain independent, including COMMITTED plus DIVERGED', async () => {
  const value = snapshot();
  const invocationToken = `admission-invocation:v2:${Buffer.alloc(32, 4).toString('base64url')}`;
  const store = createMemoryAdmissionStore({ now: NOW, ownerTokenFactory: () => owner(1), invocationTokenFactory: () => invocationToken, currentnessOracle: currentnessOracle() });
  const reserved = await store.reserve(value);
  assert.equal(reserved.ok, true);
  if (!reserved.ok) return;
  const begun = await store.beginInvocation({ tenant_id: value.tenant_id, admission_id: value.admission_id, expected_revision: 0, owner_token: reserved.owner_token });
  assert.equal(begun.ok, true);
  if (!begun.ok) return;
  const committed = await store.recordProviderOutcome({ tenant_id: value.tenant_id, admission_id: value.admission_id, expected_revision: 1, owner_token: reserved.owner_token, invocation_token: invocationToken, value: 'COMMITTED', evidence_digest: d('provider-commitment'), observed_at: NOW });
  assert.equal(committed.ok, true);
  if (!committed.ok) return;
  const divergent = await store.recordEffectRelation({ tenant_id: value.tenant_id, admission_id: value.admission_id, expected_revision: 2, owner_token: reserved.owner_token, invocation_token: invocationToken, value: 'DIVERGED', evidence_digest: d('effect-evidence'), observed_at: NOW });
  assert.equal(divergent.ok, true);
  if (!divergent.ok) return;
  assert.equal(divergent.record.provider_outcome?.value, 'COMMITTED');
  assert.equal(divergent.record.effect_relation?.value, 'DIVERGED');
  assert.equal(divergent.record.execution_right, 'CONSUMED');
  assert.ok(divergent.record.resources.every((resource) => resource.state === 'CONSUMED'));
});

test('ambiguous post-commit crash becomes INDETERMINATE and cannot blind-retry', async () => {
  const value = snapshot();
  const store = createMemoryAdmissionStore({ now: NOW, ownerTokenFactory: () => owner(1), currentnessOracle: currentnessOracle() });
  const reserved = await store.reserve(value);
  assert.equal(reserved.ok, true);
  if (!reserved.ok) return;
  const begun = await store.beginInvocation({ tenant_id: value.tenant_id, admission_id: value.admission_id, expected_revision: 0, owner_token: reserved.owner_token });
  assert.equal(begun.ok, true);
  const recovered = await store.recoverIndeterminate({ tenant_id: value.tenant_id, admission_id: value.admission_id, owner_token: reserved.owner_token });
  assert.equal(recovered.ok, true);
  if (!recovered.ok) return;
  assert.equal(recovered.record.state, 'INDETERMINATE');
  assert.equal(recovered.record.execution_right, 'CONSUMED');
  assert.ok(recovered.reconciliation_token.startsWith('admission-invocation:v2:'));
  assert.deepEqual(await store.beginInvocation({ tenant_id: value.tenant_id, admission_id: value.admission_id, expected_revision: 2, owner_token: reserved.owner_token }), { ok: false, reason: 'state_conflict' });
});

test('remedy is a separately admitted action with a new operation and CAID', async () => {
  let n = 1;
  const store = createMemoryAdmissionStore({ now: NOW, ownerTokenFactory: () => owner(n++), currentnessOracle: currentnessOracle() });
  const original = snapshot();
  const reserved = await store.reserve(original);
  assert.equal(reserved.ok, true);
  if (!reserved.ok) return;
  const begun = await store.beginInvocation({ tenant_id: original.tenant_id, admission_id: original.admission_id, expected_revision: 0, owner_token: reserved.owner_token });
  assert.equal(begun.ok, true);
  if (!begun.ok) return;
  const remedy = snapshot({ admission_id: 'admission:remedy', operation_id: 'operation:remedy', caid: caid('remedy'), action_digest: d('remedy-action'), effect_request_digest: d('remedy-effect'), idempotency_key: 'idempotency:remedy', remedy_for: { tenant_id: original.tenant_id, admission_id: original.admission_id, operation_id: original.operation_id, snapshot_digest: begun.snapshot.snapshot_digest } });
  remedy.resource_reservations = remedy.resource_reservations.map((resource) => ({ ...resource, resource_id: `${resource.resource_id}:remedy`, reservation_id: `${resource.reservation_id}:remedy`, digest: d(`${resource.digest}:remedy`) }));
  assert.equal((await store.reserve(remedy)).ok, true);
});

test('CAS owner and revision stop stale writers and journal tampering is detectable', async () => {
  const value = snapshot();
  const store = createMemoryAdmissionStore({ now: NOW, ownerTokenFactory: () => owner(1) });
  const reserved = await store.reserve(value);
  assert.equal(reserved.ok, true);
  if (!reserved.ok) return;
  assert.deepEqual(await store.release({ tenant_id: value.tenant_id, admission_id: value.admission_id, expected_revision: 1, owner_token: reserved.owner_token }), { ok: false, reason: 'revision_conflict' });
  assert.deepEqual(await store.release({ tenant_id: value.tenant_id, admission_id: value.admission_id, expected_revision: 0, owner_token: owner(2) }), { ok: false, reason: 'owner_conflict' });
  assert.equal((await store.release({ tenant_id: value.tenant_id, admission_id: value.admission_id, expected_revision: 0, owner_token: reserved.owner_token })).ok, true);
  const journal = await store.journal({ tenant_id: value.tenant_id, admission_id: value.admission_id });
  assert.deepEqual(verifyAdmissionJournal(journal), { ok: true });
  const tampered = structuredClone(journal) as any[];
  tampered[1].event = 'INVOKING';
  assert.equal(verifyAdmissionJournal(tampered).ok, false);
});

test('concurrent reservations linearize to exactly one operation owner', async () => {
  let n = 1;
  const store = createMemoryAdmissionStore({ now: NOW, ownerTokenFactory: () => owner(n++) });
  const results = await Promise.all(Array.from({ length: 20 }, (_, index) => store.reserve(snapshot({ admission_id: `admission:${100 + index}` }))));
  assert.equal(results.filter((result) => result.ok).length, 1);
  assert.equal(results.filter((result) => result.ok === false && result.reason === 'operation_exists').length, 19);
  assert.deepEqual(await store.checkInvariants(), { ok: true, violations: [] });
});
