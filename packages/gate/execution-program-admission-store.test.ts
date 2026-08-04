// SPDX-License-Identifier: Apache-2.0
import assert from 'node:assert/strict';
import crypto, { generateKeyPairSync } from 'node:crypto';
import test from 'node:test';

import {
  ADMISSION_CURRENTNESS_VERSION,
  EXECUTION_PROGRAM_REPORT_SNAPSHOT_VERSION,
  EXECUTION_PROGRAM_STATUS_VERSION,
  createAdmissionSnapshot,
  createExecutionProgramAdmissionBinding,
  createMemoryAdmissionStore,
  executionProgramReportSnapshotMarker,
  type AdmissionCurrentnessObservation,
  type AdmissionSnapshotInput,
  type CreateMemoryAdmissionStoreOptions,
  type ExecutionProgramActionMatchExpected,
  type ExecutionProgramReserveInput,
  type ExecutionProgramStatusObservation,
  type ExecutionProgramStatusReference,
} from './admission-store.js';
import { signBoundedExecutionProgram } from './bounded-execution-program.js';

const NOW = '2026-07-29T20:00:00.000Z';
const EXPIRES = '2026-07-29T20:30:00.000Z';
const INPUT_EXPIRES = '2026-07-29T20:45:00.000Z';

function d(label: string): `sha256:${string}` {
  return `sha256:${crypto.createHash('sha256').update(label).digest('hex')}`;
}

function caid(label: string): string {
  return `caid:1:devops.infrastructure-change.1:jcs-sha256:${crypto.createHash('sha256').update(label).digest('base64url')}`;
}

function owner(index: number): string {
  return `admission-owner:v2:${Buffer.alloc(32, index).toString('base64url')}`;
}

function keys() {
  const pair = generateKeyPairSync('ed25519');
  const publicKey = pair.publicKey.export({ type: 'spki', format: 'der' }).toString('base64url');
  return {
    signer: {
      issuer_id: 'customer:security',
      key_id: 'key:program-authorizer',
      private_key: pair.privateKey,
    },
    policy: {
      trusted_keys: {
        'key:program-authorizer': {
          issuer_id: 'customer:security',
          public_key: publicKey,
          role: 'program_authorizer' as const,
          status: 'ACTIVE' as const,
        },
      },
    },
    context: (version = 1) => ({
      expected_program_id: 'program:remediation:01',
      expected_tenant_id: 'tenant:alpha',
      expected_authorization_digest: version === 1
        ? d('authorization') : d(`authorization:${version}`),
      expected_audience: 'gate:production:01',
    }),
  };
}

const MATERIAL = keys();

if (false) {
  const removedLegacyField: ExecutionProgramReserveInput = {
    program_digest: d('type-surface'),
    node_id: 'inspect',
    occurrence_id: 'occurrence:type-surface',
    admission: {} as AdmissionSnapshotInput,
    // @ts-expect-error action_match is not a public reserve input field.
    action_match: {
      result: 'MATCH',
      profile_id: 'profile:legacy',
      profile_digest: d('profile:legacy'),
      evidence_payload_digest: d('evidence:legacy'),
    },
  };
  void removedLegacyField;
}

function program(version = 1, predecessor: string | null = null) {
  return {
    program_id: 'program:remediation:01',
    tenant_id: 'tenant:alpha',
    version,
    subject_id: 'agent:operations:01',
    audience: 'gate:production:01',
    objective_digest: d('objective'),
    authorization_digest: version === 1 ? d('authorization') : d(`authorization:${version}`),
    presentation_digest: d('presentation'),
    supersedes_program_digest: predecessor,
    issued_at: '2026-07-29T19:55:00.000Z',
    valid_from: NOW,
    expires_at: '2026-07-29T21:00:00.000Z',
    max_total_occurrences: 4,
    max_concurrent_effects: 2,
    budgets: [
      { budget_id: 'attempts', unit: 'attempt', limit: 2 },
      { budget_id: 'change-risk', unit: 'risk-point', limit: 3 },
    ],
    nodes: [
      {
        node_id: 'inspect',
        action: { mode: 'exact', caid: caid('inspect'), action_digest: d('action:inspect') },
        trust_program_digest: d('trust:inspect'),
        depends_on: [],
        max_occurrences: 1,
        charges: [
          { budget_id: 'attempts', amount: 1 },
          { budget_id: 'change-risk', amount: 1 },
        ],
      },
      {
        node_id: 'remediate',
        action: { mode: 'exact', caid: caid('remediate'), action_digest: d('action:remediate') },
        trust_program_digest: d('trust:remediate'),
        depends_on: [{ node_id: 'inspect', outcomes: ['COMMITTED'] }],
        max_occurrences: 1,
        charges: [
          { budget_id: 'attempts', amount: 1 },
          { budget_id: 'change-risk', amount: 2 },
        ],
      },
    ],
  };
}

function admissionInput(
  node: 'inspect' | 'remediate',
  sequence: number,
): AdmissionSnapshotInput {
  const actionCaid = caid(node);
  const actionDigest = d(`action:${node}`);
  const trustDigest = d(`trust:${node}`);
  const admissionId = `admission:${node}:${sequence}`;
  const operationId = `operation:${node}:${sequence}`;
  const roles: AdmissionSnapshotInput['inputs'] = [
    'candidate_manifest', 'runtime_measurement', 'test_result',
    'agent_evaluation_evidence', 'qualification_statement',
    'qualification_status', 'aeb', 'aec', 'local_policy', 'authorization',
  ].map((role) => ({
    role: role as AdmissionSnapshotInput['inputs'][number]['role'],
    artifact_type: `artifact.${role}`,
    subject: role === 'candidate_manifest' || role === 'aeb'
      ? 'agent:operations:01' : `subject:${role}`,
    payload_digest: role === 'authorization' ? d('authorization') : d(`payload:${role}:${sequence}`),
    profile_digest: d(`profile:${role}`),
    verifier_id: `verifier:${role}`,
    trust_configuration_digest: d(`trust-config:${role}`),
    valid_until: INPUT_EXPIRES,
  }));
  return {
    tenant_id: 'tenant:alpha',
    admission_id: admissionId,
    operation_id: operationId,
    candidate_manifest_digest: d(`candidate:${sequence}`),
    runtime_measurement_digest: d(`runtime:${sequence}`),
    candidate_custody: {
      request_construction: 'GATE',
      mutation_credential_custody: 'GATE',
      enforcement_placement: 'ACTUATOR',
      evidence_digest: d(`custody:${sequence}`),
    },
    assignment_digest: d(`assignment:${sequence}`),
    qualification_policy_digest: d(`qualification-policy:${sequence}`),
    test_result_payload_digests: [d(`payload:test_result:${sequence}`)],
    agent_evaluation_evidence_payload_digests: [d(`payload:agent_evaluation_evidence:${sequence}`)],
    qualification_statement_payload_digest: d(`payload:qualification_statement:${sequence}`),
    qualification_status: {
      authority_id: 'qualification-authority:primary',
      sequence,
      head_payload_digest: d(`status:${sequence}`),
      observed_at: NOW,
      expires_at: INPUT_EXPIRES,
    },
    caid: actionCaid,
    action_digest: actionDigest,
    effect_request_digest: d(`effect:${node}:${sequence}`),
    provider: {
      provider_id: 'provider:example',
      account_id: 'account:production',
      environment: 'production',
    },
    executor_adapter_digest: d('executor-adapter'),
    idempotency_key: `idempotency:${operationId}`,
    authorization_policy_digest: trustDigest,
    trust_epoch: 1,
    trust_configuration_digest: d('trust-configuration'),
    configuration_epoch: 1,
    configuration_digest: d('configuration'),
    inputs: roles,
    resource_reservations: [
      { kind: 'replay', resource_id: `receipt:${sequence}`, reservation_id: `replay:${admissionId}`, digest: d(`replay:${sequence}`), expires_at: INPUT_EXPIRES },
      { kind: 'provider_operation', resource_id: operationId, reservation_id: `provider:${admissionId}`, digest: d(`provider:${sequence}`), expires_at: INPUT_EXPIRES },
    ],
    admitted_at: NOW,
    expires_at: EXPIRES,
    supersedes_admission_id: null,
    remedy_for: null,
  };
}

function observation(value: AdmissionSnapshotInput): AdmissionCurrentnessObservation {
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
    external_leases: [],
  };
}

function programStatusObservation(
  reference: ExecutionProgramStatusReference,
  status: 'ACTIVE' | 'SUSPENDED' | 'REVOKED',
  sequence: number,
  observedAt: string,
  expiresAt: string,
): ExecutionProgramStatusObservation {
  return {
    '@version': EXECUTION_PROGRAM_STATUS_VERSION,
    ...reference,
    status,
    sequence,
    observed_at: observedAt,
    expires_at: expiresAt,
  };
}

function store(overrides: Partial<CreateMemoryAdmissionStoreOptions> = {}) {
  let ownerIndex = 1;
  const source = overrides.now ?? NOW;
  const storeNow = () => {
    const value = typeof source === 'function' ? source() : source;
    if (value instanceof Date) return value.getTime();
    if (typeof value === 'string') return Date.parse(value);
    return value;
  };
  return createMemoryAdmissionStore({
    now: NOW,
    ownerTokenFactory: () => owner(ownerIndex++),
    invocationTokenFactory: () => `admission-invocation:v2:${crypto.randomBytes(32).toString('base64url')}`,
    currentnessOracle: { read: async (snapshot) => observation(snapshot.body) },
    executionProgramVerificationPolicy: MATERIAL.policy,
    executionProgramStatusOracle: {
      read: async (reference) => {
        const observedAt = storeNow();
        return programStatusObservation(
          reference,
          'ACTIVE',
          observedAt,
          new Date(observedAt).toISOString(),
          new Date(observedAt + 5_400_000).toISOString(),
        );
      },
    },
    ...overrides,
  });
}

async function register(reference = store()) {
  const artifact = signBoundedExecutionProgram(program(), MATERIAL.signer);
  const registered = await reference.registerExecutionProgram(artifact, MATERIAL.context());
  assert.equal(registered.ok, true);
  if (!registered.ok) throw new Error('program registration failed');
  return { store: reference, material: MATERIAL, artifact, registered };
}

test('program-linked admissions cannot bypass the program-aware begin or release paths', async () => {
  const fixture = await register();
  const value = admissionInput('inspect', 1);
  assert.deepEqual(await fixture.store.reserve(value), {
    ok: false,
    reason: 'program_required',
  });
  const reserved = await fixture.store.reserveExecutionProgramAdmission({
    program_digest: fixture.registered.program.program_digest,
    node_id: 'inspect',
    occurrence_id: 'occurrence:inspect:01',
    admission: value,
  });
  assert.equal(reserved.ok, true);
  if (!reserved.ok) return;
  const cas = {
    tenant_id: value.tenant_id,
    admission_id: value.admission_id,
    expected_revision: 0,
    owner_token: reserved.owner_token,
  };
  assert.deepEqual(await fixture.store.beginInvocation(cas), { ok: false, reason: 'program_required' });
  assert.deepEqual(await fixture.store.release(cas), { ok: false, reason: 'program_required' });
  assert.equal(
    reserved.snapshot.body.resource_reservations.filter(
      (resource) => resource.kind === 'execution_program',
    ).length,
    1,
  );
  const begun = await fixture.store.beginExecutionProgramInvocation(cas);
  assert.equal(begun.ok, true);
});

test('program-linked provider entry accepts a token durably prepared before atomic consumption', async () => {
  const fixture = await register();
  const value = admissionInput('inspect', 301);
  const reserved = await fixture.store.reserveExecutionProgramAdmission({
    program_digest: fixture.registered.program.program_digest,
    node_id: 'inspect',
    occurrence_id: 'occurrence:inspect:prepared-token',
    admission: value,
  });
  assert.equal(reserved.ok, true);
  if (!reserved.ok) return;
  const invocationToken = `admission-invocation:v2:${Buffer.alloc(32, 31).toString('base64url')}`;
  const begun = await fixture.store.beginExecutionProgramInvocationWithPreparedToken({
    tenant_id: value.tenant_id,
    admission_id: value.admission_id,
    expected_revision: reserved.record.revision,
    owner_token: reserved.owner_token,
    invocation_token: invocationToken,
  });
  assert.equal(begun.ok, true);
  if (!begun.ok) return;
  assert.equal(begun.invocation_token, invocationToken);
  assert.equal(begun.record.state, 'INVOKING');
  assert.deepEqual(await fixture.store.checkInvariants(), { ok: true, violations: [] });
});

test('a terminal predecessor unlocks its dependent node and consumes budgets at provider entry', async () => {
  const fixture = await register();
  const inspect = admissionInput('inspect', 1);
  const first = await fixture.store.reserveExecutionProgramAdmission({
    program_digest: fixture.registered.program.program_digest,
    node_id: 'inspect', occurrence_id: 'occurrence:inspect:01', admission: inspect,
  });
  assert.equal(first.ok, true);
  if (!first.ok) return;
  assert.deepEqual(await fixture.store.reserveExecutionProgramAdmission({
    program_digest: fixture.registered.program.program_digest,
    node_id: 'remediate', occurrence_id: 'occurrence:remediate:01', admission: admissionInput('remediate', 2),
  }), { ok: false, reason: 'program_node_unreachable' });
  const begun = await fixture.store.beginExecutionProgramInvocation({
    tenant_id: inspect.tenant_id, admission_id: inspect.admission_id,
    expected_revision: 0, owner_token: first.owner_token,
  });
  assert.equal(begun.ok, true);
  if (!begun.ok) return;
  const committed = await fixture.store.recordProviderOutcome({
    tenant_id: inspect.tenant_id, admission_id: inspect.admission_id,
    expected_revision: 1, owner_token: first.owner_token,
    invocation_token: begun.invocation_token,
    value: 'COMMITTED', evidence_digest: d('provider:committed'), observed_at: NOW,
  });
  assert.equal(committed.ok, true);
  const second = await fixture.store.reserveExecutionProgramAdmission({
    program_digest: fixture.registered.program.program_digest,
    node_id: 'remediate', occurrence_id: 'occurrence:remediate:01', admission: admissionInput('remediate', 2),
  });
  assert.equal(second.ok, true);
  const state = await fixture.store.readExecutionProgram({
    tenant_id: 'tenant:alpha', program_digest: fixture.registered.program.program_digest,
  });
  assert.deepEqual(state?.budgets, [
    { budget_id: 'attempts', unit: 'attempt', limit: 2, reserved: 1, consumed: 1 },
    { budget_id: 'change-risk', unit: 'risk-point', limit: 3, reserved: 2, consumed: 1 },
  ]);
});

test('INDETERMINATE consumes the attempt but never unlocks a dependent node', async () => {
  const fixture = await register();
  const inspect = admissionInput('inspect', 1);
  const reserved = await fixture.store.reserveExecutionProgramAdmission({
    program_digest: fixture.registered.program.program_digest,
    node_id: 'inspect', occurrence_id: 'occurrence:inspect:01', admission: inspect,
  });
  assert.equal(reserved.ok, true);
  if (!reserved.ok) return;
  const begun = await fixture.store.beginExecutionProgramInvocation({
    tenant_id: inspect.tenant_id, admission_id: inspect.admission_id,
    expected_revision: 0, owner_token: reserved.owner_token,
  });
  assert.equal(begun.ok, true);
  if (!begun.ok) return;
  const recovered = await fixture.store.recoverIndeterminate({
    tenant_id: inspect.tenant_id, admission_id: inspect.admission_id,
    owner_token: reserved.owner_token,
  });
  assert.equal(recovered.ok, true);
  assert.deepEqual(await fixture.store.reserveExecutionProgramAdmission({
    program_digest: fixture.registered.program.program_digest,
    node_id: 'remediate', occurrence_id: 'occurrence:remediate:01', admission: admissionInput('remediate', 2),
  }), { ok: false, reason: 'program_node_unreachable' });
  const state = await fixture.store.readExecutionProgram({
    tenant_id: 'tenant:alpha', program_digest: fixture.registered.program.program_digest,
  });
  assert.equal(state?.budgets[0].consumed, 1);
  assert.equal(state?.budgets[0].reserved, 0);
});

test('the signed concurrent-effect ceiling blocks provider entry until an open effect closes', async () => {
  const reference = store();
  const source = program();
  source.max_concurrent_effects = 1;
  source.max_total_occurrences = 2;
  source.nodes = [source.nodes[0]];
  source.nodes[0].max_occurrences = 2;
  source.budgets = source.budgets.map((entry) => ({ ...entry, limit: 2 }));
  const artifact = signBoundedExecutionProgram(source, MATERIAL.signer);
  const registered = await reference.registerExecutionProgram(artifact, MATERIAL.context());
  assert.equal(registered.ok, true);
  if (!registered.ok) return;

  const firstInput = admissionInput('inspect', 201);
  const secondInput = admissionInput('inspect', 202);
  const first = await reference.reserveExecutionProgramAdmission({
    program_digest: registered.program.program_digest,
    node_id: 'inspect',
    occurrence_id: 'occurrence:concurrency:1',
    admission: firstInput,
  });
  const second = await reference.reserveExecutionProgramAdmission({
    program_digest: registered.program.program_digest,
    node_id: 'inspect',
    occurrence_id: 'occurrence:concurrency:2',
    admission: secondInput,
  });
  assert.equal(first.ok, true);
  assert.equal(second.ok, true);
  if (!first.ok || !second.ok) return;

  const firstBegun = await reference.beginExecutionProgramInvocation({
    tenant_id: firstInput.tenant_id,
    admission_id: firstInput.admission_id,
    expected_revision: 0,
    owner_token: first.owner_token,
  });
  assert.equal(firstBegun.ok, true);
  if (!firstBegun.ok) return;
  assert.deepEqual(await reference.beginExecutionProgramInvocation({
    tenant_id: secondInput.tenant_id,
    admission_id: secondInput.admission_id,
    expected_revision: 0,
    owner_token: second.owner_token,
  }), { ok: false, reason: 'program_concurrency_exhausted' });

  assert.equal((await reference.recordProviderOutcome({
    tenant_id: firstInput.tenant_id,
    admission_id: firstInput.admission_id,
    expected_revision: 1,
    owner_token: first.owner_token,
    invocation_token: firstBegun.invocation_token,
    value: 'COMMITTED',
    evidence_digest: d('provider:concurrency:1'),
    observed_at: NOW,
  })).ok, true);
  assert.equal((await reference.beginExecutionProgramInvocation({
    tenant_id: secondInput.tenant_id,
    admission_id: secondInput.admission_id,
    expected_revision: 0,
    owner_token: second.owner_token,
  })).ok, true);
  assert.deepEqual(await reference.checkInvariants(), { ok: true, violations: [] });
});

test('release before invocation restores occurrence and budget reservations', async () => {
  const fixture = await register();
  const value = admissionInput('inspect', 1);
  const first = await fixture.store.reserveExecutionProgramAdmission({
    program_digest: fixture.registered.program.program_digest,
    node_id: 'inspect', occurrence_id: 'occurrence:inspect:01', admission: value,
  });
  assert.equal(first.ok, true);
  if (!first.ok) return;
  const released = await fixture.store.releaseExecutionProgramAdmission({
    tenant_id: value.tenant_id, admission_id: value.admission_id,
    expected_revision: 0, owner_token: first.owner_token,
  });
  assert.equal(released.ok, true);
  const state = await fixture.store.readExecutionProgram({
    tenant_id: 'tenant:alpha', program_digest: fixture.registered.program.program_digest,
  });
  assert.ok(state?.budgets.every((entry) => entry.reserved === 0 && entry.consumed === 0));
  const replacement = admissionInput('inspect', 9);
  const replacementReserved = await fixture.store.reserveExecutionProgramAdmission({
    program_digest: fixture.registered.program.program_digest,
    node_id: 'inspect', occurrence_id: 'occurrence:inspect:02', admission: replacement,
  });
  assert.equal(replacementReserved.ok, true);
  const snapshot = await fixture.store.readExecutionProgramReportSnapshot({
    tenant_id: 'tenant:alpha',
    program_digest: fixture.registered.program.program_digest,
  });
  assert.ok(snapshot);
  assert.equal(snapshot['@version'], EXECUTION_PROGRAM_REPORT_SNAPSHOT_VERSION);
  assert.equal(snapshot.runtime_state.total_occurrences, 2);
  assert.deepEqual(snapshot.occurrences.map(({ occurrence_id, state }) => ({
    occurrence_id, state,
  })), [
    { occurrence_id: 'occurrence:inspect:01', state: 'RELEASED' },
    { occurrence_id: 'occurrence:inspect:02', state: 'RESERVED' },
  ]);
  const { snapshot_marker: marker, ...body } = snapshot;
  assert.equal(marker, executionProgramReportSnapshotMarker(body));
  assert.match(marker, /^sha256:[0-9a-f]{64}$/);
  assert.deepEqual(await fixture.store.readExecutionProgramReportSnapshot({
    tenant_id: 'tenant:alpha',
    program_digest: fixture.registered.program.program_digest,
  }), snapshot);
  assert.equal(Object.isFrozen(snapshot), true);
  assert.equal(await fixture.store.readExecutionProgramReportSnapshot({
    tenant_id: 'tenant:other',
    program_digest: fixture.registered.program.program_digest,
  }), null);
});

test('execution-program resource IDs hash structured tuples without aliases or length overflow', () => {
  const base = {
    tenant_id: 'tenant+alpha',
    program_digest: d('resource-program'),
    expires_at: EXPIRES,
  };
  const left = createExecutionProgramAdmissionBinding({
    ...base,
    node_id: 'node:a',
    occurrence_id: 'b:c',
  });
  const right = createExecutionProgramAdmissionBinding({
    ...base,
    node_id: 'node:a:b',
    occurrence_id: 'c',
  });
  assert.notEqual(left.resource_id, right.resource_id);
  assert.notEqual(left.reservation_id, right.reservation_id);

  const maximumIdentifier = `x${'a'.repeat(511)}`;
  const seen = new Set<string>();
  for (let index = 0; index < 128; index += 1) {
    const binding = createExecutionProgramAdmissionBinding({
      ...base,
      node_id: index === 0 ? maximumIdentifier : `node+${index}`,
      occurrence_id: index === 1 ? maximumIdentifier : `occurrence+${index}`,
    });
    assert.match(binding.resource_id, /^[A-Za-z0-9][A-Za-z0-9:_.@/+\-]{0,511}$/);
    assert.match(binding.reservation_id, /^[A-Za-z0-9][A-Za-z0-9:_.@/+\-]{0,511}$/);
    assert.ok(Buffer.byteLength(binding.resource_id, 'utf8') <= 512);
    assert.ok(Buffer.byteLength(binding.reservation_id, 'utf8') <= 512);
    assert.equal(seen.has(binding.resource_id), false);
    seen.add(binding.resource_id);
  }
});

test('registration uses only the store clock and active program-authorizer pins', async () => {
  const reference = store();
  const artifact = signBoundedExecutionProgram(program(), MATERIAL.signer);
  const attacker = keys();
  attacker.signer.issuer_id = 'customer:attacker';
  attacker.signer.key_id = 'key:attacker-program-authorizer';
  assert.deepEqual(await reference.registerExecutionProgram(artifact, {
    ...MATERIAL.context(),
    trusted_keys: attacker.policy.trusted_keys,
    now: '2026-07-29T19:59:00.000Z',
  } as any), { ok: false, reason: 'context_binding_required' });

  const attackerArtifact = signBoundedExecutionProgram(program(), attacker.signer);
  assert.deepEqual(
    await reference.registerExecutionProgram(attackerArtifact, MATERIAL.context()),
    { ok: false, reason: 'program_issuer_untrusted' },
  );

  const inactive = store({
    executionProgramVerificationPolicy: {
      trusted_keys: {
        'key:program-authorizer': {
          ...MATERIAL.policy.trusted_keys['key:program-authorizer'],
          status: 'SUSPENDED',
        },
      },
    },
  });
  assert.deepEqual(
    await inactive.registerExecutionProgram(artifact, MATERIAL.context()),
    { ok: false, reason: 'program_issuer_untrusted' },
  );

  const late = store({ now: '2026-07-29T21:00:00.000Z' });
  assert.deepEqual(
    await late.registerExecutionProgram(artifact, MATERIAL.context()),
    { ok: false, reason: 'program_expired' },
  );

  const registered = await reference.registerExecutionProgram(artifact, MATERIAL.context());
  assert.equal(registered.ok, true);
  if (!registered.ok) return;
  const mismatched = admissionInput('inspect', 1);
  mismatched.action_digest = d('substituted-action');
  assert.deepEqual(await reference.reserveExecutionProgramAdmission({
    program_digest: registered.program.program_digest,
    node_id: 'inspect', occurrence_id: 'occurrence:inspect:01', admission: mismatched,
  }), { ok: false, reason: 'program_binding_mismatch' });
  assert.deepEqual(await reference.reserveExecutionProgramAdmission({
    program_digest: registered.program.program_digest,
    node_id: 'inspect', occurrence_id: 'occurrence:prebuilt:01',
    admission: createAdmissionSnapshot(admissionInput('inspect', 91)),
  }), { ok: false, reason: 'program_binding_mismatch' });
});

test('registration refuses to strand an existing unconsumed ordinary authorization', async () => {
  const reference = store();
  const ordinary = await reference.reserve(admissionInput('inspect', 81));
  assert.equal(ordinary.ok, true);
  const artifact = signBoundedExecutionProgram(program(), MATERIAL.signer);
  assert.deepEqual(await reference.registerExecutionProgram(artifact, MATERIAL.context()), {
    ok: false,
    reason: 'program_binding_mismatch',
  });
});

test('signed supersession refuses reserved work and closes the predecessor after release', async () => {
  const fixture = await register();
  const value = admissionInput('inspect', 1);
  const reserved = await fixture.store.reserveExecutionProgramAdmission({
    program_digest: fixture.registered.program.program_digest,
    node_id: 'inspect', occurrence_id: 'occurrence:inspect:01', admission: value,
  });
  assert.equal(reserved.ok, true);
  if (!reserved.ok) return;
  const next = signBoundedExecutionProgram(
    program(2, fixture.registered.program.program_digest),
    fixture.material.signer,
  );
  assert.deepEqual(await fixture.store.supersedeExecutionProgram(next, fixture.material.context(2)), {
    ok: false, reason: 'program_reserved_work_exists',
  });
  assert.equal((await fixture.store.releaseExecutionProgramAdmission({
    tenant_id: value.tenant_id, admission_id: value.admission_id,
    expected_revision: 0, owner_token: reserved.owner_token,
  })).ok, true);
  const superseded = await fixture.store.supersedeExecutionProgram(next, fixture.material.context(2));
  assert.equal(superseded.ok, true);
  assert.deepEqual(await fixture.store.reserveExecutionProgramAdmission({
    program_digest: fixture.registered.program.program_digest,
    node_id: 'inspect', occurrence_id: 'occurrence:old:01', admission: admissionInput('inspect', 7),
  }), { ok: false, reason: 'program_superseded' });
});

test('supersession freezes identity and intent bindings and requires version plus one with fresh authorization', async () => {
  const fixture = await register();
  const predecessor = fixture.registered.program.program_digest;
  const cases: Array<{
    label: string;
    mutate: (candidate: ReturnType<typeof program>) => void;
    context?: Record<string, string>;
  }> = [
    { label: 'version gap', mutate: (candidate) => {
      candidate.version = 3;
      candidate.authorization_digest = d('authorization:3');
    }, context: MATERIAL.context(3) },
    { label: 'reused authorization', mutate: (candidate) => {
      candidate.authorization_digest = d('authorization');
    }, context: MATERIAL.context(1) },
    { label: 'subject', mutate: (candidate) => { candidate.subject_id = 'agent:attacker'; } },
    { label: 'objective', mutate: (candidate) => { candidate.objective_digest = d('objective:changed'); } },
    { label: 'presentation', mutate: (candidate) => { candidate.presentation_digest = d('presentation:changed'); } },
    { label: 'audience', mutate: (candidate) => { candidate.audience = 'gate:other'; }, context: {
      ...MATERIAL.context(2), expected_audience: 'gate:other',
    } },
    { label: 'program id', mutate: (candidate) => { candidate.program_id = 'program:other'; }, context: {
      ...MATERIAL.context(2), expected_program_id: 'program:other',
    } },
    { label: 'tenant', mutate: (candidate) => { candidate.tenant_id = 'tenant:other'; }, context: {
      ...MATERIAL.context(2), expected_tenant_id: 'tenant:other',
    } },
  ];

  for (const entry of cases) {
    const candidate = program(2, predecessor);
    entry.mutate(candidate);
    const artifact = signBoundedExecutionProgram(candidate, MATERIAL.signer);
    const result = await fixture.store.supersedeExecutionProgram(
      artifact,
      (entry.context ?? MATERIAL.context(2)) as any,
    );
    assert.equal(result.ok, false, entry.label);
  }

  const state = await fixture.store.readExecutionProgram({
    tenant_id: 'tenant:alpha',
    program_digest: predecessor,
  });
  assert.equal(state?.status, 'ACTIVE');
});

test('concurrent occurrence reservations linearize to one winner', async () => {
  const fixture = await register();
  const [left, right] = await Promise.all([
    fixture.store.reserveExecutionProgramAdmission({
      program_digest: fixture.registered.program.program_digest,
      node_id: 'inspect', occurrence_id: 'occurrence:inspect:left',
      admission: admissionInput('inspect', 11),
    }),
    fixture.store.reserveExecutionProgramAdmission({
      program_digest: fixture.registered.program.program_digest,
      node_id: 'inspect', occurrence_id: 'occurrence:inspect:right',
      admission: admissionInput('inspect', 12),
    }),
  ]);
  assert.equal([left, right].filter((result) => result.ok).length, 1);
  assert.deepEqual(
    [left, right].filter((result) => !result.ok).map((result: any) => result.reason),
    ['program_occurrence_exhausted'],
  );
  assert.deepEqual(await fixture.store.checkInvariants(), { ok: true, violations: [] });
});

test('currentness failure atomically releases both admission and program budget reservations', async () => {
  let ownerIndex = 1;
  const reference = store({
    ownerTokenFactory: () => owner(ownerIndex++),
    currentnessOracle: {
      read: async (snapshot) => ({
        ...observation(snapshot.body),
        candidate_match: 'MISMATCH' as const,
      }),
    },
  });
  const fixture = await register(reference);
  const value = admissionInput('inspect', 21);
  const reserved = await reference.reserveExecutionProgramAdmission({
    program_digest: fixture.registered.program.program_digest,
    node_id: 'inspect', occurrence_id: 'occurrence:inspect:currentness', admission: value,
  });
  assert.equal(reserved.ok, true);
  if (!reserved.ok) return;
  assert.deepEqual(await reference.beginExecutionProgramInvocation({
    tenant_id: value.tenant_id, admission_id: value.admission_id,
    expected_revision: 0, owner_token: reserved.owner_token,
  }), { ok: false, reason: 'currentness_refused' });
  const state = await reference.readExecutionProgram({
    tenant_id: value.tenant_id,
    program_digest: fixture.registered.program.program_digest,
  });
  assert.ok(state?.budgets.every((budget) => budget.reserved === 0 && budget.consumed === 0));
  assert.equal((await reference.readExecutionProgramOccurrence({
    tenant_id: value.tenant_id,
    program_digest: fixture.registered.program.program_digest,
    occurrence_id: 'occurrence:inspect:currentness',
  }))?.state, 'RELEASED');
  assert.deepEqual(await reference.checkInvariants(), { ok: true, violations: [] });
});

test('store-authoritative suspension and revocation are current at reserve and begin', async () => {
  let now = Date.parse(NOW);
  let status: 'ACTIVE' | 'SUSPENDED' | 'REVOKED' = 'SUSPENDED';
  let sequence = 1;
  const reference = store({
    now: () => now,
    currentnessOracle: {
      read: async (snapshot) => ({
        ...observation(snapshot.body),
        observed_at: new Date(now).toISOString(),
      }),
    },
    executionProgramStatusOracle: {
      read: async (programReference) => programStatusObservation(
        programReference,
        status,
        sequence,
        new Date(now).toISOString(),
        new Date(now + 60_000).toISOString(),
      ),
    },
  });
  const fixture = await register(reference);

  assert.deepEqual(await reference.reserveExecutionProgramAdmission({
    program_digest: fixture.registered.program.program_digest,
    node_id: 'inspect', occurrence_id: 'occurrence:status:suspended',
    admission: admissionInput('inspect', 51),
  }), { ok: false, reason: 'program_suspended' });

  status = 'ACTIVE';
  sequence += 1;
  const beforeBegin = admissionInput('inspect', 52);
  const reserved = await reference.reserveExecutionProgramAdmission({
    program_digest: fixture.registered.program.program_digest,
    node_id: 'inspect', occurrence_id: 'occurrence:status:before-begin',
    admission: beforeBegin,
  });
  assert.equal(reserved.ok, true);
  if (!reserved.ok) return;

  now += 1_000;
  status = 'SUSPENDED';
  sequence += 1;
  assert.deepEqual(await reference.beginExecutionProgramInvocation({
    tenant_id: beforeBegin.tenant_id,
    admission_id: beforeBegin.admission_id,
    expected_revision: 0,
    owner_token: reserved.owner_token,
  }), { ok: false, reason: 'program_suspended' });
  assert.equal((await reference.read({
    tenant_id: beforeBegin.tenant_id,
    admission_id: beforeBegin.admission_id,
  }))?.state, 'RELEASED');

  status = 'ACTIVE';
  sequence += 1;
  const invokingInput = admissionInput('inspect', 53);
  const invokingReservation = await reference.reserveExecutionProgramAdmission({
    program_digest: fixture.registered.program.program_digest,
    node_id: 'inspect', occurrence_id: 'occurrence:status:invoking',
    admission: invokingInput,
  });
  assert.equal(invokingReservation.ok, true);
  if (!invokingReservation.ok) return;
  const begun = await reference.beginExecutionProgramInvocation({
    tenant_id: invokingInput.tenant_id,
    admission_id: invokingInput.admission_id,
    expected_revision: 0,
    owner_token: invokingReservation.owner_token,
  });
  assert.equal(begun.ok, true);
  if (!begun.ok) return;

  status = 'REVOKED';
  sequence += 1;
  assert.deepEqual(await reference.reserveExecutionProgramAdmission({
    program_digest: fixture.registered.program.program_digest,
    node_id: 'inspect', occurrence_id: 'occurrence:status:revoked',
    admission: admissionInput('inspect', 54),
  }), { ok: false, reason: 'program_revoked' });
  const reconciled = await reference.recordProviderOutcome({
    tenant_id: invokingInput.tenant_id,
    admission_id: invokingInput.admission_id,
    expected_revision: 1,
    owner_token: invokingReservation.owner_token,
    invocation_token: begun.invocation_token,
    value: 'PROVEN_NOT_COMMITTED',
    evidence_digest: d('provider:not-committed-after-revocation'),
    observed_at: new Date(now).toISOString(),
  });
  assert.equal(reconciled.ok, true);
  const state = await reference.readExecutionProgram({
    tenant_id: 'tenant:alpha',
    program_digest: fixture.registered.program.program_digest,
  });
  assert.equal(state?.status, 'REVOKED');
  assert.ok(state?.budgets.every((budget) => budget.reserved === 0));
});

test('program status currentness fails closed and releases a reserved begin', async () => {
  let stale = false;
  const reference = store({
    executionProgramStatusOracle: {
      read: async (programReference) => programStatusObservation(
        programReference,
        'ACTIVE',
        1,
        NOW,
        stale ? '2026-07-29T19:59:59.999Z' : '2026-07-29T20:01:00.000Z',
      ),
    },
  });
  const fixture = await register(reference);
  const value = admissionInput('inspect', 55);
  const reserved = await reference.reserveExecutionProgramAdmission({
    program_digest: fixture.registered.program.program_digest,
    node_id: 'inspect', occurrence_id: 'occurrence:status:stale', admission: value,
  });
  assert.equal(reserved.ok, true);
  if (!reserved.ok) return;
  stale = true;
  assert.deepEqual(await reference.beginExecutionProgramInvocation({
    tenant_id: value.tenant_id,
    admission_id: value.admission_id,
    expected_revision: 0,
    owner_token: reserved.owner_token,
  }), { ok: false, reason: 'program_status_indeterminate' });
  assert.equal((await reference.read({
    tenant_id: value.tenant_id,
    admission_id: value.admission_id,
  }))?.state, 'RELEASED');
});

test('program operations fail closed when the store has no status oracle', async () => {
  const configuration: CreateMemoryAdmissionStoreOptions = {
    now: NOW,
    ownerTokenFactory: () => owner(1),
    invocationTokenFactory: () => `admission-invocation:v2:${crypto.randomBytes(32).toString('base64url')}`,
    currentnessOracle: { read: async (snapshot) => observation(snapshot.body) },
    executionProgramVerificationPolicy: MATERIAL.policy,
  };
  const absentAtRegistration = createMemoryAdmissionStore(configuration);
  const artifact = signBoundedExecutionProgram(program(), MATERIAL.signer);
  assert.deepEqual(
    await absentAtRegistration.registerExecutionProgram(artifact, MATERIAL.context()),
    { ok: false, reason: 'program_status_indeterminate' },
  );

  let statusAvailable = true;
  configuration.executionProgramStatusOracle = {
    read: async (reference) => statusAvailable
      ? programStatusObservation(
        reference,
        'ACTIVE',
        1,
        NOW,
        '2026-07-29T21:00:00.000Z',
      )
      : null,
  };
  const missingAfterRegistration = createMemoryAdmissionStore(configuration);
  const registered = await missingAfterRegistration.registerExecutionProgram(
    artifact,
    MATERIAL.context(),
  );
  assert.equal(registered.ok, true);
  if (!registered.ok) return;

  statusAvailable = false;
  assert.deepEqual(await missingAfterRegistration.reserveExecutionProgramAdmission({
    program_digest: registered.program.program_digest,
    node_id: 'inspect',
    occurrence_id: 'occurrence:no-status:reserve',
    admission: admissionInput('inspect', 56),
  }), { ok: false, reason: 'program_status_indeterminate' });

  statusAvailable = true;
  const beforeBegin = admissionInput('inspect', 57);
  const reserved = await missingAfterRegistration.reserveExecutionProgramAdmission({
    program_digest: registered.program.program_digest,
    node_id: 'inspect',
    occurrence_id: 'occurrence:no-status:begin',
    admission: beforeBegin,
  });
  assert.equal(reserved.ok, true);
  if (!reserved.ok) return;
  statusAvailable = false;
  assert.deepEqual(await missingAfterRegistration.beginExecutionProgramInvocation({
    tenant_id: beforeBegin.tenant_id,
    admission_id: beforeBegin.admission_id,
    expected_revision: 0,
    owner_token: reserved.owner_token,
  }), { ok: false, reason: 'program_status_indeterminate' });
});

test('program status source is constructor-pinned against options mutation', async () => {
  const configuration: CreateMemoryAdmissionStoreOptions = {
    now: NOW,
    ownerTokenFactory: () => owner(1),
    invocationTokenFactory: () => `admission-invocation:v2:${crypto.randomBytes(32).toString('base64url')}`,
    currentnessOracle: { read: async (snapshot) => observation(snapshot.body) },
    executionProgramVerificationPolicy: MATERIAL.policy,
    executionProgramStatusOracle: {
      read: async (reference) => programStatusObservation(
        reference,
        'ACTIVE',
        1,
        NOW,
        '2026-07-29T21:00:00.000Z',
      ),
    },
  };
  const reference = createMemoryAdmissionStore(configuration);
  configuration.executionProgramStatusOracle = {
    read: async (statusReference) => programStatusObservation(
      statusReference,
      'REVOKED',
      1,
      NOW,
      '2026-07-29T21:00:00.000Z',
    ),
  };
  const registered = await reference.registerExecutionProgram(
    signBoundedExecutionProgram(program(), MATERIAL.signer),
    MATERIAL.context(),
  );
  assert.equal(registered.ok, true);
  if (!registered.ok) return;
  const reserved = await reference.reserveExecutionProgramAdmission({
    program_digest: registered.program.program_digest,
    node_id: 'inspect',
    occurrence_id: 'occurrence:pinned-status:01',
    admission: admissionInput('inspect', 58),
  });
  assert.equal(reserved.ok, true);
});

test('status observations that expire while awaited are refused using the fresh store clock', async () => {
  let now = Date.parse(NOW);
  const reference = store({
    now: () => now,
    executionProgramStatusOracle: {
      read: async (programReference) => {
        const observationValue = programStatusObservation(
          programReference,
          'ACTIVE',
          1,
          new Date(now).toISOString(),
          new Date(now + 1_000).toISOString(),
        );
        now += 2_000;
        return observationValue;
      },
    },
  });
  const fixture = await register(reference);
  assert.deepEqual(await reference.reserveExecutionProgramAdmission({
    program_digest: fixture.registered.program.program_digest,
    node_id: 'inspect',
    occurrence_id: 'occurrence:status:expired-in-flight',
    admission: admissionInput('inspect', 58),
  }), { ok: false, reason: 'program_status_indeterminate' });
});

test('admission currentness that expires while awaited is refused using the fresh store clock', async () => {
  let now = Date.parse(NOW);
  const reference = store({
    now: () => now,
    currentnessOracle: {
      read: async (snapshot) => {
        const current = {
          ...observation(snapshot.body),
          observed_at: new Date(now).toISOString(),
          qualification_status_expires_at: new Date(now + 1_000).toISOString(),
        };
        now += 2_000;
        return current;
      },
    },
  });
  const fixture = await register(reference);
  const value = admissionInput('inspect', 60);
  const reserved = await reference.reserveExecutionProgramAdmission({
    program_digest: fixture.registered.program.program_digest,
    node_id: 'inspect',
    occurrence_id: 'occurrence:currentness:expired-in-flight',
    admission: value,
  });
  assert.equal(reserved.ok, true);
  if (!reserved.ok) return;
  assert.deepEqual(await reference.beginExecutionProgramInvocation({
    tenant_id: value.tenant_id,
    admission_id: value.admission_id,
    expected_revision: 0,
    owner_token: reserved.owner_token,
  }), { ok: false, reason: 'currentness_refused' });
});

test('program verification callbacks may read the store without deadlocking mutation serialization', async () => {
  let reference: ReturnType<typeof createMemoryAdmissionStore>;
  const reentrantProgram = program();
  (reentrantProgram.nodes[0] as { action: unknown }).action = {
    mode: 'profile',
    profile_id: 'profile:caid-equivalence:1',
    profile_digest: d('profile:aeb'),
  };
  const artifact = signBoundedExecutionProgram(reentrantProgram, MATERIAL.signer);
  const configuration: CreateMemoryAdmissionStoreOptions = {
    now: NOW,
    ownerTokenFactory: () => owner(1),
    invocationTokenFactory: () => `admission-invocation:v2:${crypto.randomBytes(32).toString('base64url')}`,
    executionProgramVerificationPolicy: MATERIAL.policy,
    executionProgramStatusOracle: {
      read: async (programReference) => {
        await reference.readExecutionProgram({
          tenant_id: programReference.tenant_id,
          program_digest: programReference.program_digest,
        });
        return programStatusObservation(
          programReference,
          'ACTIVE',
          1,
          NOW,
          '2026-07-29T21:00:00.000Z',
        );
      },
    },
    executionProgramActionMatchVerifier: {
      verify: async ({ expected }) => {
        await reference.readExecutionProgram({
          tenant_id: expected.tenant_id,
          program_digest: d('program-placeholder'),
        });
        return { ...expected, valid: true, result: 'MATCH' };
      },
    },
    currentnessOracle: {
      read: async (snapshot) => {
        await reference.readExecutionProgram({
          tenant_id: snapshot.body.tenant_id,
          program_digest: registeredDigest,
        });
        return observation(snapshot.body);
      },
    },
  };
  let registeredDigest = d('not-registered');
  reference = createMemoryAdmissionStore(configuration);
  const registered = await reference.registerExecutionProgram(artifact, MATERIAL.context());
  assert.equal(registered.ok, true);
  if (!registered.ok) return;
  registeredDigest = registered.program.program_digest as `sha256:${string}`;
  const value = admissionInput('inspect', 59);
  const result = await Promise.race([
    (async () => {
      const reserved = await reference.reserveExecutionProgramAdmission({
        program_digest: registered.program.program_digest,
        node_id: 'inspect',
        occurrence_id: 'occurrence:reentrant:01',
        admission: value,
        action_match_evidence: { source: 'reentrant-test' },
      });
      assert.equal(reserved.ok, true);
      if (!reserved.ok) return reserved;
      return reference.beginExecutionProgramInvocation({
        tenant_id: value.tenant_id,
        admission_id: value.admission_id,
        expected_revision: 0,
        owner_token: reserved.owner_token,
      });
    })(),
    new Promise<never>((_resolve, reject) => {
      setTimeout(() => reject(new Error('reentrant verifier deadlocked')), 1_000).unref();
    }),
  ]);
  assert.equal(result.ok, true);
});

test('admission expiry is capped by program expiry and reserved work can expire there', async () => {
  const extendEvidence = (value: AdmissionSnapshotInput, admissionExpiry: string) => {
    value.expires_at = admissionExpiry;
    value.qualification_status.expires_at = '2026-07-29T21:30:00.000Z';
    for (const input of value.inputs) input.valid_until = '2026-07-29T21:30:00.000Z';
    for (const resource of value.resource_reservations) {
      resource.expires_at = '2026-07-29T21:30:00.000Z';
    }
    return value;
  };
  let now = Date.parse(NOW);
  const reference = store({ now: () => now });
  const fixture = await register(reference);
  assert.deepEqual(await reference.reserveExecutionProgramAdmission({
    program_digest: fixture.registered.program.program_digest,
    node_id: 'inspect', occurrence_id: 'occurrence:expiry:too-long',
    admission: extendEvidence(admissionInput('inspect', 61), '2026-07-29T21:00:00.001Z'),
  }), { ok: false, reason: 'program_expiration_mismatch' });

  const atLimit = extendEvidence(admissionInput('inspect', 62), '2026-07-29T21:00:00.000Z');
  const reserved = await reference.reserveExecutionProgramAdmission({
    program_digest: fixture.registered.program.program_digest,
    node_id: 'inspect', occurrence_id: 'occurrence:expiry:at-limit', admission: atLimit,
  });
  assert.equal(reserved.ok, true);
  if (!reserved.ok) return;
  now = Date.parse('2026-07-29T21:00:00.000Z');
  const expired = await reference.expireExecutionProgramAdmission({
    tenant_id: atLimit.tenant_id,
    admission_id: atLimit.admission_id,
    expected_revision: 0,
    owner_token: reserved.owner_token,
  });
  assert.equal(expired.ok, true);
  assert.ok((await reference.readExecutionProgram({
    tenant_id: 'tenant:alpha',
    program_digest: fixture.registered.program.program_digest,
  }))?.budgets.every((budget) => budget.reserved === 0 && budget.consumed === 0));

  let beginClock = Date.parse(NOW);
  const beginReference = store({ now: () => beginClock });
  const beginFixture = await register(beginReference);
  const beginInput = extendEvidence(admissionInput('inspect', 63), '2026-07-29T21:00:00.000Z');
  const beginReservation = await beginReference.reserveExecutionProgramAdmission({
    program_digest: beginFixture.registered.program.program_digest,
    node_id: 'inspect', occurrence_id: 'occurrence:expiry:begin', admission: beginInput,
  });
  assert.equal(beginReservation.ok, true);
  if (!beginReservation.ok) return;
  beginClock = Date.parse('2026-07-29T21:00:00.000Z');
  assert.deepEqual(await beginReference.beginExecutionProgramInvocation({
    tenant_id: beginInput.tenant_id,
    admission_id: beginInput.admission_id,
    expected_revision: 0,
    owner_token: beginReservation.owner_token,
  }), { ok: false, reason: 'program_expired' });
  assert.equal((await beginReference.read({
    tenant_id: beginInput.tenant_id,
    admission_id: beginInput.admission_id,
  }))?.state, 'RELEASED');
});

test('profile-mode nodes require pinned MATCH evidence already sealed into the admission', async () => {
  const source = program();
  source.nodes[0].action = {
    mode: 'profile',
    profile_id: 'profile:aeb-action-match',
    profile_digest: d('profile:aeb'),
  } as any;
  const evidenceToken = { signed_match: 'opaque-verifier-input' };
  let actionMatchOverride: Partial<ExecutionProgramActionMatchExpected> = {};
  const reference = store({
    executionProgramActionMatchVerifier: {
      verify: async ({ evidence, expected }) => {
        assert.deepEqual(evidence, evidenceToken);
        return { valid: true, result: 'MATCH', ...expected, ...actionMatchOverride };
      },
    },
  });
  const artifact = signBoundedExecutionProgram(source, MATERIAL.signer);
  const registered = await reference.registerExecutionProgram(artifact, MATERIAL.context());
  assert.equal(registered.ok, true);
  if (!registered.ok) return;
  const value = admissionInput('inspect', 31);
  const evidence = value.inputs.find((entry) => entry.role === 'aeb')!;
  assert.deepEqual(await reference.reserveExecutionProgramAdmission({
    program_digest: registered.program.program_digest,
    node_id: 'inspect', occurrence_id: 'occurrence:profile:missing', admission: value,
  }), { ok: false, reason: 'program_binding_mismatch' });
  const substitutions: Array<Partial<ExecutionProgramActionMatchExpected>> = [
    { profile_id: 'profile:other' },
    { profile_digest: d('profile:other') },
    { subject_id: 'agent:attacker' },
    { operation_id: 'operation:substituted' },
    { caid: caid('other') },
    { action_digest: d('action:substituted') },
    { verifier_id: 'verifier:attacker' },
    { evidence_payload_digest: d('evidence:substituted') },
    { evidence_trust_configuration_digest: d('trust-config:substituted') },
    { trust_epoch: 2 },
    { trust_configuration_digest: d('trust:substituted') },
  ];
  for (const [index, substitution] of substitutions.entries()) {
    actionMatchOverride = substitution;
    assert.deepEqual(await reference.reserveExecutionProgramAdmission({
      program_digest: registered.program.program_digest,
      node_id: 'inspect', occurrence_id: `occurrence:profile:substitution:${index}`,
      admission: value,
      action_match_evidence: evidenceToken,
    }), { ok: false, reason: 'program_binding_mismatch' });
  }
  actionMatchOverride = {};
  const reserved = await reference.reserveExecutionProgramAdmission({
    program_digest: registered.program.program_digest,
    node_id: 'inspect', occurrence_id: 'occurrence:profile:01', admission: value,
    action_match_evidence: evidenceToken,
  });
  assert.equal(reserved.ok, true);
});

test('aggregate attempt ceilings refuse a third root even when its occurrence ceiling is open', async () => {
  const reference = store();
  const source = program();
  source.nodes = ['inspect', 'remediate', 'verify'].map((node, index) => ({
    node_id: node,
    action: { mode: 'exact', caid: caid(node), action_digest: d(`action:${node}`) },
    trust_program_digest: d(`trust:${node}`),
    depends_on: [],
    max_occurrences: 1,
    charges: [
      { budget_id: 'attempts', amount: 1 },
      { budget_id: 'change-risk', amount: 1 },
    ],
  })) as any;
  const artifact = signBoundedExecutionProgram(source, MATERIAL.signer);
  const registered = await reference.registerExecutionProgram(artifact, MATERIAL.context());
  assert.equal(registered.ok, true);
  if (!registered.ok) return;
  assert.equal((await reference.reserveExecutionProgramAdmission({
    program_digest: registered.program.program_digest,
    node_id: 'inspect', occurrence_id: 'occurrence:budget:1', admission: admissionInput('inspect', 41),
  })).ok, true);
  assert.equal((await reference.reserveExecutionProgramAdmission({
    program_digest: registered.program.program_digest,
    node_id: 'remediate', occurrence_id: 'occurrence:budget:2', admission: admissionInput('remediate', 42),
  })).ok, true);
  const third = admissionInput('inspect', 43);
  third.caid = caid('verify');
  third.action_digest = d('action:verify');
  third.authorization_policy_digest = d('trust:verify');
  assert.deepEqual(await reference.reserveExecutionProgramAdmission({
    program_digest: registered.program.program_digest,
    node_id: 'verify', occurrence_id: 'occurrence:budget:3', admission: third,
  }), { ok: false, reason: 'program_budget_exhausted' });
});

test('duplicate unit labels retain independent budget_id accounting', async () => {
  const reference = store();
  const source = program();
  source.budgets = [
    { budget_id: 'attempts-primary', unit: 'attempt', limit: 1 },
    { budget_id: 'attempts-secondary', unit: 'attempt', limit: 2 },
  ];
  source.nodes[0].charges = [{ budget_id: 'attempts-primary', amount: 1 }];
  source.nodes[1].charges = [{ budget_id: 'attempts-secondary', amount: 2 }];
  const artifact = signBoundedExecutionProgram(source, MATERIAL.signer);
  const registered = await reference.registerExecutionProgram(artifact, MATERIAL.context());
  assert.equal(registered.ok, true);
  if (!registered.ok) return;
  const value = admissionInput('inspect', 71);
  const reserved = await reference.reserveExecutionProgramAdmission({
    program_digest: registered.program.program_digest,
    node_id: 'inspect', occurrence_id: 'occurrence:unit-label:1', admission: value,
  });
  assert.equal(reserved.ok, true);
  if (!reserved.ok) return;
  const begun = await reference.beginExecutionProgramInvocation({
    tenant_id: value.tenant_id,
    admission_id: value.admission_id,
    expected_revision: 0,
    owner_token: reserved.owner_token,
  });
  assert.equal(begun.ok, true);
  const state = await reference.readExecutionProgram({
    tenant_id: 'tenant:alpha',
    program_digest: registered.program.program_digest,
  });
  assert.deepEqual(state?.budgets, [
    { budget_id: 'attempts-primary', unit: 'attempt', limit: 1, reserved: 0, consumed: 1 },
    { budget_id: 'attempts-secondary', unit: 'attempt', limit: 2, reserved: 0, consumed: 0 },
  ]);
});

test('total occurrence ceiling counts released attempts and bounds retained program work', async () => {
  const reference = store();
  const source = program();
  source.max_total_occurrences = 2;
  source.nodes = [source.nodes[0]];
  source.nodes[0].max_occurrences = 3;
  source.budgets = source.budgets.map((budget) => ({ ...budget, limit: 10 }));
  const artifact = signBoundedExecutionProgram(source, MATERIAL.signer);
  const registered = await reference.registerExecutionProgram(artifact, MATERIAL.context());
  assert.equal(registered.ok, true);
  if (!registered.ok) return;

  for (let index = 0; index < 2; index += 1) {
    const value = admissionInput('inspect', 80 + index);
    const reserved = await reference.reserveExecutionProgramAdmission({
      program_digest: registered.program.program_digest,
      node_id: 'inspect', occurrence_id: `occurrence:total:${index}`, admission: value,
    });
    assert.equal(reserved.ok, true);
    if (!reserved.ok) return;
    assert.equal((await reference.releaseExecutionProgramAdmission({
      tenant_id: value.tenant_id,
      admission_id: value.admission_id,
      expected_revision: 0,
      owner_token: reserved.owner_token,
    })).ok, true);
  }

  assert.deepEqual(await reference.reserveExecutionProgramAdmission({
    program_digest: registered.program.program_digest,
    node_id: 'inspect', occurrence_id: 'occurrence:total:2', admission: admissionInput('inspect', 82),
  }), { ok: false, reason: 'program_total_occurrence_exhausted' });
  assert.equal((await reference.readExecutionProgram({
    tenant_id: 'tenant:alpha', program_digest: registered.program.program_digest,
  }))?.total_occurrences, 2);
  assert.deepEqual(await reference.checkInvariants(), { ok: true, violations: [] });
});

test('indexed node and terminal-outcome counts remain correct under retained occurrence stress', async () => {
  const reference = store();
  const source = program();
  const rootCount = 128;
  source.max_total_occurrences = rootCount + 1;
  source.budgets = [{ budget_id: 'attempts', unit: 'attempt', limit: rootCount + 1 }];
  source.nodes[0].max_occurrences = rootCount;
  source.nodes[0].charges = [{ budget_id: 'attempts', amount: 1 }];
  source.nodes[1].depends_on = [{ node_id: 'inspect', outcomes: ['PROVEN_NOT_COMMITTED'] }];
  source.nodes[1].charges = [{ budget_id: 'attempts', amount: 1 }];
  const artifact = signBoundedExecutionProgram(source, MATERIAL.signer);
  const registered = await reference.registerExecutionProgram(artifact, MATERIAL.context());
  assert.equal(registered.ok, true);
  if (!registered.ok) return;

  for (let index = 0; index < rootCount; index += 1) {
    const value = admissionInput('inspect', 1_000 + index);
    const reserved = await reference.reserveExecutionProgramAdmission({
      program_digest: registered.program.program_digest,
      node_id: 'inspect', occurrence_id: `occurrence:stress:${index}`, admission: value,
    });
    assert.equal(reserved.ok, true, `reserve ${index}`);
    if (!reserved.ok) return;
    const begun = await reference.beginExecutionProgramInvocation({
      tenant_id: value.tenant_id,
      admission_id: value.admission_id,
      expected_revision: 0,
      owner_token: reserved.owner_token,
    });
    assert.equal(begun.ok, true, `begin ${index}`);
    if (!begun.ok) return;
    const terminal = await reference.recordProviderOutcome({
      tenant_id: value.tenant_id,
      admission_id: value.admission_id,
      expected_revision: 1,
      owner_token: reserved.owner_token,
      invocation_token: begun.invocation_token,
      value: 'PROVEN_NOT_COMMITTED',
      evidence_digest: d(`stress-terminal:${index}`),
      observed_at: NOW,
    });
    assert.equal(terminal.ok, true, `terminal ${index}`);
  }

  const dependent = await reference.reserveExecutionProgramAdmission({
    program_digest: registered.program.program_digest,
    node_id: 'remediate', occurrence_id: 'occurrence:stress:dependent',
    admission: admissionInput('remediate', 2_000),
  });
  assert.equal(dependent.ok, true);
  const state = await reference.readExecutionProgram({
    tenant_id: 'tenant:alpha', program_digest: registered.program.program_digest,
  });
  assert.equal(state?.total_occurrences, rootCount + 1);
  assert.deepEqual(await reference.checkInvariants(), { ok: true, violations: [] });
});
