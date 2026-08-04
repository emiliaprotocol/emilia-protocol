// SPDX-License-Identifier: Apache-2.0
import assert from 'node:assert/strict';
import { generateKeyPairSync } from 'node:crypto';
import test from 'node:test';

import {
  ADMISSION_CURRENTNESS_VERSION,
  createMemoryAdmissionStore,
  type AdmissionCurrentnessObservation,
  type AdmissionSnapshotInput,
  type AdmissionStore,
} from './admission-store.js';
import {
  RECOVERY_CAPABILITY_STATUS_VERSION,
  deriveRecoveryAdmissionSnapshotBindings,
  signRecoveryCapability,
} from './recovery-admission.js';
import {
  RECOVERY_ADMISSION_POSTGRES_BEGIN,
  executeRecoveryAdmissionPostgresLocalAtomic,
  type RecoveryAdmissionPostgresClient,
  type RecoveryAdmissionPostgresPool,
} from './recovery-admission-postgres.js';

const NOW_ISO = '2026-08-03T20:00:00.000Z';
const NOW = Date.parse(NOW_ISO);
const ACTION_EXPIRES = '2026-08-03T20:30:00.000Z';
const ADMISSION_EXPIRES = '2026-08-03T21:00:00.000Z';
const CAID = `caid:1:operations.update.1:jcs-sha256:${'A'.repeat(43)}`;
const EVIDENCE_DIGEST = `sha256:${'4'.repeat(64)}`;
const STATE_DOMAIN_DIGEST = `sha256:${'3'.repeat(64)}`;
const ADAPTER_DIGEST = `sha256:${'1'.repeat(64)}`;
const INVOCATION_TOKEN = `admission-invocation:v2:${'I'.repeat(43)}`;
const d = (character: string) => `sha256:${character.repeat(64)}` as const;

function currentness(
  snapshot: Readonly<{ body: AdmissionSnapshotInput }>,
): AdmissionCurrentnessObservation {
  return {
    '@version': ADMISSION_CURRENTNESS_VERSION,
    observed_at: NOW_ISO,
    qualification_status_authority_id: snapshot.body.qualification_status.authority_id,
    qualification_status_sequence: snapshot.body.qualification_status.sequence,
    qualification_status_head_digest: snapshot.body.qualification_status.head_payload_digest,
    qualification_status_expires_at: snapshot.body.qualification_status.expires_at,
    trust_epoch: snapshot.body.trust_epoch,
    trust_configuration_digest: snapshot.body.trust_configuration_digest,
    configuration_epoch: snapshot.body.configuration_epoch,
    configuration_digest: snapshot.body.configuration_digest,
    runtime_measurement_digest: snapshot.body.runtime_measurement_digest,
    candidate_match: 'EXACT_MATCH',
    external_leases: [],
  };
}

function admissionInput(): AdmissionSnapshotInput {
  const inputs: AdmissionSnapshotInput['inputs'] = [
    'candidate_manifest', 'runtime_measurement', 'test_result',
    'agent_evaluation_evidence', 'qualification_statement',
    'qualification_status', 'aeb', 'aec', 'local_policy', 'authorization',
  ].map((role, index) => ({
    role: role as AdmissionSnapshotInput['inputs'][number]['role'],
    artifact_type: `artifact.${role}`,
    subject: role === 'candidate_manifest' || role === 'aeb'
      ? 'agent:recovery-demo' : `subject:${role}`,
    payload_digest: d(String((index % 9) + 1)),
    profile_digest: d('a'),
    verifier_id: `verifier:${role}`,
    trust_configuration_digest: d('b'),
    valid_until: ADMISSION_EXPIRES,
  }));
  return {
    tenant_id: 'tenant:demo',
    admission_id: 'admission:recovery:01',
    operation_id: 'operation:recovery:01',
    candidate_manifest_digest: d('c'),
    runtime_measurement_digest: d('d'),
    candidate_custody: {
      request_construction: 'GATE',
      mutation_credential_custody: 'GATE',
      enforcement_placement: 'ACTUATOR',
      evidence_digest: d('e'),
    },
    assignment_digest: d('f'),
    qualification_policy_digest: d('0'),
    test_result_payload_digests: [d('1')],
    agent_evaluation_evidence_payload_digests: [d('2')],
    qualification_statement_payload_digest: d('3'),
    qualification_status: {
      authority_id: 'qualification-authority:primary',
      sequence: 1,
      head_payload_digest: d('4'),
      observed_at: NOW_ISO,
      expires_at: ADMISSION_EXPIRES,
    },
    caid: CAID,
    action_digest: d('5'),
    effect_request_digest: d('6'),
    provider: {
      provider_id: 'provider:postgres:demo',
      account_id: 'account:production',
      environment: 'production',
    },
    executor_adapter_digest: ADAPTER_DIGEST,
    idempotency_key: 'idempotency:recovery:01',
    authorization_policy_digest: d('7'),
    trust_epoch: 1,
    trust_configuration_digest: d('8'),
    configuration_epoch: 1,
    configuration_digest: d('9'),
    inputs,
    resource_reservations: [{
      kind: 'provider_operation',
      resource_id: 'operation:recovery:01',
      reservation_id: 'reservation:recovery:01',
      digest: d('a'),
      expires_at: ADMISSION_EXPIRES,
    }],
    admitted_at: NOW_ISO,
    expires_at: ADMISSION_EXPIRES,
    supersedes_admission_id: null,
    remedy_for: null,
  };
}

interface FakePostgresOptions {
  connectError?: Error;
  query?: (text: string) => Promise<void> | void;
}

function fakePostgres(options: FakePostgresOptions = {}) {
  const events: string[] = [];
  const releases: Array<Error | undefined> = [];
  let connects = 0;
  const client: RecoveryAdmissionPostgresClient = {
    async query(text) {
      events.push(text);
      await options.query?.(text);
      return { rowCount: null, rows: [] };
    },
    release(error) {
      releases.push(error);
      events.push(error ? 'RELEASE_DISCARD' : 'RELEASE');
    },
  };
  const pool: RecoveryAdmissionPostgresPool = {
    localAtomic: true,
    policyBoundToSingleTransaction: true,
    externalEffectsForbidden: true,
    stateDomainDigest: STATE_DOMAIN_DIGEST,
    adapterDigest: ADAPTER_DIGEST,
    async connect() {
      connects += 1;
      events.push('CONNECT');
      if (options.connectError) throw options.connectError;
      return client;
    },
  };
  return { events, releases, pool, connects: () => connects };
}

async function fixture(pg = fakePostgres()) {
  const signerPair = generateKeyPairSync('ed25519');
  const signer = {
    issuer_id: 'rp:example-operations',
    key_id: 'key:rp:recovery:v1',
    private_key: signerPair.privateKey,
  };
  const admission = admissionInput();
  const admissionStore = createMemoryAdmissionStore({
    now: NOW_ISO,
    currentnessOracle: { read: async (snapshot) => currentness(snapshot as any) },
  });
  const reserved = await admissionStore.reserve(admission);
  assert.equal(reserved.ok, true);
  if (!reserved.ok) throw new Error('admission reservation failed');
  const admissionBindings = deriveRecoveryAdmissionSnapshotBindings(reserved.snapshot.body);
  const recovery = {
    scope: 'INTRA_TRANSACTION_ONLY' as const,
    state_domain_digest: STATE_DOMAIN_DIGEST,
    adapter_id: 'adapter:postgres:demo',
    adapter_digest: ADAPTER_DIGEST,
    max_transaction_ms: 100,
  };
  const capabilityInput = {
    capability_id: 'recovery-capability:demo:01',
    admission_id: admission.admission_id,
    admission_snapshot_digest: reserved.snapshot.snapshot_digest,
    tenant_id: admission.tenant_id,
    audience: 'gate:demo',
    action_caid: admission.caid,
    action_digest: admission.action_digest,
    action_capability_expires_at: ACTION_EXPIRES,
    provider_id: admissionBindings.provider_id,
    account_digest: admissionBindings.account_digest,
    environment_digest: admissionBindings.environment_digest,
    operation_id: admission.operation_id,
    issuer_digest: d('d'),
    trust_epoch_digest: admissionBindings.trust_epoch_digest,
    config_epoch_digest: admissionBindings.config_epoch_digest,
    adapter_id: 'adapter:postgres:demo',
    adapter_digest: admissionBindings.adapter_digest,
    resource_set_digest: admissionBindings.resource_set_digest,
    issued_at: '2026-08-03T19:59:00.000Z',
    valid_from: NOW_ISO,
    expires_at: ACTION_EXPIRES,
    mode: 'LOCAL_ATOMIC' as const,
    recovery,
  };
  const artifact = signRecoveryCapability(capabilityInput, signer);
  const trustedKeys = {
    [signer.key_id]: {
      issuer_id: signer.issuer_id,
      public_key: signerPair.publicKey.export({ type: 'spki', format: 'der' }).toString('base64url'),
    },
  };
  const expectedPolicy = {
    capability_id: capabilityInput.capability_id,
    admission_id: capabilityInput.admission_id,
    admission_snapshot_digest: capabilityInput.admission_snapshot_digest,
    mode: capabilityInput.mode,
    recovery,
    tenant_id: capabilityInput.tenant_id,
    audience: capabilityInput.audience,
    action_caid: capabilityInput.action_caid,
    action_digest: capabilityInput.action_digest,
    action_capability_expires_at: capabilityInput.action_capability_expires_at,
    provider_id: capabilityInput.provider_id,
    account_digest: capabilityInput.account_digest,
    environment_digest: capabilityInput.environment_digest,
    operation_id: capabilityInput.operation_id,
    issuer_id: signer.issuer_id,
    issuer_digest: capabilityInput.issuer_digest,
    trust_epoch_digest: capabilityInput.trust_epoch_digest,
    config_epoch_digest: capabilityInput.config_epoch_digest,
    adapter_id: capabilityInput.adapter_id,
    adapter_digest: capabilityInput.adapter_digest,
    resource_set_digest: capabilityInput.resource_set_digest,
  };
  const verificationContext = {
    trusted_keys: trustedKeys,
    expected_policy: expectedPolicy,
    now: NOW_ISO,
  };
  const evaluatorDependencies = {
    current_status_resolver(input: Readonly<Record<string, any>>) {
      return {
        '@version': RECOVERY_CAPABILITY_STATUS_VERSION,
        capability_id: input.capability.capability_id,
        capability_digest: input.capability_digest,
        tenant_id: input.capability.tenant_id,
        audience: input.capability.audience,
        action_caid: input.capability.action_caid,
        action_digest: input.capability.action_digest,
        provider_id: input.capability.provider_id,
        adapter_id: input.capability.adapter_id,
        issuer_id: input.issuer_id,
        status: 'CURRENT',
        observed_at: NOW_ISO,
        valid_from: NOW_ISO,
        valid_until: ACTION_EXPIRES,
      };
    },
  };
  const callbacks = {
    async perform(client: RecoveryAdmissionPostgresClient, invocation: Readonly<Record<string, any>>) {
      assert.equal(invocation.invocation_token, INVOCATION_TOKEN);
      pg.events.push('PERFORM_CALLBACK');
      await client.query('PERFORM');
      return { result: Object.freeze({ changed: 1 }), evidence_digest: EVIDENCE_DIGEST };
    },
    async validatePrecommit(client: RecoveryAdmissionPostgresClient) {
      pg.events.push('VALIDATE_CALLBACK');
      await client.query('VALIDATE');
      return true;
    },
    async recheckCurrent(client: RecoveryAdmissionPostgresClient) {
      pg.events.push('RECHECK_CALLBACK');
      await client.query('RECHECK');
      return true;
    },
  };
  return {
    admission,
    admissionStore,
    artifact,
    signer,
    capabilityInput,
    reserved,
    pg,
    options: {
      artifact,
      verificationContext,
      evaluatorDependencies,
      admissionStore,
      ownerToken: reserved.owner_token,
      invocationToken: INVOCATION_TOKEN,
      pool: pg.pool,
      now: () => NOW,
      ...callbacks,
    },
  };
}

test('consumes ordinary admission before one serializable transaction and records COMMITTED', async () => {
  const fx = await fixture();
  const result = await executeRecoveryAdmissionPostgresLocalAtomic(fx.options);
  assert.deepEqual(result, {
    outcome: 'COMMITTED', invoked: true, result: { changed: 1 },
    evidence_digest: EVIDENCE_DIGEST,
  });
  assert.deepEqual(fx.pg.events, [
    'CONNECT', RECOVERY_ADMISSION_POSTGRES_BEGIN, 'PERFORM_CALLBACK', 'PERFORM',
    'VALIDATE_CALLBACK', 'VALIDATE', 'RECHECK_CALLBACK', 'RECHECK', 'COMMIT', 'RELEASE',
  ]);
  const record = await fx.admissionStore.read({
    tenant_id: fx.admission.tenant_id, admission_id: fx.admission.admission_id,
  });
  assert.equal(record?.state, 'COMMITTED');
  assert.equal(record?.execution_right, 'CONSUMED');
  assert.equal(record?.provider_outcome?.evidence_digest, EVIDENCE_DIGEST);
});

test('a caller-constructed decision is ignored and cannot authorize execution', async () => {
  const fx = await fixture();
  const result = await executeRecoveryAdmissionPostgresLocalAtomic({
    ...fx.options,
    artifact: { decision: { route: 'LOCAL_ATOMIC' } },
    decision: { route: 'LOCAL_ATOMIC' },
  } as any);
  assert.deepEqual(result, { outcome: 'NOT_INVOKED', invoked: false, reason: 'recovery_admission_refused' });
  assert.equal(fx.pg.connects(), 0);
  const record = await fx.admissionStore.read({ tenant_id: fx.admission.tenant_id, admission_id: fx.admission.admission_id });
  assert.equal(record?.state, 'RESERVED');
});

test('wrong admission snapshot policy refuses before consuming authority', async () => {
  const fx = await fixture();
  const result = await executeRecoveryAdmissionPostgresLocalAtomic({
    ...fx.options,
    verificationContext: {
      ...fx.options.verificationContext,
      expected_policy: {
        ...fx.options.verificationContext.expected_policy,
        admission_snapshot_digest: d('f'),
      },
    },
  } as any);
  assert.deepEqual(result, { outcome: 'NOT_INVOKED', invoked: false, reason: 'recovery_admission_refused' });
  assert.equal(fx.pg.connects(), 0);
});

test('a recovery policy that self-consistently names the wrong admission context still refuses', async () => {
  const fx = await fixture();
  const accountDigest = d('f');
  const artifact = signRecoveryCapability({
    ...fx.capabilityInput,
    account_digest: accountDigest,
  }, fx.signer);
  const result = await executeRecoveryAdmissionPostgresLocalAtomic({
    ...fx.options,
    artifact,
    verificationContext: {
      ...fx.options.verificationContext,
      expected_policy: {
        ...fx.options.verificationContext.expected_policy,
        account_digest: accountDigest,
      },
    },
  } as any);
  assert.deepEqual(result, { outcome: 'NOT_INVOKED', invoked: false, reason: 'admission_binding_mismatch' });
  assert.equal(fx.pg.connects(), 0);
  const record = await fx.admissionStore.read({ tenant_id: fx.admission.tenant_id, admission_id: fx.admission.admission_id });
  assert.equal(record?.state, 'RESERVED');
});

test('wrong owner token or unavailable prepared-token API refuses before PostgreSQL', async (t) => {
  await t.test('owner', async () => {
    const fx = await fixture();
    const result = await executeRecoveryAdmissionPostgresLocalAtomic({
      ...fx.options,
      ownerToken: `admission-owner:v2:${'X'.repeat(43)}`,
    });
    assert.deepEqual(result, { outcome: 'NOT_INVOKED', invoked: false, reason: 'begin_invocation_refused' });
    assert.equal(fx.pg.connects(), 0);
  });
  await t.test('store contract', async () => {
    const fx = await fixture();
    const store = Object.create(fx.admissionStore) as AdmissionStore;
    Object.defineProperty(store, 'beginInvocationWithPreparedToken', { value: undefined });
    const result = await executeRecoveryAdmissionPostgresLocalAtomic({ ...fx.options, admissionStore: store });
    assert.deepEqual(result, { outcome: 'NOT_INVOKED', invoked: false, reason: 'admission_store_guarantee_mismatch' });
    assert.equal(fx.pg.connects(), 0);
  });
});

test('pool markers and adapter/state-domain digests fail before admission consumption', async (t) => {
  for (const [name, pool] of [
    ['external effect marker', { externalEffectsForbidden: false }],
    ['state domain', { stateDomainDigest: d('a') }],
    ['adapter', { adapterDigest: d('b') }],
  ] as const) {
    await t.test(name, async () => {
      const fx = await fixture();
      const result = await executeRecoveryAdmissionPostgresLocalAtomic({
        ...fx.options, pool: { ...fx.pg.pool, ...pool },
      });
      assert.equal(result.outcome, 'NOT_INVOKED');
      assert.equal(fx.pg.connects(), 0);
      const record = await fx.admissionStore.read({ tenant_id: fx.admission.tenant_id, admission_id: fx.admission.admission_id });
      assert.equal(record?.state, 'RESERVED');
    });
  }
});

test('successful rollback with evidence records PROVEN_NOT_COMMITTED without restoring authority', async () => {
  const fx = await fixture();
  const result = await executeRecoveryAdmissionPostgresLocalAtomic({
    ...fx.options,
    validatePrecommit: async () => false,
  });
  assert.deepEqual(result, {
    outcome: 'PROVEN_NOT_COMMITTED', invoked: true,
    reason: 'precommit_validation_failed', evidence_digest: EVIDENCE_DIGEST,
  });
  const record = await fx.admissionStore.read({ tenant_id: fx.admission.tenant_id, admission_id: fx.admission.admission_id });
  assert.equal(record?.state, 'PROVEN_NOT_COMMITTED');
  assert.equal(record?.execution_right, 'CONSUMED');
  assert.equal(fx.pg.events.includes('ROLLBACK'), true);
  assert.equal(fx.pg.events.includes('COMMIT'), false);
});

test('missing rollback evidence stays INDETERMINATE after authority consumption', async () => {
  const fx = await fixture();
  const result = await executeRecoveryAdmissionPostgresLocalAtomic({
    ...fx.options,
    perform: async () => { throw new Error('perform failed before evidence'); },
  });
  assert.deepEqual(result, { outcome: 'INDETERMINATE', invoked: true, reason: 'evidence_required' });
  const record = await fx.admissionStore.read({ tenant_id: fx.admission.tenant_id, admission_id: fx.admission.admission_id });
  assert.equal(record?.state, 'INDETERMINATE');
  assert.equal(record?.execution_right, 'CONSUMED');
});

test('rollback or COMMIT acknowledgement loss is INDETERMINATE and never retried', async (t) => {
  await t.test('rollback', async () => {
    const fx = await fixture(fakePostgres({ query(text) { if (text === 'ROLLBACK') throw new Error('lost'); } }));
    const result = await executeRecoveryAdmissionPostgresLocalAtomic({
      ...fx.options, validatePrecommit: async () => false,
    });
    assert.equal(result.outcome, 'INDETERMINATE');
    assert.equal(result.reason, 'rollback_failed');
    assert.equal(fx.pg.events.includes('COMMIT'), false);
  });
  await t.test('commit', async () => {
    const fx = await fixture(fakePostgres({ query(text) { if (text === 'COMMIT') throw new Error('lost'); } }));
    const result = await executeRecoveryAdmissionPostgresLocalAtomic(fx.options);
    assert.equal(result.outcome, 'INDETERMINATE');
    assert.equal(result.reason, 'commit_acknowledgement_failed');
    assert.equal(fx.pg.events.filter((entry) => entry === 'COMMIT').length, 1);
  });
});

test('connection loss after authority consumption becomes durable INDETERMINATE', async () => {
  const fx = await fixture(fakePostgres({ connectError: new Error('down') }));
  const result = await executeRecoveryAdmissionPostgresLocalAtomic(fx.options);
  assert.deepEqual(result, { outcome: 'INDETERMINATE', invoked: true, reason: 'connection_failed' });
  const record = await fx.admissionStore.read({ tenant_id: fx.admission.tenant_id, admission_id: fx.admission.admission_id });
  assert.equal(record?.state, 'INDETERMINATE');
});

test('provider-outcome recording failure after COMMIT is reported INDETERMINATE', async () => {
  const fx = await fixture();
  const failingStore = Object.create(fx.admissionStore) as AdmissionStore;
  Object.defineProperty(failingStore, 'recordProviderOutcome', {
    value: async () => { throw new Error('journal unavailable'); },
  });
  const result = await executeRecoveryAdmissionPostgresLocalAtomic({ ...fx.options, admissionStore: failingStore });
  assert.deepEqual(result, {
    outcome: 'INDETERMINATE', invoked: true,
    reason: 'provider_outcome_recording_failed', evidence_digest: EVIDENCE_DIGEST,
  });
  assert.equal(fx.pg.events.includes('COMMIT'), true);
});

test('throwing prepared-token transition is ambiguous and prevents PostgreSQL entry', async () => {
  const fx = await fixture();
  const throwingStore = Object.create(fx.admissionStore) as AdmissionStore;
  Object.defineProperty(throwingStore, 'beginInvocationWithPreparedToken', {
    value: async () => { throw new Error('ack lost'); },
  });
  const result = await executeRecoveryAdmissionPostgresLocalAtomic({ ...fx.options, admissionStore: throwingStore });
  assert.deepEqual(result, { outcome: 'INDETERMINATE', invoked: false, reason: 'begin_invocation_ambiguous' });
  assert.equal(fx.pg.connects(), 0);
});
