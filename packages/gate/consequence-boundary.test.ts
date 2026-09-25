// SPDX-License-Identifier: Apache-2.0
import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import test from 'node:test';
import { ml_dsa65 } from '@noble/post-quantum/ml-dsa.js';
import {
  adapterPinDigest,
  digestAeb,
  evaluateAebEvidence,
  mappingProfileDigest,
  registryEntryDigest,
  unifiedRegistryDigest,
} from '@emilia-protocol/verify/aeb-adapter-contract';
import {
  AEB_NATIVE_AUTHORIZATION_GATEWAY_KEY_VERSION,
  AEB_NATIVE_AUTHORIZATION_PINS_VERSION,
  AEB_NATIVE_AUTHORIZATION_SOURCE_PIN_VERSION,
  AEB_NATIVE_AUTHORIZATION_STATUS_VERSION,
  issueAebNativeAuthorizationHandoff,
  verifyAebNativeAuthorizationHandoff,
  type AebNativeAuthorizationSystem,
} from '@emilia-protocol/verify/aeb';
import { loadDefaultAgilityMldsaBackend } from '@emilia-protocol/verify/pq-signature-agility';
import {
  consequenceBoundaryProviderIdempotencyKey,
  createConsequenceBoundary,
  createNativeConsequenceBoundary,
  nativeConsequenceBoundaryActionFenceKey,
  nativeConsequenceBoundaryProviderIdempotencyKey,
  type ConsequenceBoundaryAttemptBinding,
  type ConsequenceBoundaryAttemptReference,
  type ConsequenceBoundaryProviderEvidence,
} from './consequence-boundary.js';
import {
  FINANCE_CUMULATIVE_EXPOSURE_PROFILE,
  createConsequenceEnvelopeBoundary,
  createMemoryConsequenceEnvelopeStore,
  issueConsequenceEnvelope,
  type ConsequenceEnvelopeBoundary,
} from './dist/consequence-envelope.js';

const CAID = `caid:1:payment.release.1:jcs-sha256:${'A'.repeat(43)}`;
const ACTION = Object.freeze({
  action_type: 'payment.release.1',
  transfer_id: 'transfer-1',
  amount: '500.00',
  currency: 'USD',
});
const EVALUATED_AT = '2026-08-09T12:00:00.000Z';
const NOW = '2026-08-09T12:00:01.000Z';
const EXECUTOR = 'executor:gate-1';
const PROVIDER = Object.freeze({
  tenant_id: 'tenant:acme',
  provider_id: 'provider:bank',
  provider_account_id: 'account:one',
  environment: 'sandbox',
});

function registryEntry(entryId: string, kind: string, definition: unknown) {
  const entry: any = { kind, version: '1', status: 'active', definition };
  entry.definition_digest = registryEntryDigest(entryId, entry);
  return entry;
}

function fixture({
  operationId = 'operation:release-1',
  executorId = EXECUTOR,
  replayId = 'native-mandate:one',
} = {}) {
  const adapter = {
    id: 'test:native-mandate',
    version: '1',
    verifyNative({ artifact, status, trust_roots }: any) {
      const trusted = trust_roots.includes(artifact.root);
      return {
        native_verification: trusted ? 'VERIFIED' : 'FAILED',
        acceptance: trusted ? 'ACCEPTED' : 'REJECTED',
        evidence_digest: digestAeb(artifact),
        status_digest: digestAeb({
          checked_at: status.checked_at,
          expires_at: status.expires_at,
          revocation_checked: status.revocation_checked,
          revoked: status.revoked,
          consumed: status.consumed,
          unavailable: status.unavailable === true,
        }),
        evidence_role: 'native-mandate',
        subject: { id: 'agent:buyer', kind: 'workload' },
        replay_unit: digestAeb({ adapter: 'test:native-mandate', replay_id: artifact.replay_id }),
        reasons: trusted ? [] : ['native_trust_root_not_pinned'],
      };
    },
    mapAction({ artifact, native, expected_action }: any) {
      return {
        mapping: native.native_verification === 'VERIFIED' ? 'MATCH' : 'INDETERMINATE',
        caid: artifact.caid,
        action_digest: digestAeb(expected_action),
        reasons: [],
      };
    },
  };
  const profile: any = {
    version: 'payment-release-v1',
    definition: { action_type: 'payment.release.1' },
    registry_entry_ref: 'mapping:payment-release',
    mapper_id: 'mapper:payment-release',
    resolver: {
      id: 'resolver:payment-release',
      version: '1',
      implementation_digest: digestAeb({ implementation: 'resolver:payment-release:1' }),
    },
    semantic_equivalence: {
      assertion: 'EQUIVALENT_UNDER_PROFILE',
      loss_policy: 'NO_MATERIAL_FIELD_LOSS',
      omitted_material_fields: [],
      omitted_nonmaterial_fields: [],
    },
  };
  profile.profile_digest = mappingProfileDigest('payment-release', profile);
  const entries: any = {
    'mapping:payment-release': registryEntry(
      'mapping:payment-release',
      'mapping-profile',
      { profile_digest: profile.profile_digest },
    ),
    'role:native-mandate': registryEntry(
      'role:native-mandate',
      'evidence-role',
      { role: 'native-mandate', subject_kinds: ['workload'] },
    ),
  };
  const registry: any = {
    '@version': 'EP-EVIDENCE-REGISTRY-v1',
    registry_id: 'registry:consequence-boundary-test',
    epoch: 1,
    entries,
  };
  registry.registry_digest = unifiedRegistryDigest(registry);
  const pin: any = {
    version: '1',
    trust_roots: ['root:test'],
    config: { mode: 'offline' },
    max_status_age_sec: 300,
  };
  pin.config_digest = adapterPinDigest('test:native-mandate', pin);
  const evaluator = crypto.generateKeyPairSync('ed25519');
  const config: any = {
    '@version': 'AEB-ADAPTER-v1',
    relying_party_id: 'rp:consequence-boundary-test',
    evaluator_keys: {
      'eval:test': {
        public_key: evaluator.publicKey.export({ type: 'spki', format: 'der' }).toString('base64url'),
      },
    },
    registry,
    accepted_mappers: ['mapper:payment-release'],
    adapters: { 'test:native-mandate': pin },
    profiles: { 'payment-release': profile },
    requirements: {
      'requirement:native-mandate': {
        '@version': 'AEB-REQUIREMENT-v1',
        all_of: ['native-mandate'],
        terms: [{ type: 'one-time-consumption' }],
      },
    },
  };
  const artifact = {
    root: 'root:test',
    caid: CAID,
    replay_id: replayId,
    mandate_id: 'ap2-like-mandate-1',
  };
  const status = {
    checked_at: '2026-08-09T11:59:59.000Z',
    expires_at: '2026-08-09T12:05:00.000Z',
    revocation_checked: true,
    revoked: false,
    consumed: false,
  };
  const evaluation = evaluateAebEvidence({
    config,
    adapters: { 'test:native-mandate': adapter },
    operation_id: operationId,
    consumption_nonce: `nonce:${operationId}`,
    initiator_id: 'agent:buyer',
    executor_id: executorId,
    requirement_ref: 'requirement:native-mandate',
    caid: CAID,
    expected_action: ACTION,
    legs: [{
      adapter_id: 'test:native-mandate',
      profile_id: 'payment-release',
      artifact_ref: 'artifact:native-mandate',
      artifact,
      status,
    }],
    evaluated_at: EVALUATED_AT,
    signer: { key_id: 'eval:test', private_key: evaluator.privateKey },
  });
  assert.equal(evaluation.valid, true, JSON.stringify(evaluation.reasons));
  return {
    config,
    adapters: { 'test:native-mandate': adapter },
    evaluation: evaluation.record,
    artifacts: { 'artifact:native-mandate': artifact },
    current_statuses: { 'artifact:native-mandate': status },
  };
}

function durableAebDatabase() {
  return {
    operations: new Map<string, 'RESERVED' | 'CONSUMED'>(),
    ownerTokens: new Map<string, string>(),
    replayOwners: new Map<string, string>(),
  };
}

/**
 * Durable test store with the shipped PostgreSQL store's ownership model:
 * the database outlives the process, but commit and release are fenced to the
 * store instance that reserved (or has since claimed) the row. A restarted
 * process is a new instance over the same database and holds no owner token
 * until an authorized recovery claim.
 */
function durableAebStore(db = durableAebDatabase()) {
  const owned = new Map<string, string>();
  const claims: string[] = [];
  const ownsRow = (key: string) => owned.has(key)
    && db.ownerTokens.get(key) === owned.get(key);
  return {
    durable: true as const,
    ownershipFenced: true as const,
    permanentConsumption: true as const,
    atomicReplayFenced: true as const,
    recoveryClaimSupported: true as const,
    db,
    operations: db.operations,
    replayOwners: db.replayOwners,
    claims,
    async reserve(key: string, replayKeys: readonly string[]) {
      if (db.operations.has(key)) return 'CONSUMPTION_CONFLICT' as const;
      if (replayKeys.some((replayKey) => db.replayOwners.has(replayKey))) {
        return 'NATIVE_REPLAY_CONFLICT' as const;
      }
      const token = crypto.randomUUID();
      db.operations.set(key, 'RESERVED');
      db.ownerTokens.set(key, token);
      owned.set(key, token);
      for (const replayKey of replayKeys) db.replayOwners.set(replayKey, key);
      return 'RESERVED' as const;
    },
    async commit(key: string) {
      if (db.operations.get(key) !== 'RESERVED' || !ownsRow(key)) return false;
      db.operations.set(key, 'CONSUMED');
      db.ownerTokens.delete(key);
      owned.delete(key);
      return true;
    },
    async release(key: string) {
      if (db.operations.get(key) !== 'RESERVED' || !ownsRow(key)) return false;
      db.operations.delete(key);
      db.ownerTokens.delete(key);
      owned.delete(key);
      for (const [replayKey, owner] of db.replayOwners) {
        if (owner === key) db.replayOwners.delete(replayKey);
      }
      return true;
    },
    async claimReservation(key: string, authorization: unknown) {
      if (owned.has(key) || authorization !== 'recovery:approved'
          || db.operations.get(key) !== 'RESERVED') return false;
      const token = crypto.randomUUID();
      db.ownerTokens.set(key, token);
      owned.set(key, token);
      claims.push(key);
      return true;
    },
    state(key: string) {
      return db.operations.get(key) ?? 'AVAILABLE';
    },
  };
}

function attemptStore() {
  const rows = new Map<string, {
    binding: ConsequenceBoundaryAttemptBinding;
    owner: string;
    state: 'RESERVED' | 'INVOKING' | 'INDETERMINATE' | 'COMMITTED' | 'RELEASED';
    evidence?: ConsequenceBoundaryProviderEvidence;
  }>();
  return {
    durable: true as const,
    ownershipFenced: true as const,
    compareAndSwap: true as const,
    atomicEvidenceBinding: true as const,
    rows,
    async reserve(binding: ConsequenceBoundaryAttemptBinding) {
      if (rows.has(binding.attempt_id)) return { reserved: false as const, reason: 'attempt_exists' };
      const owner = `owner:${crypto.randomBytes(24).toString('base64url')}`;
      rows.set(binding.attempt_id, { binding: structuredClone(binding), owner, state: 'RESERVED' });
      return { reserved: true as const, owner: owner as any };
    },
    async transition(input: ConsequenceBoundaryAttemptReference & any) {
      const row = rows.get(input.attempt_id);
      if (!row || row.owner !== input.owner || row.state !== input.expected_state) return false;
      row.state = input.next_state;
      return true;
    },
    async reconcile(input: ConsequenceBoundaryAttemptReference & any) {
      const row = rows.get(input.attempt_id);
      if (!row || row.owner !== input.owner || row.state !== input.expected_state) return false;
      const binding = row.binding;
      const evidence = input.evidence as ConsequenceBoundaryProviderEvidence;
      for (const field of [
        'tenant_id', 'provider_id', 'provider_account_id', 'environment',
        'attempt_id', 'request_digest', 'provider_idempotency_key',
      ] as const) {
        if (evidence[field] !== binding[field]) return false;
      }
      row.state = input.next_state;
      row.evidence = structuredClone(evidence);
      return true;
    },
    async state(input: ConsequenceBoundaryAttemptReference) {
      const row = rows.get(input.attempt_id);
      if (!row || row.owner !== input.owner) throw new Error('attempt_not_owned');
      return {
        state: row.state,
        ...(row.evidence ? { evidence: structuredClone(row.evidence) } : {}),
      };
    },
  };
}

function input(f: ReturnType<typeof fixture>, action: unknown = ACTION) {
  return {
    evaluation: f.evaluation,
    action,
    artifacts: f.artifacts,
    current_statuses: f.current_statuses,
  };
}

function executedEvidence() {
  return {
    evidence_id: 'provider-evidence:executed-1',
    observed_at: '2026-08-09T12:00:02.000Z',
    evidence_digest: digestAeb({ provider: 'bank', outcome: 'executed', id: 1 }),
  };
}

function makeBoundary({
  f = fixture(),
  aebStore = durableAebStore(),
  attempts = attemptStore(),
  consequenceEnvelope = undefined as ConsequenceEnvelopeBoundary | undefined,
  localAuthorize = () => true,
  invoke = async () => ({ state: 'EXECUTED' as const, evidence: executedEvidence(), result: { id: 'effect-1' } }),
} = {}) {
  let attemptCounter = 0;
  const boundary = createConsequenceBoundary({
    executor_id: EXECUTOR,
    provider: PROVIDER,
    aeb: { config: f.config, adapters: f.adapters, store: aebStore },
    attempts: {
      store: attempts,
      create_id: () => `attempt:${++attemptCounter}`,
      recover: ({ attempt, recovery_authorization }) => {
        if (recovery_authorization !== 'recovery:approved') return null;
        const row = attempts.rows.get(attempt.attempt_id);
        if (!row) return null;
        return { ...structuredClone(row.binding), owner: row.owner as any };
      },
    },
    consequence_envelope: consequenceEnvelope,
    allow_test_consequence_envelope: consequenceEnvelope ? true : undefined,
    local_authorize: localAuthorize,
    invoke,
    now: () => NOW,
  });
  return { boundary, aebStore, attempts };
}

async function unitConsequenceEnvelope(capacityUnits = '1') {
  const edPrivate = crypto.createPrivateKey({
    key: {
      crv: 'Ed25519',
      d: 'EBsZ3aVNd8cSzmZECgG0MMAPTreFIhgDFtTY9UTkQ_Y',
      x: 'c_kUSHs4ymdA65GF3OV8C3PDWhelodqfOvCmFe-6oUI',
      kty: 'OKP',
    },
    format: 'jwk',
  });
  const edPublic = crypto.createPublicKey(edPrivate);
  const pqPair = ml_dsa65.keygen(new Uint8Array(32).fill(0x61));
  const mldsaBackend = await loadDefaultAgilityMldsaBackend();
  assert.ok(mldsaBackend);
  const envelope = await issueConsequenceEnvelope({
    envelope_id: 'envelope:boundary-integration:1',
    state_domain_id: 'state-domain:boundary-integration',
    epoch: 1,
    capacity_units: capacityUnits,
    impact_profile_id: FINANCE_CUMULATIVE_EXPOSURE_PROFILE.id,
    impact_profile_digest: FINANCE_CUMULATIVE_EXPOSURE_PROFILE.digest,
    validity: {
      not_before: '2026-08-09T12:00:00.000Z',
      not_after: '2026-08-09T12:10:00.000Z',
    },
    issuer: { id: 'authority:boundary-integration', key_id: 'envelope-ed' },
    parent_allocation: null,
    renewable: false,
  }, {
    signing_keys: [
      { alg: 'Ed25519', key_id: 'envelope-ed', private_key: edPrivate },
      { alg: 'ML-DSA-65', key_id: 'envelope-pq', private_key: pqPair.secretKey },
    ],
    mldsaBackend,
  });
  return createConsequenceEnvelopeBoundary({
    envelope,
    verification_keys: [
      {
        alg: 'Ed25519',
        key_id: 'envelope-ed',
        public_key: edPublic.export({ type: 'spki', format: 'der' }).toString('base64url'),
      },
      {
        alg: 'ML-DSA-65',
        key_id: 'envelope-pq',
        public_key: Buffer.from(pqPair.publicKey).toString('base64url'),
      },
    ],
    mldsaBackend,
    profile: {
      ...FINANCE_CUMULATIVE_EXPOSURE_PROFILE,
      derive() {
        return { ok: true as const, impact_units: 1n };
      },
    },
    store: createMemoryConsequenceEnvelopeStore(),
    allow_test_store: true,
    now: () => NOW,
    authorize_recovery: ({ recovery_authorization }) => recovery_authorization === 'recovery:approved',
  });
}

test('neutral consequence boundary executes native mandate evidence without requiring a receipt or human role', async () => {
  const f = fixture();
  let calls = 0;
  const h = makeBoundary({
    f,
    localAuthorize: (context) => {
      assert.equal(Object.isFrozen(context), true);
      assert.equal(Object.isFrozen(context.action), true);
      assert.deepEqual(context.action, ACTION);
      assert.equal(context.evaluation.operation_id, f.evaluation.operation_id);
      assert.equal(context.provider.provider_account_id, PROVIDER.provider_account_id);
      return true;
    },
    invoke: async (context) => {
      calls += 1;
      assert.equal(Object.isFrozen(context), true);
      assert.equal(Object.isFrozen(context.action), true);
      assert.equal(context.caid, CAID);
      assert.equal(
        context.provider_idempotency_key,
        consequenceBoundaryProviderIdempotencyKey({
          provider: PROVIDER,
          caid: CAID,
          action_digest: digestAeb(ACTION),
          authorization_instance: f.evaluation.consumption_nonce,
        }),
      );
      assert.equal(context.attempt.provider_idempotency_key, context.provider_idempotency_key);
      return { state: 'EXECUTED', evidence: executedEvidence(), result: { id: 'effect-1' } };
    },
  });
  const result = await h.boundary.run(input(f));
  assert.equal(result.state, 'EXECUTED');
  assert.equal(result.invoked, true);
  assert.equal(calls, 1);
});

test('provider idempotency key is canonical, provider-scoped, and bound to one exact authorization instance', () => {
  const base = {
    provider: PROVIDER,
    caid: CAID,
    action_digest: digestAeb(ACTION),
    authorization_instance: 'nonce:operation:release-1',
  } as const;
  const first = consequenceBoundaryProviderIdempotencyKey(base);
  assert.match(first, /^epcb1:[a-f0-9]{64}$/);
  assert.equal(consequenceBoundaryProviderIdempotencyKey(base), first);
  assert.notEqual(consequenceBoundaryProviderIdempotencyKey({
    ...base,
    provider: { ...PROVIDER, provider_account_id: 'account:two' },
  }), first);
  assert.notEqual(consequenceBoundaryProviderIdempotencyKey({
    ...base,
    action_digest: digestAeb({ ...ACTION, amount: '501.00' }),
  }), first);
  assert.notEqual(consequenceBoundaryProviderIdempotencyKey({
    ...base,
    authorization_instance: 'nonce:operation:release-2',
  }), first);
});

test('approve-A execute-B substitution is refused before the provider callback', async () => {
  const f = fixture();
  let localCalls = 0;
  let calls = 0;
  const h = makeBoundary({
    f,
    localAuthorize: () => {
      localCalls += 1;
      return true;
    },
    invoke: async () => {
      calls += 1;
      return { state: 'EXECUTED', evidence: executedEvidence(), result: null };
    },
  });
  const result = await h.boundary.run(input(f, { ...ACTION, amount: '5000.00' }));
  assert.equal(result.state, 'REFUSED');
  assert.equal(result.invoked, false);
  assert.equal(result.reason, 'exact_action_binding_mismatch');
  assert.equal(localCalls, 0);
  assert.equal(h.aebStore.operations.size, 0);
  assert.equal(calls, 0);
});

test('an untrusted evaluation cannot obtain the trusted exact-action mismatch reason', async () => {
  const f = fixture({ operationId: 'operation:untrusted-substitution', replayId: 'native-mandate:untrusted-substitution' });
  const evaluation: any = structuredClone(f.evaluation);
  evaluation.signature.value = `${evaluation.signature.value[0] === 'A' ? 'B' : 'A'}${evaluation.signature.value.slice(1)}`;
  let localCalls = 0;
  let calls = 0;
  const h = makeBoundary({
    f,
    localAuthorize: () => {
      localCalls += 1;
      return true;
    },
    invoke: async () => {
      calls += 1;
      return { state: 'EXECUTED', evidence: executedEvidence(), result: null };
    },
  });
  const result = await h.boundary.run({
    ...input(f, { ...ACTION, amount: '5000.00' }),
    evaluation,
  });
  assert.equal(result.state, 'REFUSED');
  assert.equal(result.invoked, false);
  assert.notEqual(result.reason, 'exact_action_binding_mismatch');
  assert.equal(localCalls, 0);
  assert.equal(h.aebStore.operations.size, 0);
  assert.equal(calls, 0);
});

test('local authorization denial is load-bearing and blocks provider entry', async () => {
  const f = fixture({ operationId: 'operation:local-refusal', replayId: 'native-mandate:local-refusal' });
  let calls = 0;
  const h = makeBoundary({
    f,
    localAuthorize: () => false,
    invoke: async () => {
      calls += 1;
      return { state: 'EXECUTED', evidence: executedEvidence(), result: null };
    },
  });
  const result = await h.boundary.run(input(f));
  assert.equal(result.state, 'REFUSED');
  assert.equal(result.invoked, false);
  assert.equal(result.reason, 'local_authorization_denied');
  assert.equal(h.aebStore.operations.size, 0);
  assert.equal(calls, 0);
});

test('local authorization exceptions fail closed before provider entry', async () => {
  const f = fixture({ operationId: 'operation:local-error', replayId: 'native-mandate:local-error' });
  let calls = 0;
  const h = makeBoundary({
    f,
    localAuthorize: () => { throw new Error('policy_unavailable'); },
    invoke: async () => {
      calls += 1;
      return { state: 'EXECUTED', evidence: executedEvidence(), result: null };
    },
  });
  const result = await h.boundary.run(input(f));
  assert.equal(result.state, 'REFUSED');
  assert.equal(result.invoked, false);
  assert.equal(result.reason, 'local_authorization_denied');
  assert.equal(h.aebStore.operations.size, 0);
  assert.equal(calls, 0);
});

test('local authorization requires the exact boolean true', async () => {
  const f = fixture({ operationId: 'operation:local-truthy', replayId: 'native-mandate:local-truthy' });
  let calls = 0;
  const h = makeBoundary({
    f,
    localAuthorize: () => 1 as any,
    invoke: async () => {
      calls += 1;
      return { state: 'EXECUTED', evidence: executedEvidence(), result: null };
    },
  });
  const result = await h.boundary.run(input(f));
  assert.equal(result.state, 'REFUSED');
  assert.equal(result.invoked, false);
  assert.equal(result.reason, 'local_authorization_denied');
  assert.equal(h.aebStore.operations.size, 0);
  assert.equal(calls, 0);
});

test('same native mandate cannot be wrapped under a new operation and admitted twice', async () => {
  const first = fixture({ operationId: 'operation:first' });
  const second = fixture({ operationId: 'operation:second' });
  const aebStore = durableAebStore();
  const firstBoundary = makeBoundary({ f: first, aebStore }).boundary;
  const secondBoundary = makeBoundary({ f: second, aebStore }).boundary;
  assert.equal((await firstBoundary.run(input(first))).state, 'EXECUTED');
  const replay = await secondBoundary.run(input(second));
  assert.equal(replay.state, 'REFUSED');
  assert.equal(replay.reason, 'native_replay_conflict');
});

test('provider exception becomes INDETERMINATE and keeps the authorization fenced', async () => {
  const f = fixture();
  const h = makeBoundary({ f, invoke: async () => { throw new Error('connection_lost'); } });
  const first = await h.boundary.run(input(f));
  assert.equal(first.state, 'INDETERMINATE');
  assert.equal(first.invoked, true);
  assert.equal(first.retry_allowed, false);
  const retry = await h.boundary.run(input(f));
  assert.equal(retry.state, 'REFUSED');
  assert.match(retry.reason, /consumption_conflict/);
});

test('authoritative FAILED burns the one-time authorization and requires a new action instance', async () => {
  const f = fixture();
  const h = makeBoundary({
    f,
    invoke: async () => ({
      state: 'FAILED',
      reason: 'provider_declined',
      evidence: {
        evidence_id: 'provider-evidence:failed-1',
        observed_at: '2026-08-09T12:00:02.000Z',
        evidence_digest: digestAeb({ provider: 'bank', outcome: 'not-committed', id: 1 }),
      },
    }),
  });
  const failed = await h.boundary.run(input(f));
  assert.equal(failed.state, 'FAILED');
  assert.equal(failed.retry_allowed, false);
  const replay = await h.boundary.run(input(f));
  assert.equal(replay.state, 'REFUSED');
});

test('evaluation for another executor is refused before local policy and effect', async () => {
  const f = fixture({ executorId: 'executor:other' });
  let localCalls = 0;
  let calls = 0;
  const h = makeBoundary({
    f,
    localAuthorize: () => {
      localCalls += 1;
      return true;
    },
    invoke: async () => {
      calls += 1;
      return { state: 'EXECUTED', evidence: executedEvidence(), result: null };
    },
  });
  const result = await h.boundary.run(input(f));
  assert.equal(result.state, 'REFUSED');
  assert.equal(result.reason, 'executor_binding_mismatch');
  assert.equal(localCalls, 0);
  assert.equal(h.aebStore.operations.size, 0);
  assert.equal(calls, 0);
});

test('concurrent admission invokes the provider exactly once', async () => {
  const f = fixture();
  let calls = 0;
  const h = makeBoundary({ f, invoke: async () => {
    calls += 1;
    await Promise.resolve();
    return { state: 'EXECUTED', evidence: executedEvidence(), result: { ok: true } };
  } });
  const results = await Promise.all([
    h.boundary.run(input(f)),
    h.boundary.run(input(f)),
  ]);
  assert.equal(calls, 1);
  assert.deepEqual(results.map((result) => result.state).sort(), ['EXECUTED', 'REFUSED']);
});

test('post-effect hostile outcome objects fail closed and non-JSON provider results do not throw', async () => {
  const hostileFixture = fixture({ operationId: 'operation:hostile-result' });
  const hostile: any = {};
  Object.defineProperty(hostile, 'state', {
    enumerable: true,
    get() { throw new Error('outcome accessor executed'); },
  });
  const hostileBoundary = makeBoundary({
    f: hostileFixture,
    invoke: async () => hostile,
  }).boundary;
  const hostileResult = await hostileBoundary.run(input(hostileFixture));
  assert.equal(hostileResult.state, 'INDETERMINATE');
  assert.equal(hostileResult.reason, 'provider_outcome_invalid');

  const binaryFixture = fixture({ operationId: 'operation:binary-result', replayId: 'native-mandate:binary' });
  const binary = Buffer.from('provider-native-result');
  const binaryBoundary = makeBoundary({
    f: binaryFixture,
    invoke: async () => ({ state: 'EXECUTED', evidence: executedEvidence(), result: binary }),
  }).boundary;
  const binaryResult = await binaryBoundary.run(input(binaryFixture));
  assert.equal(binaryResult.state, 'EXECUTED');
  if (binaryResult.state === 'EXECUTED') assert.equal(binaryResult.result, binary);
});

test('INDETERMINATE is closed to replay but can be reconciled through separately authorized custody recovery', async () => {
  const f = fixture({ operationId: 'operation:reconcile', replayId: 'native-mandate:reconcile' });
  const h = makeBoundary({
    f,
    invoke: async () => ({ state: 'INDETERMINATE', reason: 'provider_timeout' }),
  });
  const first = await h.boundary.run(input(f));
  assert.equal(first.state, 'INDETERMINATE');
  assert.ok(first.attempt);
  const tamperedBinding = await h.boundary.reconcile({
    evaluation: f.evaluation,
    action: ACTION,
    artifacts: f.artifacts,
    attempt: {
      ...first.attempt,
      provider_idempotency_key: `epcb1:${'0'.repeat(64)}`,
    },
    outcome: { state: 'EXECUTED', evidence: executedEvidence(), result: { id: 'effect:wrong-key' } },
    recovery_authorization: 'recovery:approved',
  });
  assert.equal(tamperedBinding.state, 'REFUSED');
  assert.equal(tamperedBinding.reason, 'reconciliation_binding_mismatch');
  const refusedRecovery = await h.boundary.reconcile({
    evaluation: f.evaluation,
    action: ACTION,
    artifacts: f.artifacts,
    attempt: first.attempt,
    outcome: { state: 'EXECUTED', evidence: executedEvidence(), result: { id: 'effect:recovered' } },
    recovery_authorization: 'recovery:wrong',
  });
  assert.equal(refusedRecovery.state, 'REFUSED');
  assert.equal(refusedRecovery.reason, 'attempt_recovery_refused');

  const reconciled = await h.boundary.reconcile({
    evaluation: f.evaluation,
    action: ACTION,
    artifacts: f.artifacts,
    attempt: first.attempt,
    outcome: { state: 'EXECUTED', evidence: executedEvidence(), result: { id: 'effect:recovered' } },
    recovery_authorization: 'recovery:approved',
  });
  assert.equal(reconciled.state, 'EXECUTED');
  const replay = await h.boundary.run(input(f));
  assert.equal(replay.state, 'REFUSED');
});

test('a shared consequence envelope refuses oversubscription before a second provider entry', async () => {
  const envelope = await unitConsequenceEnvelope('1');
  const first = fixture({ operationId: 'operation:capacity:first', replayId: 'native-mandate:capacity:first' });
  const second = fixture({ operationId: 'operation:capacity:second', replayId: 'native-mandate:capacity:second' });
  let providerCalls = 0;
  const invoke = async () => {
    providerCalls += 1;
    return { state: 'EXECUTED' as const, evidence: executedEvidence(), result: { admitted: true } };
  };
  const firstBoundary = makeBoundary({ f: first, consequenceEnvelope: envelope, invoke });
  const secondBoundary = makeBoundary({ f: second, consequenceEnvelope: envelope, invoke });

  assert.equal((await firstBoundary.boundary.run(input(first))).state, 'EXECUTED');
  const refused = await secondBoundary.boundary.run(input(second));
  assert.equal(refused.state, 'REFUSED');
  assert.equal(refused.reason, 'consequence_envelope_capacity_exceeded');
  assert.equal(providerCalls, 1);
  assert.equal(secondBoundary.aebStore.operations.size, 0);
  assert.deepEqual(envelope.snapshot(), {
    capacity_units: '1',
    available_units: '0',
    held_units: '0',
    committed_units: '1',
  });
});

test('unknown provider outcome keeps aggregate capacity unavailable and reconciliation never reexecutes', async () => {
  const envelope = await unitConsequenceEnvelope('1');
  const f = fixture({ operationId: 'operation:capacity:unknown', replayId: 'native-mandate:capacity:unknown' });
  let providerCalls = 0;
  const h = makeBoundary({
    f,
    consequenceEnvelope: envelope,
    invoke: async () => {
      providerCalls += 1;
      throw new Error('response_lost');
    },
  });
  const first = await h.boundary.run(input(f));
  assert.equal(first.state, 'INDETERMINATE');
  assert.ok(first.attempt);
  assert.equal(providerCalls, 1);
  assert.equal(envelope.snapshot().committed_units, '1');

  const retry = await h.boundary.run(input(f));
  assert.equal(retry.state, 'REFUSED');
  assert.equal(providerCalls, 1);

  const reconciled = await h.boundary.reconcile({
    evaluation: f.evaluation,
    action: ACTION,
    artifacts: f.artifacts,
    attempt: first.attempt,
    outcome: { state: 'EXECUTED', evidence: executedEvidence(), result: { id: 'effect:reconciled' } },
    recovery_authorization: 'recovery:approved',
  });
  assert.equal(reconciled.state, 'EXECUTED');
  assert.equal(providerCalls, 1);
  assert.equal(envelope.snapshot().committed_units, '1');
});

test('authoritative non-commitment releases aggregate capacity without reviving spent authority', async () => {
  const envelope = await unitConsequenceEnvelope('1');
  const f = fixture({ operationId: 'operation:capacity:failed', replayId: 'native-mandate:capacity:failed' });
  const h = makeBoundary({
    f,
    consequenceEnvelope: envelope,
    invoke: async () => ({
      state: 'FAILED',
      reason: 'provider_declined',
      evidence: {
        evidence_id: 'provider-evidence:capacity-failed',
        observed_at: '2026-08-09T12:00:02.000Z',
        evidence_digest: digestAeb({ provider: 'bank', outcome: 'not-committed', id: 'capacity' }),
      },
    }),
  });
  const failed = await h.boundary.run(input(f));
  assert.equal(failed.state, 'FAILED');
  assert.equal(envelope.snapshot().available_units, '1');
  assert.equal(envelope.snapshot().committed_units, '0');
  assert.equal((await h.boundary.run(input(f))).state, 'REFUSED');
});

function nativeFixture(system: AebNativeAuthorizationSystem = 'authzen') {
  const pair = crypto.generateKeyPairSync('ed25519');
  const gatewayId = `gateway:${system}`;
  const keyId = `gateway-key:${system}:one`;
  const nativeAuthorization = {
    system,
    profile: `${system}:exact-action-result:1`,
    issuer: `https://${system}.example`,
    authorization_id: `native-authz:${system}:123`,
  };
  const pins: any = {
    '@version': AEB_NATIVE_AUTHORIZATION_PINS_VERSION,
    relying_party_id: 'rp:payments',
    audience: 'https://gate.example/payments',
    executor_id: EXECUTOR,
    provider: PROVIDER,
    max_handoff_age_seconds: 120,
    max_status_age_seconds: 30,
    clock_skew_seconds: 2,
    gateway_keys: [{
      '@version': AEB_NATIVE_AUTHORIZATION_GATEWAY_KEY_VERSION,
      gateway_id: gatewayId,
      key_id: keyId,
      algorithm: 'Ed25519',
      public_key: pair.publicKey.export({ type: 'spki', format: 'der' }).toString('base64url'),
    }],
    accepted_sources: [{
      '@version': AEB_NATIVE_AUTHORIZATION_SOURCE_PIN_VERSION,
      gateway_id: gatewayId,
      system,
      profile: nativeAuthorization.profile,
      issuer: nativeAuthorization.issuer,
    }],
  };
  const handoffInput: any = {
    gateway_id: gatewayId,
    native_authorization: nativeAuthorization,
    relying_party_id: pins.relying_party_id,
    audience: pins.audience,
    executor_id: pins.executor_id,
    provider: PROVIDER,
    action: ACTION,
    issued_at: '2026-08-09T12:00:00.000Z',
    not_before: '2026-08-09T12:00:00.000Z',
    expires_at: '2026-08-09T12:01:00.000Z',
    revocation_id: `revocation:${system}:123`,
  };
  const signer = { key_id: keyId, private_key: pair.privateKey };
  const handoff = issueAebNativeAuthorizationHandoff(handoffInput, signer);
  const status: any = {
    '@version': AEB_NATIVE_AUTHORIZATION_STATUS_VERSION,
    gateway_id: gatewayId,
    native_authorization: handoff.native_authorization,
    revocation_id: handoffInput.revocation_id,
    checked_at: '2026-08-09T12:00:00.000Z',
    valid_until: '2026-08-09T12:00:30.000Z',
    revoked: false,
  };
  return { pins, handoffInput, signer, handoff, status };
}

function issueNative(
  f: ReturnType<typeof nativeFixture>,
  overrides: Record<string, unknown>,
) {
  return issueAebNativeAuthorizationHandoff({ ...f.handoffInput, ...overrides }, f.signer);
}

function makeNativeBoundary({
  f = nativeFixture(),
  aebStore = durableAebStore(),
  attempts = attemptStore(),
  localAuthorize = () => true,
  resolveStatus = () => f.status,
  resolveHistoricalPins = () => f.pins,
  providerOutcomeVerify = () => true,
  trustSnapshotId = 'native-trust-snapshot:test:1',
  localAuthorizationProgramDigest = digestAeb({
    program: 'native-local-authorization:test:1',
  }),
  providerOutcomeVerificationProgramDigest = digestAeb({
    program: 'native-provider-outcome-verifier:test:1',
  }),
  recover = undefined as undefined | ((input: {
    attempt: Readonly<ConsequenceBoundaryAttemptBinding>;
    recovery_authorization: unknown;
  }) => ConsequenceBoundaryAttemptReference | null
    | Promise<ConsequenceBoundaryAttemptReference | null>),
  invoke = async () => ({
    state: 'EXECUTED' as const,
    evidence: executedEvidence(),
    result: { id: 'native-effect-1' },
  }),
  now = () => NOW,
} = {}) {
  let attemptCounter = 0;
  const configuration = {
    executor_id: EXECUTOR,
    provider: PROVIDER,
    native_authorization: {
      pins: f.pins,
      trust_snapshot_id: trustSnapshotId,
      store: aebStore,
      resolve_status: resolveStatus,
      resolve_historical_pins: resolveHistoricalPins,
    },
    attempts: {
      store: attempts,
      create_id: () => `native-attempt:${++attemptCounter}`,
      recover: recover ?? (({ attempt, recovery_authorization }: {
        attempt: Readonly<ConsequenceBoundaryAttemptBinding>;
        recovery_authorization: unknown;
      }) => {
        if (recovery_authorization !== 'recovery:approved') return null;
        const row = attempts.rows.get(attempt.attempt_id);
        return row ? { ...structuredClone(row.binding), owner: row.owner as any } : null;
      }),
    },
    local_authorization_program_digest: localAuthorizationProgramDigest,
    local_authorize: localAuthorize,
    invoke,
    provider_outcomes: {
      verification_program_digest: providerOutcomeVerificationProgramDigest,
      verify: providerOutcomeVerify,
    },
    now,
  };
  const boundary = createNativeConsequenceBoundary(configuration);
  return { boundary, aebStore, attempts, configuration };
}

function nativeInput(
  f: ReturnType<typeof nativeFixture>,
  operationId = 'operation:native:one',
  overrides: Record<string, unknown> = {},
) {
  return {
    operation_id: operationId,
    handoff: f.handoff,
    action: ACTION,
    ...overrides,
  };
}

test('direct native AIMS and COAZ PERMITs execute without a CAID or AEC evaluation', async () => {
  for (const system of ['aims', 'coaz'] as const) {
    const f = nativeFixture(system);
    let calls = 0;
    const h = makeNativeBoundary({
      f,
      localAuthorize: (context) => {
        assert.equal(context.verification.execution_authorizing, true);
        assert.equal(context.handoff.native_authorization.system, system);
        assert.match(context.local_authorization_program_digest, /^sha256:[0-9a-f]{64}$/);
        return true;
      },
      invoke: async (context) => {
        calls += 1;
        assert.equal(Object.hasOwn(context, 'caid'), false);
        assert.equal(Object.hasOwn(context, 'evaluation'), false);
        assert.equal(context.local_authorization.decision, 'PERMIT');
        assert.equal(
          context.local_authorization.program_digest,
          context.attempt.local_authorization_program_digest,
        );
        assert.equal(
          context.local_authorization.decision_digest,
          context.attempt.local_decision_digest,
        );
        assert.equal(
          context.authorization_program_digest,
          context.attempt.authorization_program_digest,
        );
        assert.equal(context.trust_snapshot_digest, context.attempt.trust_snapshot_digest);
        return { state: 'EXECUTED', evidence: executedEvidence(), result: { system } };
      },
    });
    const result = await h.boundary.run(nativeInput(f, `operation:native:${system}`));
    assert.equal(result.state, 'EXECUTED', system);
    assert.equal(calls, 1, system);
  }
});

test('direct native binding, source, freshness, and revocation failures stop before local policy and provider entry', async () => {
  const cases: Array<{
    name: string;
    prepare(f: ReturnType<typeof nativeFixture>): Record<string, unknown>;
    reason: string;
    now?: () => string;
    resolveStatus?: (f: ReturnType<typeof nativeFixture>) => unknown;
  }> = [
    {
      name: 'action',
      prepare: () => ({ action: { ...ACTION, amount: '5000.00' } }),
      reason: 'native_handoff_exact_action_mismatch',
    },
    {
      name: 'provider',
      prepare: (f) => ({
        handoff: issueNative(f, {
          provider: { ...PROVIDER, provider_account_id: 'account:other' },
        }),
      }),
      reason: 'native_handoff_provider_mismatch',
    },
    {
      name: 'audience',
      prepare: (f) => ({ handoff: issueNative(f, { audience: 'https://other.example/gate' }) }),
      reason: 'native_handoff_audience_mismatch',
    },
    {
      name: 'executor',
      prepare: (f) => ({ handoff: issueNative(f, { executor_id: 'executor:other' }) }),
      reason: 'native_handoff_executor_mismatch',
    },
    {
      name: 'source',
      prepare: (f) => ({
        handoff: issueNative(f, {
          native_authorization: {
            ...f.handoffInput.native_authorization,
            profile: 'authzen:untrusted-profile:1',
          },
        }),
      }),
      reason: 'native_handoff_source_not_pinned',
    },
    {
      name: 'freshness',
      prepare: () => ({}),
      now: () => '2026-08-09T12:03:00.000Z',
      reason: 'native_handoff_stale_or_not_current',
    },
    {
      // Status reaches the boundary only through the trusted resolver. These
      // resolver cases send well-formed run input so the resolver is reached.
      name: 'revocation',
      prepare: () => ({}),
      resolveStatus: (f) => ({ ...f.status, revoked: true }),
      reason: 'native_handoff_revoked',
    },
    {
      name: 'status-resolver-error',
      prepare: () => ({}),
      resolveStatus: () => { throw new Error('status source unavailable'); },
      reason: 'native_status_resolution_failed',
    },
    {
      name: 'status-resolver-invalid',
      prepare: () => ({}),
      resolveStatus: () => ({ revoked: false }),
      reason: 'native_handoff_revocation_status_invalid',
    },
    {
      // A caller cannot inject status: the extra member closes the input shape.
      name: 'caller-status-injection',
      prepare: (f) => ({ status: { ...f.status, revoked: false } }),
      resolveStatus: (f) => ({ ...f.status, revoked: true }),
      reason: 'native_execution_input_invalid',
    },
  ];
  for (const testCase of cases) {
    const f = nativeFixture();
    let localCalls = 0;
    let providerCalls = 0;
    let statusLookups = 0;
    const h = makeNativeBoundary({
      f,
      now: testCase.now ?? (() => NOW),
      resolveStatus: testCase.resolveStatus
        ? () => { statusLookups += 1; return testCase.resolveStatus!(f) as any; }
        : () => { statusLookups += 1; return f.status; },
      localAuthorize: () => { localCalls += 1; return true; },
      invoke: async () => {
        providerCalls += 1;
        return { state: 'EXECUTED', evidence: executedEvidence(), result: {} };
      },
    });
    const result = await h.boundary.run(nativeInput(
      f,
      `operation:native:mutation:${testCase.name}`,
      testCase.prepare(f),
    ));
    if (testCase.name.startsWith('status-') || testCase.name === 'revocation') {
      assert.equal(statusLookups, 1, `${testCase.name} must reach the trusted resolver`);
    }
    assert.equal(result.state, 'REFUSED', testCase.name);
    if (result.state === 'REFUSED') assert.equal(result.reason, testCase.reason, testCase.name);
    assert.equal(localCalls, 0, testCase.name);
    assert.equal(providerCalls, 0, testCase.name);
    assert.equal(h.aebStore.operations.size, 0, testCase.name);
  }
});

test('direct native local denial remains separate and blocks reservation and provider entry', async () => {
  const f = nativeFixture();
  let calls = 0;
  const h = makeNativeBoundary({
    f,
    localAuthorize: () => false,
    invoke: async () => {
      calls += 1;
      return { state: 'EXECUTED', evidence: executedEvidence(), result: {} };
    },
  });
  const result = await h.boundary.run(nativeInput(f));
  assert.equal(result.state, 'REFUSED');
  assert.equal(result.reason, 'local_authorization_denied');
  assert.equal(calls, 0);
});

test('direct native replay fencing is stable across operation IDs and concurrent dispatch', async () => {
  const f = nativeFixture();
  let calls = 0;
  const h = makeNativeBoundary({
    f,
    invoke: async () => {
      calls += 1;
      await new Promise((resolve) => setTimeout(resolve, 5));
      return { state: 'EXECUTED', evidence: executedEvidence(), result: { id: 'winner' } };
    },
  });
  const [first, second] = await Promise.all([
    h.boundary.run(nativeInput(f, 'operation:native:concurrent:one')),
    h.boundary.run(nativeInput(f, 'operation:native:concurrent:two')),
  ]);
  assert.equal(calls, 1);
  assert.deepEqual([first.state, second.state].sort(), ['EXECUTED', 'REFUSED']);
  const refusedResult = first.state === 'REFUSED' ? first : second;
  assert.equal(refusedResult.reason, 'native_replay_conflict');
});

test('post-entry throw, invalid result, and explicit uncertainty stay fenced against blind replay', async () => {
  for (const [name, outcome] of [
    ['throw', 'throw'],
    ['invalid', { state: 'EXECUTED', result: {} }],
    ['indeterminate', { state: 'INDETERMINATE', reason: 'provider_timeout' }],
  ] as const) {
    const f = nativeFixture();
    let calls = 0;
    const h = makeNativeBoundary({
      f,
      invoke: async () => {
        calls += 1;
        if (outcome === 'throw') throw new Error('response lost');
        return outcome as any;
      },
    });
    const first = await h.boundary.run(nativeInput(f, `operation:native:${name}:one`));
    assert.equal(first.state, 'INDETERMINATE', name);
    assert.equal(first.retry_allowed, false, name);
    const replay = await h.boundary.run(nativeInput(f, `operation:native:${name}:two`));
    assert.equal(replay.state, 'REFUSED', name);
    assert.equal(replay.reason, 'native_replay_conflict', name);
    assert.equal(calls, 1, name);
  }
});

test('direct native authenticated reconciliation closes uncertainty without re-invocation', async () => {
  const f = nativeFixture('oauth');
  let calls = 0;
  const h = makeNativeBoundary({
    f,
    invoke: async () => {
      calls += 1;
      throw new Error('provider accepted request but response was lost');
    },
  });
  const first = await h.boundary.run(nativeInput(f, 'operation:native:reconcile'));
  assert.equal(first.state, 'INDETERMINATE');
  assert.ok(first.attempt);
  assert.equal(calls, 1);

  const reconciled = await h.boundary.reconcile({
    operation_id: 'operation:native:reconcile',
    handoff: f.handoff,
    action: ACTION,
    attempt: first.attempt,
    outcome: {
      state: 'EXECUTED',
      evidence: executedEvidence(),
      result: { id: 'provider-confirmed' },
    },
    recovery_authorization: 'recovery:approved',
  });
  assert.equal(reconciled.state, 'EXECUTED');
  assert.equal(calls, 1);
  const replay = await h.boundary.run(nativeInput(f, 'operation:native:reconcile:replay'));
  assert.equal(replay.state, 'REFUSED');
  assert.equal(replay.reason, 'native_replay_conflict');
  assert.equal(calls, 1);
});

test('invalid direct-native handoffs never trigger the trusted status lookup', async () => {
  const f = nativeFixture();
  const tampered = structuredClone(f.handoff);
  tampered.signature.value = `${tampered.signature.value[0] === 'A' ? 'B' : 'A'}${tampered.signature.value.slice(1)}`;
  let statusLookups = 0;
  const h = makeNativeBoundary({
    f,
    resolveStatus: () => {
      statusLookups += 1;
      return f.status;
    },
  });
  const result = await h.boundary.run(nativeInput(f, 'operation:native:invalid-preflight', {
    handoff: tampered,
  }));
  assert.equal(result.state, 'REFUSED');
  assert.equal(statusLookups, 0);
});

test('untrusted replay-key input cannot poison another authorization', async () => {
  const f = nativeFixture();
  let calls = 0;
  const h = makeNativeBoundary({
    f,
    invoke: async () => {
      calls += 1;
      return { state: 'EXECUTED', evidence: executedEvidence(), result: {} };
    },
  });
  const poisoned = await h.boundary.run({
    ...nativeInput(f, 'operation:native:poisoned'),
    additional_replay_keys: ['aeb-native:victim'],
  } as any);
  assert.equal(poisoned.state, 'REFUSED');
  assert.equal(poisoned.reason, 'native_execution_input_invalid');
  assert.equal(calls, 0);

  const clean = await h.boundary.run(nativeInput(f, 'operation:native:clean'));
  assert.equal(clean.state, 'EXECUTED');
  assert.equal(calls, 1);
});

test('freshness and revocation are rechecked immediately before provider entry', async () => {
  const f = nativeFixture();
  const times = [
    '2026-08-09T12:00:01.000Z',
    '2026-08-09T12:00:02.000Z',
    '2026-08-09T12:00:33.000Z',
  ];
  let statusLookups = 0;
  let providerCalls = 0;
  const h = makeNativeBoundary({
    f,
    now: () => times.shift() ?? '2026-08-09T12:00:33.000Z',
    resolveStatus: () => {
      statusLookups += 1;
      return f.status;
    },
    invoke: async () => {
      providerCalls += 1;
      return { state: 'EXECUTED', evidence: executedEvidence(), result: {} };
    },
  });
  const result = await h.boundary.run(nativeInput(f, 'operation:native:toctou'));
  assert.equal(result.state, 'REFUSED');
  assert.equal(result.reason, 'native_handoff_revocation_status_not_current');
  assert.equal(statusLookups, 2);
  assert.equal(providerCalls, 0);
  assert.equal(h.aebStore.operations.size, 0);
  assert.equal([...h.attempts.rows.values()][0]?.state, 'RELEASED');
});

test('revocation during a delayed custody transition prevents provider entry', async () => {
  const f = nativeFixture();
  const attempts = attemptStore();
  const transition = attempts.transition.bind(attempts);
  let revoked = false;
  let providerCalls = 0;
  attempts.transition = async (entry: any) => {
    const result = await transition(entry);
    if (entry.expected_state === 'RESERVED' && entry.next_state === 'INVOKING') {
      revoked = true;
    }
    return result;
  };
  const h = makeNativeBoundary({
    f,
    attempts,
    resolveStatus: () => ({ ...f.status, revoked }),
    invoke: async () => {
      providerCalls += 1;
      return { state: 'EXECUTED', evidence: executedEvidence(), result: {} };
    },
  });
  const result = await h.boundary.run(nativeInput(f, 'operation:native:transition-delay'));
  assert.equal(result.state, 'REFUSED');
  assert.equal(result.reason, 'native_handoff_revoked');
  assert.equal(providerCalls, 0);
  assert.equal(h.aebStore.operations.size, 0);
  assert.equal([...attempts.rows.values()][0]?.state, 'RELEASED');
});

test('terminal provider evidence must pass the pinned verifier for the exact attempt binding', async () => {
  for (const mode of ['forged', 'wrong-operation'] as const) {
    const f = nativeFixture();
    let attestation: Record<string, unknown> | null = null;
    const h = makeNativeBoundary({
      f,
      invoke: async (context) => {
        const evidence = executedEvidence();
        attestation = {
          operation_id: mode === 'wrong-operation'
            ? 'operation:native:other'
            : context.operation_id,
          action_digest: context.action_digest,
          native_replay_unit: context.native_replay_unit,
          attempt_id: context.attempt.attempt_id,
          outcome: 'EXECUTED',
          evidence_digest: mode === 'forged'
            ? digestAeb({ forged: true })
            : evidence.evidence_digest,
        };
        return { state: 'EXECUTED', evidence, result: { id: mode } };
      },
      providerOutcomeVerify: (context) => attestation !== null
        && attestation.operation_id === context.operation_id
        && attestation.action_digest === context.action_digest
        && attestation.native_replay_unit === context.native_replay_unit
        && attestation.attempt_id === context.attempt.attempt_id
        && attestation.outcome === context.outcome.state
        && attestation.evidence_digest === context.outcome.evidence.evidence_digest
        && context.verification_program_digest
          === context.attempt.provider_outcome_verification_program_digest,
    });
    const result = await h.boundary.run(nativeInput(
      f,
      `operation:native:provider-auth:${mode}`,
    ));
    assert.equal(result.state, 'INDETERMINATE', mode);
    assert.equal(result.reason, 'provider_outcome_authentication_failed', mode);
    assert.equal([...h.aebStore.operations.values()][0], 'RESERVED', mode);
    assert.equal([...h.attempts.rows.values()][0]?.state, 'INDETERMINATE', mode);
  }
});

test('authenticated provider evidence closes a fully bound direct-native attempt', async () => {
  const f = nativeFixture();
  let attestation: Record<string, unknown> | null = null;
  const h = makeNativeBoundary({
    f,
    invoke: async (context) => {
      const evidence = executedEvidence();
      attestation = {
        operation_id: context.operation_id,
        action_digest: context.action_digest,
        native_replay_unit: context.native_replay_unit,
        attempt_id: context.attempt.attempt_id,
        outcome: 'EXECUTED',
        evidence_digest: evidence.evidence_digest,
      };
      return { state: 'EXECUTED', evidence, result: { id: 'authenticated' } };
    },
    providerOutcomeVerify: (context) => attestation !== null
      && attestation.operation_id === context.operation_id
      && attestation.action_digest === context.action_digest
      && attestation.native_replay_unit === context.native_replay_unit
      && attestation.attempt_id === context.attempt.attempt_id
      && attestation.outcome === context.outcome.state
      && attestation.evidence_digest === context.outcome.evidence.evidence_digest,
  });
  const result = await h.boundary.run(nativeInput(f, 'operation:native:provider-auth:valid'));
  assert.equal(result.state, 'EXECUTED');
  assert.equal([...h.aebStore.operations.values()][0], 'CONSUMED');
  assert.equal([...h.attempts.rows.values()][0]?.state, 'COMMITTED');
});

test('the provider cannot mutate a result after its verified outcome snapshot is accepted', async () => {
  const f = nativeFixture();
  const mutableResult = { id: 'verified-result', amount: '500.00' };
  const h = makeNativeBoundary({
    f,
    invoke: async () => ({
      state: 'EXECUTED',
      evidence: executedEvidence(),
      result: mutableResult,
    }),
    providerOutcomeVerify: (context) => context.outcome.state === 'EXECUTED'
      && context.outcome.result.id === 'verified-result'
      && context.outcome.result.amount === '500.00',
  });
  const result = await h.boundary.run(nativeInput(
    f,
    'operation:native:provider-result-snapshot',
  ));
  assert.equal(result.state, 'EXECUTED');
  mutableResult.id = 'mutated-after-verification';
  mutableResult.amount = '5000.00';
  if (result.state === 'EXECUTED') {
    assert.deepEqual(result.result, { id: 'verified-result', amount: '500.00' });
    assert.equal(Object.isFrozen(result.result), true);
  }
});

test('lost commit and terminal-write acknowledgements are closed from durable state', async () => {
  const f = nativeFixture();
  const aebStore = durableAebStore();
  const attempts = attemptStore();
  const commit = aebStore.commit.bind(aebStore);
  const terminal = attempts.reconcile.bind(attempts);
  let loseCommitAck = true;
  let loseTerminalAck = true;
  aebStore.commit = async (key: string) => {
    const result = await commit(key);
    if (loseCommitAck) {
      loseCommitAck = false;
      throw new Error('commit acknowledgement lost');
    }
    return result;
  };
  attempts.reconcile = async (entry: any) => {
    const result = await terminal(entry);
    if (loseTerminalAck) {
      loseTerminalAck = false;
      throw new Error('terminal acknowledgement lost');
    }
    return result;
  };
  const h = makeNativeBoundary({ f, aebStore, attempts });
  const result = await h.boundary.run(nativeInput(f, 'operation:native:lost-acks'));
  assert.equal(result.state, 'EXECUTED');
  assert.equal([...aebStore.operations.values()][0], 'CONSUMED');
  assert.equal([...attempts.rows.values()][0]?.state, 'COMMITTED');
});

test('reconciliation resumes after authorization closed but the first attempt write failed', async () => {
  const f = nativeFixture();
  const aebStore = durableAebStore();
  const attempts = attemptStore();
  const terminal = attempts.reconcile.bind(attempts);
  let failBeforeWrite = true;
  attempts.reconcile = async (entry: any) => {
    if (failBeforeWrite) {
      failBeforeWrite = false;
      throw new Error('attempt store unavailable before write');
    }
    return terminal(entry);
  };
  const h = makeNativeBoundary({ f, aebStore, attempts });
  const first = await h.boundary.run(nativeInput(f, 'operation:native:partial-close'));
  assert.equal(first.state, 'INDETERMINATE');
  assert.equal(first.reason, 'attempt_terminal_record_unconfirmed');
  assert.equal([...aebStore.operations.values()][0], 'CONSUMED');
  assert.equal([...attempts.rows.values()][0]?.state, 'INDETERMINATE');
  assert.ok(first.attempt);

  const reconciliation = {
    operation_id: 'operation:native:partial-close',
    handoff: f.handoff,
    action: ACTION,
    attempt: first.attempt,
    outcome: {
      state: 'EXECUTED' as const,
      evidence: executedEvidence(),
      result: { id: 'recovered' },
    },
    recovery_authorization: 'recovery:approved',
  };
  const closed = await h.boundary.reconcile(reconciliation);
  assert.equal(closed.state, 'EXECUTED');
  assert.equal([...attempts.rows.values()][0]?.state, 'COMMITTED');

  const repeated = await h.boundary.reconcile(reconciliation);
  assert.equal(repeated.state, 'EXECUTED');
});

test('reconciliation can freeze an invoking attempt after the first freeze write failed', async () => {
  const f = nativeFixture();
  const attempts = attemptStore();
  const transition = attempts.transition.bind(attempts);
  let failFreeze = true;
  attempts.transition = async (entry: any) => {
    if (failFreeze
        && entry.expected_state === 'INVOKING'
        && entry.next_state === 'INDETERMINATE') {
      failFreeze = false;
      throw new Error('freeze write did not land');
    }
    return transition(entry);
  };
  const h = makeNativeBoundary({
    f,
    attempts,
    invoke: async () => { throw new Error('provider response lost'); },
  });
  const first = await h.boundary.run(nativeInput(f, 'operation:native:freeze-recovery'));
  assert.equal(first.state, 'INDETERMINATE');
  assert.ok(first.attempt);
  assert.equal([...attempts.rows.values()][0]?.state, 'INVOKING');

  const closed = await h.boundary.reconcile({
    operation_id: 'operation:native:freeze-recovery',
    handoff: f.handoff,
    action: ACTION,
    attempt: first.attempt,
    outcome: {
      state: 'EXECUTED',
      evidence: executedEvidence(),
      result: { id: 'confirmed' },
    },
    recovery_authorization: 'recovery:approved',
  });
  assert.equal(closed.state, 'EXECUTED');
  assert.equal([...attempts.rows.values()][0]?.state, 'COMMITTED');
});

test('reconciliation uses the persisted historical trust snapshot after key rotation and restart', async () => {
  const old = nativeFixture('oauth');
  const aebStore = durableAebStore();
  const attempts = attemptStore();
  const firstBoundary = makeNativeBoundary({
    f: old,
    aebStore,
    attempts,
    trustSnapshotId: 'native-trust-snapshot:old:1',
    invoke: async () => { throw new Error('provider response lost'); },
  });
  const first = await firstBoundary.boundary.run(nativeInput(
    old,
    'operation:native:key-rotation',
  ));
  assert.equal(first.state, 'INDETERMINATE');
  assert.ok(first.attempt);

  const rotated = nativeFixture('oauth');
  let requestedSnapshot: string | null = null;
  // A restart is a new store instance over the same database: it owns no
  // reservation until reconciliation claims it through the recovery path.
  const restartedStore = durableAebStore(aebStore.db);
  const restarted = makeNativeBoundary({
    f: rotated,
    aebStore: restartedStore,
    attempts,
    trustSnapshotId: 'native-trust-snapshot:new:2',
    resolveHistoricalPins: ({ trust_snapshot_id }: any) => {
      requestedSnapshot = trust_snapshot_id;
      return trust_snapshot_id === 'native-trust-snapshot:old:1' ? old.pins : null;
    },
  });
  const result = await restarted.boundary.reconcile({
    operation_id: 'operation:native:key-rotation',
    handoff: old.handoff,
    action: ACTION,
    attempt: first.attempt,
    outcome: {
      state: 'EXECUTED',
      evidence: executedEvidence(),
      result: { id: 'confirmed-after-rotation' },
    },
    recovery_authorization: 'recovery:approved',
  });
  assert.equal(requestedSnapshot, 'native-trust-snapshot:old:1');
  assert.equal(result.state, 'EXECUTED');
  assert.equal(restartedStore.claims.length, 2, 'operation and action-fence holder claimed');
  assert.deepEqual([...aebStore.operations.values()].slice(0, 2), ['CONSUMED', 'CONSUMED']);
});

test('direct native security callbacks are pinned when the boundary is constructed', async () => {
  {
    const f = nativeFixture();
    let providerCalls = 0;
    const h = makeNativeBoundary({
      f,
      localAuthorize: () => false,
      invoke: async () => {
        providerCalls += 1;
        return { state: 'EXECUTED', evidence: executedEvidence(), result: {} };
      },
    });
    (h.configuration as any).local_authorize = () => true;
    const result = await h.boundary.run(nativeInput(f, 'operation:native:mutated-local-policy'));
    assert.equal(result.state, 'REFUSED');
    assert.equal(result.reason, 'local_authorization_denied');
    assert.equal(providerCalls, 0);
  }

  {
    const f = nativeFixture();
    let providerCalls = 0;
    const h = makeNativeBoundary({
      f,
      resolveStatus: () => ({ ...f.status, revoked: true }),
      invoke: async () => {
        providerCalls += 1;
        return { state: 'EXECUTED', evidence: executedEvidence(), result: {} };
      },
    });
    (h.configuration.native_authorization as any).resolve_status = () => f.status;
    const result = await h.boundary.run(nativeInput(f, 'operation:native:mutated-status'));
    assert.equal(result.state, 'REFUSED');
    assert.equal(result.reason, 'native_handoff_revoked');
    assert.equal(providerCalls, 0);
  }

  {
    const f = nativeFixture();
    let originalCalls = 0;
    let replacementCalls = 0;
    const h = makeNativeBoundary({
      f,
      invoke: async () => {
        originalCalls += 1;
        return { state: 'EXECUTED', evidence: executedEvidence(), result: { source: 'pinned' } };
      },
    });
    (h.configuration as any).invoke = async () => {
      replacementCalls += 1;
      return { state: 'EXECUTED', evidence: executedEvidence(), result: { source: 'replacement' } };
    };
    const result = await h.boundary.run(nativeInput(f, 'operation:native:mutated-invoke'));
    assert.equal(result.state, 'EXECUTED');
    assert.equal(originalCalls, 1);
    assert.equal(replacementCalls, 0);
    if (result.state === 'EXECUTED') assert.deepEqual(result.result, { source: 'pinned' });
  }

  {
    const f = nativeFixture();
    const h = makeNativeBoundary({ f, providerOutcomeVerify: () => false });
    (h.configuration.provider_outcomes as any).verify = () => true;
    const result = await h.boundary.run(nativeInput(
      f,
      'operation:native:mutated-provider-verifier',
    ));
    assert.equal(result.state, 'INDETERMINATE');
    assert.equal(result.reason, 'provider_outcome_authentication_failed');
  }
});

test('direct native recovery callbacks cannot be replaced after construction', async () => {
  {
    const f = nativeFixture();
    const aebStore = durableAebStore();
    const attempts = attemptStore();
    const first = makeNativeBoundary({
      f,
      aebStore,
      attempts,
      invoke: async () => { throw new Error('provider response lost'); },
    });
    const uncertain = await first.boundary.run(nativeInput(
      f,
      'operation:native:mutated-historical-pins',
    ));
    assert.equal(uncertain.state, 'INDETERMINATE');
    assert.ok(uncertain.attempt);

    const restarted = makeNativeBoundary({
      f,
      aebStore,
      attempts,
      resolveHistoricalPins: () => null,
    });
    (restarted.configuration.native_authorization as any).resolve_historical_pins = () => f.pins;
    const result = await restarted.boundary.reconcile({
      operation_id: 'operation:native:mutated-historical-pins',
      handoff: f.handoff,
      action: ACTION,
      attempt: uncertain.attempt,
      outcome: {
        state: 'EXECUTED',
        evidence: executedEvidence(),
        result: { id: 'must-not-close-under-replaced-trust-resolver' },
      },
      recovery_authorization: 'recovery:approved',
    });
    assert.equal(result.state, 'REFUSED');
    assert.equal(result.reason, 'native_historical_trust_snapshot_unavailable');
  }

  {
    const f = nativeFixture();
    const aebStore = durableAebStore();
    const attempts = attemptStore();
    const first = makeNativeBoundary({
      f,
      aebStore,
      attempts,
      invoke: async () => { throw new Error('provider response lost'); },
    });
    const uncertain = await first.boundary.run(nativeInput(
      f,
      'operation:native:mutated-recovery',
    ));
    assert.equal(uncertain.state, 'INDETERMINATE');
    assert.ok(uncertain.attempt);

    const restarted = makeNativeBoundary({
      f,
      aebStore,
      attempts,
      recover: () => null,
    });
    (restarted.configuration.attempts as any).recover = ({ attempt }: any) => {
      const row = attempts.rows.get(attempt.attempt_id);
      return row ? { ...structuredClone(row.binding), owner: row.owner } : null;
    };
    const result = await restarted.boundary.reconcile({
      operation_id: 'operation:native:mutated-recovery',
      handoff: f.handoff,
      action: ACTION,
      attempt: uncertain.attempt,
      outcome: {
        state: 'EXECUTED',
        evidence: executedEvidence(),
        result: { id: 'must-not-close-under-replaced-recovery' },
      },
      recovery_authorization: 'recovery:approved',
    });
    assert.equal(result.state, 'REFUSED');
    assert.equal(result.reason, 'attempt_recovery_refused');
  }
});

test('direct native durable-store methods are pinned when the boundary is constructed', async () => {
  const f = nativeFixture();
  const aebStore = durableAebStore();
  const attempts = attemptStore();
  const h = makeNativeBoundary({ f, aebStore, attempts });
  const replacementCalls: string[] = [];

  for (const name of ['reserve', 'commit', 'state'] as const) {
    const original = aebStore[name].bind(aebStore) as (...args: any[]) => any;
    (aebStore as any)[name] = (...args: any[]) => {
      replacementCalls.push(`consumption.${name}`);
      return original(...args);
    };
  }
  for (const name of ['reserve', 'transition', 'reconcile', 'state'] as const) {
    const original = attempts[name].bind(attempts) as (...args: any[]) => any;
    (attempts as any)[name] = (...args: any[]) => {
      replacementCalls.push(`attempt.${name}`);
      return original(...args);
    };
  }

  const result = await h.boundary.run(nativeInput(f, 'operation:native:mutated-stores'));
  assert.equal(result.state, 'EXECUTED');
  assert.deepEqual(replacementCalls, []);
});

test('direct native pre-entry release uses the store method pinned at construction', async () => {
  const f = nativeFixture();
  const aebStore = durableAebStore();
  const attempts = attemptStore();
  attempts.reserve = async () => ({ reserved: false as const, reason: 'attempt_policy_refused' });
  const h = makeNativeBoundary({ f, aebStore, attempts });
  const originalRelease = aebStore.release.bind(aebStore);
  let replacementCalls = 0;
  aebStore.release = async (...args: Parameters<typeof originalRelease>) => {
    replacementCalls += 1;
    return originalRelease(...args);
  };

  const result = await h.boundary.run(nativeInput(f, 'operation:native:mutated-release'));
  assert.equal(result.state, 'REFUSED');
  assert.equal(result.reason, 'attempt_policy_refused');
  assert.equal(replacementCalls, 0);
});

// ---------------------------------------------------------------------------
// Same-action in-flight fence, relabel-invariant replay identity, recovery
// after restart, and hostile in-process inputs (PR #788 follow-up).
// ---------------------------------------------------------------------------

function nativeStatusFor(
  f: ReturnType<typeof nativeFixture>,
  handoff: { gateway_id: string; native_authorization: unknown; revocation_id: string },
) {
  return {
    ...f.status,
    gateway_id: handoff.gateway_id,
    native_authorization: handoff.native_authorization,
    revocation_id: handoff.revocation_id,
  };
}

function freshAuthorization(f: ReturnType<typeof nativeFixture>, suffix: string, overrides: Record<string, unknown> = {}) {
  return issueNative(f, {
    native_authorization: {
      ...f.handoffInput.native_authorization,
      authorization_id: `native-authz:fresh:${suffix}`,
    },
    revocation_id: `revocation:fresh:${suffix}`,
    ...overrides,
  });
}

function providerOutcomeFor(calls: number) {
  return {
    evidence_id: `provider-evidence:call-${calls}`,
    observed_at: '2026-08-09T12:00:02.000Z',
    evidence_digest: digestAeb({ provider: 'bank', call: calls }),
  };
}

test('a fresh native authorization cannot re-enter the provider while the same action is INDETERMINATE', async () => {
  // Regression for the C1 probe: before the fence this returned
  // INDETERMINATE, then EXECUTED, with two provider calls.
  const f = nativeFixture();
  let calls = 0;
  const h = makeNativeBoundary({
    f,
    resolveStatus: (handoff: any) => nativeStatusFor(f, handoff),
    invoke: async () => {
      calls += 1;
      if (calls === 1) throw new Error('provider timeout');
      return { state: 'EXECUTED' as const, evidence: providerOutcomeFor(calls), result: {} };
    },
  });
  const first = await h.boundary.run(nativeInput(f, 'operation:native:fence:1'));
  assert.equal(first.state, 'INDETERMINATE');
  assert.equal(first.reason, 'provider_outcome_indeterminate');

  const second = await h.boundary.run({
    operation_id: 'operation:native:fence:2',
    handoff: freshAuthorization(f, '124'),
    action: ACTION,
  });
  assert.equal(second.state, 'REFUSED');
  assert.equal(second.reason, 'native_action_in_flight');
  assert.equal(calls, 1);
  // The refused attempt handed its own operation reservation back: only the
  // first attempt's operation and fence-holder reservations remain.
  assert.deepEqual([...h.aebStore.operations.values()], ['RESERVED', 'RESERVED']);

  const reconciled = await h.boundary.reconcile({
    operation_id: 'operation:native:fence:1',
    handoff: f.handoff,
    action: ACTION,
    attempt: first.attempt,
    outcome: { state: 'EXECUTED', evidence: providerOutcomeFor(1), result: {} },
    recovery_authorization: 'recovery:approved',
  });
  assert.equal(reconciled.state, 'EXECUTED');

  const third = await h.boundary.run({
    operation_id: 'operation:native:fence:3',
    handoff: freshAuthorization(f, '125'),
    action: ACTION,
  });
  assert.equal(third.state, 'REFUSED');
  assert.equal(third.reason, 'native_action_already_executed');
  assert.equal(calls, 1);
});

test('concurrent fresh authorizations for one exact action enter the provider once', async () => {
  const f = nativeFixture();
  let calls = 0;
  const h = makeNativeBoundary({
    f,
    resolveStatus: (handoff: any) => nativeStatusFor(f, handoff),
    invoke: async () => {
      calls += 1;
      await new Promise((resolve) => setTimeout(resolve, 5));
      return { state: 'EXECUTED' as const, evidence: providerOutcomeFor(calls), result: {} };
    },
  });
  const results = await Promise.all(Array.from({ length: 6 }, (_, index) => h.boundary.run({
    operation_id: `operation:native:fence:concurrent:${index}`,
    handoff: freshAuthorization(f, `concurrent-${index}`),
    action: ACTION,
  })));
  assert.equal(calls, 1);
  assert.equal(results.filter((result) => result.state === 'EXECUTED').length, 1);
  for (const result of results) {
    if (result.state === 'REFUSED') {
      assert.ok(['native_action_in_flight', 'native_action_already_executed'].includes(result.reason));
    }
  }
});

test('an authenticated FAILED releases the action fence but keeps the spent authorization burned', async () => {
  const f = nativeFixture();
  let calls = 0;
  const h = makeNativeBoundary({
    f,
    resolveStatus: (handoff: any) => nativeStatusFor(f, handoff),
    invoke: async () => {
      calls += 1;
      return calls === 1
        ? { state: 'FAILED' as const, evidence: providerOutcomeFor(calls), reason: 'insufficient_funds' }
        : { state: 'EXECUTED' as const, evidence: providerOutcomeFor(calls), result: { retry: true } };
    },
  });
  const failed = await h.boundary.run(nativeInput(f, 'operation:native:fence:failed:1'));
  assert.equal(failed.state, 'FAILED');

  const sameAuthority = await h.boundary.run(nativeInput(f, 'operation:native:fence:failed:2'));
  assert.equal(sameAuthority.state, 'REFUSED');
  assert.equal(sameAuthority.reason, 'native_replay_conflict');

  const retried = await h.boundary.run({
    operation_id: 'operation:native:fence:failed:3',
    handoff: freshAuthorization(f, 'after-failed'),
    action: ACTION,
  });
  assert.equal(retried.state, 'EXECUTED');
  assert.equal(calls, 2);
});

test('reconciliation to an authenticated FAILED releases the fence; reconciliation to EXECUTED keeps it', async () => {
  for (const terminal of ['FAILED', 'EXECUTED'] as const) {
    const f = nativeFixture();
    let calls = 0;
    const h = makeNativeBoundary({
      f,
      resolveStatus: (handoff: any) => nativeStatusFor(f, handoff),
      invoke: async () => {
        calls += 1;
        if (calls === 1) throw new Error('response lost');
        return { state: 'EXECUTED' as const, evidence: providerOutcomeFor(calls), result: {} };
      },
    });
    const first = await h.boundary.run(nativeInput(f, `operation:native:fence:reconcile:${terminal}`));
    assert.equal(first.state, 'INDETERMINATE', terminal);
    const reconciled = await h.boundary.reconcile({
      operation_id: `operation:native:fence:reconcile:${terminal}`,
      handoff: f.handoff,
      action: ACTION,
      attempt: first.attempt,
      outcome: terminal === 'FAILED'
        ? { state: 'FAILED', evidence: providerOutcomeFor(1), reason: 'provider_declined' }
        : { state: 'EXECUTED', evidence: providerOutcomeFor(1), result: {} },
      recovery_authorization: 'recovery:approved',
    });
    assert.equal(reconciled.state, terminal, terminal);
    const retry = await h.boundary.run({
      operation_id: `operation:native:fence:reconcile:${terminal}:retry`,
      handoff: freshAuthorization(f, `reconcile-${terminal}`),
      action: ACTION,
    });
    if (terminal === 'FAILED') {
      assert.equal(retry.state, 'EXECUTED', terminal);
      assert.equal(calls, 2, terminal);
    } else {
      assert.equal(retry.state, 'REFUSED', terminal);
      assert.equal(retry.reason, 'native_action_already_executed', terminal);
      assert.equal(calls, 1, terminal);
    }
  }
});

test('an intentional repeat differs in the canonical action and is not fenced', async () => {
  const f = nativeFixture();
  let calls = 0;
  const second = { ...ACTION, transfer_id: 'transfer-2' };
  const h = makeNativeBoundary({
    f,
    resolveStatus: (handoff: any) => nativeStatusFor(f, handoff),
    invoke: async () => {
      calls += 1;
      if (calls === 1) throw new Error('provider timeout');
      return { state: 'EXECUTED' as const, evidence: providerOutcomeFor(calls), result: {} };
    },
  });
  const first = await h.boundary.run(nativeInput(f, 'operation:native:instance:1'));
  assert.equal(first.state, 'INDETERMINATE');
  const repeat = await h.boundary.run({
    operation_id: 'operation:native:instance:2',
    handoff: freshAuthorization(f, 'instance-2', { action: second }),
    action: second,
  });
  assert.equal(repeat.state, 'EXECUTED');
  assert.equal(calls, 2);
});

test('a pre-entry refusal releases the action fence for a later authorization', async () => {
  const f = nativeFixture();
  let lookups = 0;
  let calls = 0;
  const h = makeNativeBoundary({
    f,
    resolveStatus: (handoff: any) => {
      lookups += 1;
      // The provider-entry recheck of the first attempt sees a revocation.
      return { ...nativeStatusFor(f, handoff), revoked: lookups === 2 };
    },
    invoke: async () => {
      calls += 1;
      return { state: 'EXECUTED' as const, evidence: providerOutcomeFor(calls), result: {} };
    },
  });
  const refusedAtEntry = await h.boundary.run(nativeInput(f, 'operation:native:fence:pre-entry'));
  assert.equal(refusedAtEntry.state, 'REFUSED');
  assert.equal(refusedAtEntry.reason, 'native_handoff_revoked');
  assert.equal(h.aebStore.operations.size, 0);
  const later = await h.boundary.run({
    operation_id: 'operation:native:fence:pre-entry:later',
    handoff: freshAuthorization(f, 'pre-entry-later'),
    action: ACTION,
  });
  assert.equal(later.state, 'EXECUTED');
  assert.equal(calls, 1);
});

test('the action fence is durable across a process restart', async () => {
  const f = nativeFixture();
  const aebStore = durableAebStore();
  const attempts = attemptStore();
  const first = makeNativeBoundary({
    f,
    aebStore,
    attempts,
    invoke: async () => { throw new Error('process died after provider entry'); },
  });
  const uncertain = await first.boundary.run(nativeInput(f, 'operation:native:fence:restart'));
  assert.equal(uncertain.state, 'INDETERMINATE');

  let calls = 0;
  const restarted = makeNativeBoundary({
    f,
    aebStore: durableAebStore(aebStore.db),
    attempts,
    resolveStatus: (handoff: any) => nativeStatusFor(f, handoff),
    invoke: async () => {
      calls += 1;
      return { state: 'EXECUTED' as const, evidence: providerOutcomeFor(calls), result: {} };
    },
  });
  const retry = await restarted.boundary.run({
    operation_id: 'operation:native:fence:restart:retry',
    handoff: freshAuthorization(f, 'restart'),
    action: ACTION,
  });
  assert.equal(retry.state, 'REFUSED');
  assert.equal(retry.reason, 'native_action_in_flight');
  assert.equal(calls, 0);
});

test('one native grant relabelled under a second pinned profile or system is one spend', async () => {
  // Regression for the C2 probe: before the fix this returned EXECUTED twice.
  for (const relabel of ['profile', 'system'] as const) {
    for (const sameAction of [true, false]) {
      const f = nativeFixture();
      const source = f.handoffInput.native_authorization;
      const relabelled = relabel === 'profile'
        ? { ...source, profile: 'authzen:exact-action-result:2' }
        : { ...source, system: 'coaz', profile: 'coaz:exact-action-result:1' };
      f.pins.accepted_sources.push({
        ...f.pins.accepted_sources[0],
        system: relabelled.system,
        profile: relabelled.profile,
      });
      const otherAction = sameAction ? ACTION : { ...ACTION, transfer_id: 'transfer-relabel' };
      let calls = 0;
      const h = makeNativeBoundary({
        f,
        resolveStatus: (handoff: any) => nativeStatusFor(f, handoff),
        invoke: async () => {
          calls += 1;
          return { state: 'EXECUTED' as const, evidence: providerOutcomeFor(calls), result: {} };
        },
      });
      const label = `${relabel}:${sameAction ? 'same-action' : 'other-action'}`;
      const first = await h.boundary.run(nativeInput(f, `operation:native:relabel:${label}:1`));
      assert.equal(first.state, 'EXECUTED', label);
      const relabelledHandoff = issueNative(f, { native_authorization: relabelled, action: otherAction });
      const second = await h.boundary.run({
        operation_id: `operation:native:relabel:${label}:2`,
        handoff: relabelledHandoff,
        action: otherAction,
      });
      assert.equal(second.state, 'REFUSED', label);
      assert.equal(second.reason, 'native_replay_conflict', label);
      assert.equal(calls, 1, label);
      // The relabelled grant derives the same replay unit, so with the same
      // action it would also carry the same provider idempotency key.
      const relabelledVerification = verifyAebNativeAuthorizationHandoff(relabelledHandoff, {
        mode: 'historical',
        pins: f.pins,
        expected_action: otherAction,
        now: NOW,
      });
      assert.equal(relabelledVerification.valid, true, label);
      if (first.state === 'EXECUTED') {
        assert.equal(relabelledVerification.native_replay_unit, first.attempt.native_replay_unit, label);
        assert.equal(
          nativeConsequenceBoundaryProviderIdempotencyKey({
            provider: PROVIDER,
            action_digest: first.attempt.action_digest,
            native_replay_unit: relabelledVerification.native_replay_unit!,
          }),
          first.attempt.provider_idempotency_key,
          label,
        );
      }
    }
  }
});

test('explicit distinct authority namespaces are an operator opt-in; mixed declarations are refused', async () => {
  {
    const f = nativeFixture();
    const source = f.handoffInput.native_authorization;
    f.pins.accepted_sources[0].authority_namespace = 'namespace:decisions';
    f.pins.accepted_sources.push({
      ...f.pins.accepted_sources[0],
      profile: 'authzen:exact-action-result:2',
      authority_namespace: 'namespace:grants',
    });
    const other = { ...ACTION, transfer_id: 'transfer-namespace' };
    let calls = 0;
    const h = makeNativeBoundary({
      f,
      resolveStatus: (handoff: any) => nativeStatusFor(f, handoff),
      invoke: async () => {
        calls += 1;
        return { state: 'EXECUTED' as const, evidence: providerOutcomeFor(calls), result: {} };
      },
    });
    assert.equal((await h.boundary.run(nativeInput(f, 'operation:native:namespace:1'))).state, 'EXECUTED');
    const second = await h.boundary.run({
      operation_id: 'operation:native:namespace:2',
      handoff: issueNative(f, {
        native_authorization: { ...source, profile: 'authzen:exact-action-result:2' },
        action: other,
      }),
      action: other,
    });
    assert.equal(second.state, 'EXECUTED');
    assert.equal(calls, 2);
  }
  {
    const f = nativeFixture();
    f.pins.accepted_sources.push({
      ...f.pins.accepted_sources[0],
      profile: 'authzen:exact-action-result:2',
      authority_namespace: 'namespace:grants',
    });
    let calls = 0;
    const h = makeNativeBoundary({
      f,
      invoke: async () => {
        calls += 1;
        return { state: 'EXECUTED' as const, evidence: providerOutcomeFor(calls), result: {} };
      },
    });
    const result = await h.boundary.run(nativeInput(f, 'operation:native:namespace:mixed'));
    assert.equal(result.state, 'REFUSED');
    assert.equal(result.reason, 'native_handoff_schema_invalid');
    assert.equal(calls, 0);
  }
});

test('reconciling a never-entered RELEASED attempt is refused and cannot burn a later attempt', async () => {
  // Regression for H4e-burn: the reconcile used to commit attempt 2's live
  // reservation of the same operation key with zero provider calls.
  const f = nativeFixture();
  const aebStore = durableAebStore();
  const attempts = attemptStore();
  let lookups = 0;
  let calls = 0;
  let unblock: () => void = () => {};
  const blocked = new Promise<void>((resolve) => { unblock = resolve; });
  const h = makeNativeBoundary({
    f,
    aebStore,
    attempts,
    resolveStatus: async (handoff: any) => {
      lookups += 1;
      if (lookups === 2) throw new Error('status service timeout');
      if (lookups === 5) { await blocked; throw new Error('status service timeout'); }
      return nativeStatusFor(f, handoff);
    },
    providerOutcomeVerify: () => true,
    invoke: async () => {
      calls += 1;
      return { state: 'EXECUTED' as const, evidence: providerOutcomeFor(calls), result: {} };
    },
  });
  const first = await h.boundary.run(nativeInput(f, 'operation:native:burn'));
  assert.equal(first.state, 'REFUSED');
  const released = [...attempts.rows.values()][0];
  assert.equal(released.state, 'RELEASED');

  const second = h.boundary.run(nativeInput(f, 'operation:native:burn'));
  await new Promise((resolve) => setTimeout(resolve, 10));
  const reservedBySecond = [...aebStore.operations.values()];
  assert.deepEqual(reservedBySecond, ['RESERVED', 'RESERVED']);

  const reconciled = await h.boundary.reconcile({
    operation_id: 'operation:native:burn',
    handoff: f.handoff,
    action: ACTION,
    attempt: released.binding,
    outcome: {
      state: 'FAILED',
      evidence: providerOutcomeFor(99),
      reason: 'no_such_operation',
    },
    recovery_authorization: 'recovery:approved',
  });
  assert.equal(reconciled.state, 'REFUSED');
  assert.equal(reconciled.reason, 'attempt_never_entered_provider');
  assert.deepEqual([...aebStore.operations.values()], ['RESERVED', 'RESERVED']);

  unblock();
  assert.equal((await second).state, 'REFUSED');
  const third = await h.boundary.run(nativeInput(f, 'operation:native:burn:new'));
  assert.equal(third.state, 'EXECUTED');
  assert.equal(calls, 1);
});

test('reservations stay held when a pre-entry attempt release is unconfirmed', async () => {
  const f = nativeFixture();
  const attempts = attemptStore();
  const transition = attempts.transition.bind(attempts);
  attempts.transition = async (entry: any) => {
    if (entry.next_state === 'RELEASED') throw new Error('attempt store unavailable');
    return transition(entry);
  };
  let lookups = 0;
  let calls = 0;
  const h = makeNativeBoundary({
    f,
    attempts,
    resolveStatus: (handoff: any) => {
      lookups += 1;
      return { ...nativeStatusFor(f, handoff), revoked: lookups === 2 };
    },
    invoke: async () => {
      calls += 1;
      return { state: 'EXECUTED' as const, evidence: providerOutcomeFor(calls), result: {} };
    },
  });
  const first = await h.boundary.run(nativeInput(f, 'operation:native:release-unconfirmed'));
  assert.equal(first.state, 'INDETERMINATE');
  assert.equal(first.reason, 'native_pre_entry_release_unconfirmed');
  assert.equal(first.invoked, false);
  // The attempt is still RESERVED, so its operation key and fence stay held.
  assert.deepEqual([...h.aebStore.operations.values()], ['RESERVED', 'RESERVED']);
  const reuse = await h.boundary.run(nativeInput(f, 'operation:native:release-unconfirmed'));
  assert.equal(reuse.state, 'REFUSED');
  assert.equal(reuse.reason, 'consumption_conflict');
  assert.equal(calls, 0);
});

test('a reconcile outcome that conflicts with the terminal record changes nothing', async () => {
  const f = nativeFixture();
  const h = makeNativeBoundary({
    f,
    resolveStatus: (handoff: any) => nativeStatusFor(f, handoff),
    invoke: async () => { throw new Error('response lost'); },
  });
  const first = await h.boundary.run(nativeInput(f, 'operation:native:conflict'));
  assert.equal(first.state, 'INDETERMINATE');
  const base = {
    operation_id: 'operation:native:conflict',
    handoff: f.handoff,
    action: ACTION,
    attempt: first.attempt,
    recovery_authorization: 'recovery:approved',
  };
  const executed = await h.boundary.reconcile({
    ...base,
    outcome: { state: 'EXECUTED', evidence: providerOutcomeFor(1), result: {} },
  });
  assert.equal(executed.state, 'EXECUTED');
  const flipped = await h.boundary.reconcile({
    ...base,
    outcome: { state: 'FAILED', evidence: providerOutcomeFor(2), reason: 'declined' },
  });
  assert.equal(flipped.state, 'REFUSED');
  assert.equal(flipped.reason, 'reconciliation_outcome_conflict');
  const retry = await h.boundary.run({
    operation_id: 'operation:native:conflict:retry',
    handoff: freshAuthorization(f, 'conflict'),
    action: ACTION,
  });
  assert.equal(retry.state, 'REFUSED');
  assert.equal(retry.reason, 'native_action_already_executed');
});

test('a relying party ID outside the Gate identifier grammar is refused at construction', () => {
  for (const relyingPartyId of ['rp', 'rp:payments#eu', `rp:${'a'.repeat(300)}`]) {
    const f = nativeFixture();
    f.pins.relying_party_id = relyingPartyId;
    assert.throws(
      () => makeNativeBoundary({ f }),
      /native_consequence_boundary_configuration_invalid/,
      relyingPartyId.slice(0, 24),
    );
  }
  assert.throws(
    () => nativeConsequenceBoundaryActionFenceKey({
      relying_party_id: 'rp:payments#eu',
      provider: PROVIDER,
      action_digest: digestAeb({ action: 1 }),
    }),
    /native_action_fence_binding_invalid/,
  );
});

test('hostile in-process run and reconcile inputs refuse with a reason instead of throwing', async () => {
  const f = nativeFixture();
  let calls = 0;
  const h = makeNativeBoundary({
    f,
    invoke: async () => {
      calls += 1;
      throw new Error('response lost');
    },
  });
  const protoRun = JSON.parse(`{"operation_id":"operation:native:proto","handoff":${JSON.stringify(f.handoff)},"action":${JSON.stringify(ACTION)},"__proto__":{"status":{"revoked":false}}}`);
  const getterRun = Object.defineProperty(
    { handoff: f.handoff, action: ACTION },
    'operation_id',
    { get() { throw new Error('getter'); }, enumerable: true },
  );
  const proxyRun = new Proxy(
    { operation_id: 'operation:native:proxy', handoff: f.handoff, action: ACTION },
    { getOwnPropertyDescriptor() { throw new Error('trap'); } },
  );
  const getTrapRun = new Proxy(
    { operation_id: 'operation:native:get-trap', handoff: f.handoff, action: ACTION },
    { get(target, key) { if (key === 'handoff') throw new Error('trap'); return (target as any)[key]; } },
  );
  const nestedProxyRun = {
    operation_id: 'operation:native:nested-proxy',
    handoff: f.handoff,
    action: new Proxy({ ...ACTION }, {}),
  };
  for (const [name, value] of Object.entries({
    protoRun, getterRun, proxyRun, getTrapRun, nestedProxyRun,
  })) {
    const result = await h.boundary.run(value as any);
    assert.equal(result.state, 'REFUSED', name);
    assert.equal(result.reason, 'native_execution_input_invalid', name);
  }
  assert.equal(calls, 0);

  const uncertain = await h.boundary.run(nativeInput(f, 'operation:native:hostile-reconcile'));
  assert.equal(uncertain.state, 'INDETERMINATE');
  const good = {
    operation_id: 'operation:native:hostile-reconcile',
    handoff: f.handoff,
    action: ACTION,
    attempt: uncertain.attempt,
    outcome: { state: 'EXECUTED', evidence: executedEvidence(), result: {} },
    recovery_authorization: 'recovery:approved',
  };
  const outcomeGetter = Object.defineProperty({ ...good }, 'outcome', {
    get() { throw new Error('getter'); },
    enumerable: true,
  });
  const proxyOutcome = new Proxy({ ...good }, {
    getOwnPropertyDescriptor(target, key) {
      if (key === 'outcome') throw new Error('trap');
      return Reflect.getOwnPropertyDescriptor(target, key);
    },
  });
  const protoReconcile = JSON.parse(JSON.stringify({ ...good, attempt: uncertain.attempt })
    .replace(/^\{/, '{"__proto__":{"recovery_authorization":"recovery:approved"},'));
  const extraMember = { ...good, status: { revoked: false } };
  for (const [name, value] of Object.entries({
    outcomeGetter, proxyOutcome, protoReconcile, extraMember,
  })) {
    const result = await h.boundary.reconcile(value as any);
    assert.equal(result.state, 'REFUSED', name);
    assert.equal(result.reason, 'native_reconciliation_input_invalid', name);
  }
  const closed = await h.boundary.reconcile(good as any);
  assert.equal(closed.state, 'EXECUTED');
});

test('a hostile attempt-store reservation answer refuses and hands both reservations back', async () => {
  const f = nativeFixture();
  const attempts = attemptStore();
  (attempts as any).reserve = async () => Object.defineProperty({}, 'reserved', {
    get() { throw new Error('getter'); },
    enumerable: true,
  });
  let calls = 0;
  const h = makeNativeBoundary({
    f,
    attempts,
    invoke: async () => {
      calls += 1;
      return { state: 'EXECUTED' as const, evidence: executedEvidence(), result: {} };
    },
  });
  const result = await h.boundary.run(nativeInput(f, 'operation:native:hostile-attempt-store'));
  assert.equal(result.state, 'REFUSED');
  assert.equal(result.reason, 'attempt_conflict');
  assert.equal(h.aebStore.operations.size, 0);
  assert.equal(calls, 0);
});

test('an unconfirmed fence release after FAILED stays reconcilable and never opens a second entry early', async () => {
  const f = nativeFixture();
  const aebStore = durableAebStore();
  const release = aebStore.release.bind(aebStore);
  let failHolderRelease = true;
  aebStore.release = async (key: string) => {
    if (failHolderRelease && key.startsWith('aeb-native-action-holder:')) {
      failHolderRelease = false;
      throw new Error('store unavailable before write');
    }
    return release(key);
  };
  let calls = 0;
  const h = makeNativeBoundary({
    f,
    aebStore,
    resolveStatus: (handoff: any) => nativeStatusFor(f, handoff),
    invoke: async () => {
      calls += 1;
      return calls === 1
        ? { state: 'FAILED' as const, evidence: providerOutcomeFor(calls), reason: 'declined' }
        : { state: 'EXECUTED' as const, evidence: providerOutcomeFor(calls), result: {} };
    },
  });
  const first = await h.boundary.run(nativeInput(f, 'operation:native:fence-release-lost'));
  assert.equal(first.state, 'INDETERMINATE');
  assert.equal(first.reason, 'native_action_fence_release_unconfirmed');
  assert.equal([...h.attempts.rows.values()][0]?.state, 'INDETERMINATE');

  const early = await h.boundary.run({
    operation_id: 'operation:native:fence-release-lost:early',
    handoff: freshAuthorization(f, 'release-lost-early'),
    action: ACTION,
  });
  assert.equal(early.state, 'REFUSED');
  assert.equal(early.reason, 'native_action_in_flight');

  // A later provider lookup carries different evidence; the attempt is still
  // INDETERMINATE, so any authenticated FAILED closes it.
  const reconciled = await h.boundary.reconcile({
    operation_id: 'operation:native:fence-release-lost',
    handoff: f.handoff,
    action: ACTION,
    attempt: first.attempt,
    outcome: { state: 'FAILED', evidence: providerOutcomeFor(42), reason: 'declined' },
    recovery_authorization: 'recovery:approved',
  });
  assert.equal(reconciled.state, 'FAILED');
  const retried = await h.boundary.run({
    operation_id: 'operation:native:fence-release-lost:retry',
    handoff: freshAuthorization(f, 'release-lost-retry'),
    action: ACTION,
  });
  assert.equal(retried.state, 'EXECUTED');
  assert.equal(calls, 2);
});
