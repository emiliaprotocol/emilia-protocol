// SPDX-License-Identifier: Apache-2.0

import assert from 'node:assert/strict';
import { generateKeyPairSync, randomBytes } from 'node:crypto';
import type { KeyObject } from 'node:crypto';
import { describe, it } from 'node:test';
import {
  CONSEQUENCE_ACTUATOR_ENVELOPE_VERSION,
  CONSEQUENCE_ACTUATOR_SQL,
  ConsequenceActuator,
  createMemoryConsequenceActuatorStore,
  createPostgresConsequenceActuatorStore,
  signConsequenceExecutionEnvelope,
  type ConsequenceActuatorConsumption,
  type ConsequenceActuatorPgQueryResult,
  type ConsequenceActuatorReservation,
  type ConsequenceExecutionEnvelopePayload,
} from './src/consequence-actuator.ts';

const NOW = Date.parse('2026-07-25T01:00:00.000Z');
const ACTION_DIGEST = `sha256:${'a'.repeat(64)}`;
const OTHER_ACTION_DIGEST = `sha256:${'b'.repeat(64)}`;
const TARGET_DIGEST = `sha256:${'c'.repeat(64)}`;
const OTHER_TARGET_DIGEST = `sha256:${'d'.repeat(64)}`;
const CAID = `caid:1:example.execute.1:jcs-sha256:${'A'.repeat(43)}`;

function payload(
  overrides: Partial<ConsequenceExecutionEnvelopePayload> = {},
): ConsequenceExecutionEnvelopePayload {
  return {
    '@version': CONSEQUENCE_ACTUATOR_ENVELOPE_VERSION,
    issuer_id: 'authorization-service',
    tenant_id: 'tenant-1',
    attempt_id: 'attempt-1',
    action_digest: ACTION_DIGEST,
    caid: CAID,
    provider_account_id: 'provider-account-1',
    target_digest: TARGET_DIGEST,
    operation: 'payment.capture',
    idempotency_key: 'operation-1',
    nonce: randomBytes(24).toString('base64url'),
    issued_at: new Date(NOW - 1_000).toISOString(),
    expires_at: new Date(NOW + 30_000).toISOString(),
    ...overrides,
  };
}

function harness() {
  const signer = generateKeyPairSync('ed25519');
  const store = createMemoryConsequenceActuatorStore();
  const providerCredential = Object.freeze({ token: 'provider-secret' });
  const calls = { count: 0 };
  const providerCall = async (
    binding: Readonly<ConsequenceExecutionEnvelopePayload>,
  ) => {
    calls.count += 1;
    assert.equal(providerCredential.token, 'provider-secret');
    assert.equal(Object.hasOwn(binding, 'credential'), false);
    assert.equal(Object.isFrozen(binding), true);
    return { provider_reference: 'provider-result-1' };
  };
  const actuator = new ConsequenceActuator({
    pins: {
      tenantId: 'tenant-1',
      caid: CAID,
      providerAccountId: 'provider-account-1',
      targetDigest: TARGET_DIGEST,
      operation: 'payment.capture',
      envelopeIssuerId: 'authorization-service',
      envelopeKeyId: 'actuator-key-1',
      envelopePublicKey: signer.publicKey,
      maxEnvelopeTtlMs: 60_000,
      clockSkewMs: 2_000,
    },
    store,
    perform: providerCall,
    now: () => NOW,
  });
  return { actuator, calls, signer, store };
}

function signEnvelope(
  signer: { privateKey: KeyObject; publicKey: KeyObject },
  body: ConsequenceExecutionEnvelopePayload,
  keyId = 'actuator-key-1',
) {
  return signConsequenceExecutionEnvelope(body, {
    privateKey: signer.privateKey,
    keyId,
  });
}

function reservation(
  overrides: Partial<ConsequenceActuatorReservation> = {},
): ConsequenceActuatorReservation {
  return {
    tenantId: 'tenant-1',
    attemptId: 'attempt-1',
    actionDigest: ACTION_DIGEST,
    caid: CAID,
    providerAccountId: 'provider-account-1',
    targetDigest: TARGET_DIGEST,
    operation: 'payment.capture',
    idempotencyKey: 'operation-1',
    nonce: randomBytes(24).toString('base64url'),
    issuedAt: new Date(NOW - 1_000).toISOString(),
    expiresAt: new Date(NOW + 30_000).toISOString(),
    envelopeDigest: `sha256:${'e'.repeat(64)}`,
    ...overrides,
  };
}

describe('credential-owning consequence actuator', () => {
  it('pins trust and provider routing immutably and executes without a Gate-held credential', async () => {
    const { actuator, calls, signer, store } = harness();
    const body = payload();
    const envelope = signEnvelope(signer, body);

    assert.equal(Object.isFrozen(actuator.pins), true);
    assert.equal(Reflect.set(actuator.pins, 'targetDigest', OTHER_TARGET_DIGEST), false);
    assert.equal(actuator.pins.targetDigest, TARGET_DIGEST);
    assert.equal(Object.hasOwn(actuator.pins, 'envelopePublicKey'), false);

    const result = await actuator.execute({
      envelope,
      attemptId: body.attempt_id,
      actionDigest: body.action_digest,
      idempotencyKey: body.idempotency_key,
    });

    assert.equal(result.ok, true);
    assert.deepEqual(result.result, { provider_reference: 'provider-result-1' });
    assert.equal(calls.count, 1);
    const snapshot = store.snapshot(body.tenant_id, body.nonce);
    assert.equal(snapshot?.state, 'CONSUMED');
    assert.equal(snapshot?.outcome, 'COMMITTED');
    assert.equal(snapshot?.attemptId, body.attempt_id);
    assert.equal(snapshot?.targetDigest, body.target_digest);
  });

  it('atomically allows one winner under a concurrent race and refuses replay', async () => {
    const { actuator, calls, signer } = harness();
    const body = payload();
    const envelope = signEnvelope(signer, body);
    const input = {
      envelope,
      attemptId: body.attempt_id,
      actionDigest: body.action_digest,
      idempotencyKey: body.idempotency_key,
    };

    const raced = await Promise.all([
      actuator.execute(input),
      actuator.execute(input),
      actuator.execute(input),
    ]);

    assert.equal(raced.filter((result) => result.ok).length, 1);
    assert.deepEqual(
      raced.filter((result) => !result.ok).map((result) => result.reason),
      ['envelope_replayed', 'envelope_replayed'],
    );
    assert.equal(calls.count, 1);

    const replay = await actuator.execute(input);
    assert.deepEqual(
      { ok: replay.ok, reason: replay.ok ? undefined : replay.reason, invoked: replay.invoked },
      { ok: false, reason: 'envelope_replayed', invoked: false },
    );
  });

  it('refuses a correctly signed envelope for the wrong target before invocation', async () => {
    const { actuator, calls, signer } = harness();
    const body = payload({ target_digest: OTHER_TARGET_DIGEST });

    const result = await actuator.execute({
      envelope: signEnvelope(signer, body),
      attemptId: body.attempt_id,
      actionDigest: body.action_digest,
      idempotencyKey: body.idempotency_key,
    });
    assert.equal(result.ok, false);
    if (result.ok) assert.fail('wrong-target envelope executed');
    assert.equal(result.reason, 'target_mismatch');
    assert.equal(result.invoked, false);
    assert.equal(calls.count, 0);
  });

  it('refuses stale envelopes and mismatched live attempt/action/idempotency bindings', async () => {
    const { actuator, calls, signer } = harness();
    const stale = payload({
      issued_at: new Date(NOW - 61_000).toISOString(),
      expires_at: new Date(NOW - 1).toISOString(),
    });
    const staleResult = await actuator.execute({
      envelope: signEnvelope(signer, stale),
      attemptId: stale.attempt_id,
      actionDigest: stale.action_digest,
      idempotencyKey: stale.idempotency_key,
    });
    assert.equal(staleResult.ok, false);
    if (staleResult.ok) assert.fail('stale envelope executed');
    assert.equal(staleResult.reason, 'envelope_expired');

    const body = payload();
    const envelope = signEnvelope(signer, body);
    const wrongAttempt = await actuator.execute({
      envelope,
      attemptId: 'attempt-substituted',
      actionDigest: body.action_digest,
      idempotencyKey: body.idempotency_key,
    });
    assert.equal(wrongAttempt.ok, false);
    if (wrongAttempt.ok) assert.fail('wrong attempt executed');
    assert.equal(wrongAttempt.reason, 'attempt_mismatch');
    const wrongAction = await actuator.execute({
      envelope,
      attemptId: body.attempt_id,
      actionDigest: OTHER_ACTION_DIGEST,
      idempotencyKey: body.idempotency_key,
    });
    assert.equal(wrongAction.ok, false);
    if (wrongAction.ok) assert.fail('wrong action executed');
    assert.equal(wrongAction.reason, 'action_digest_mismatch');
    const wrongIdempotencyKey = await actuator.execute({
      envelope,
      attemptId: body.attempt_id,
      actionDigest: body.action_digest,
      idempotencyKey: 'operation-substituted',
    });
    assert.equal(wrongIdempotencyKey.ok, false);
    if (wrongIdempotencyKey.ok) assert.fail('wrong idempotency key executed');
    assert.equal(wrongIdempotencyKey.reason, 'idempotency_key_mismatch');
    assert.equal(calls.count, 0);
  });

  it('verifies only the constructor-pinned Ed25519 key and key identifier', async () => {
    const { actuator, calls } = harness();
    const attacker = generateKeyPairSync('ed25519');
    const body = payload();

    const wrongKey = await actuator.execute({
      envelope: signEnvelope(attacker, body),
      attemptId: body.attempt_id,
      actionDigest: body.action_digest,
      idempotencyKey: body.idempotency_key,
    });
    assert.equal(wrongKey.ok, false);
    if (wrongKey.ok) assert.fail('substituted key executed');
    assert.equal(wrongKey.reason, 'signature_invalid');
    assert.equal(wrongKey.invoked, false);

    const wrongKeyIdBody = payload();
    const wrongKeyId = await actuator.execute({
      envelope: signEnvelope(attacker, wrongKeyIdBody, 'attacker-key'),
      attemptId: wrongKeyIdBody.attempt_id,
      actionDigest: wrongKeyIdBody.action_digest,
      idempotencyKey: wrongKeyIdBody.idempotency_key,
    });
    assert.equal(wrongKeyId.ok, false);
    if (wrongKeyId.ok) assert.fail('substituted key identifier executed');
    assert.equal(wrongKeyId.reason, 'signer_key_mismatch');
    assert.equal(wrongKeyId.invoked, false);
    assert.equal(calls.count, 0);
  });

  it('permanently fences an indeterminate provider invocation', async () => {
    const signer = generateKeyPairSync('ed25519');
    const store = createMemoryConsequenceActuatorStore();
    let calls = 0;
    const perform = async () => {
      calls += 1;
      throw new Error('provider acknowledgement lost');
    };
    const actuator = new ConsequenceActuator({
      pins: {
        tenantId: 'tenant-1',
        caid: CAID,
        providerAccountId: 'provider-account-1',
        targetDigest: TARGET_DIGEST,
        operation: 'payment.capture',
        envelopeIssuerId: 'authorization-service',
        envelopeKeyId: 'actuator-key-1',
        envelopePublicKey: signer.publicKey,
      },
      store,
      perform,
      now: () => NOW,
    });
    const body = payload();
    const input = {
      envelope: signEnvelope(signer, body),
      attemptId: body.attempt_id,
      actionDigest: body.action_digest,
      idempotencyKey: body.idempotency_key,
    };

    const indeterminate = await actuator.execute(input);
    assert.equal(indeterminate.ok, false);
    if (indeterminate.ok) assert.fail('provider error returned success');
    assert.equal(indeterminate.reason, 'provider_outcome_indeterminate');
    assert.equal(indeterminate.invoked, true);
    const snapshot = store.snapshot(body.tenant_id, body.nonce);
    assert.equal(snapshot?.state, 'CONSUMED');
    assert.equal(snapshot?.outcome, 'INDETERMINATE');
    const replay = await actuator.execute(input);
    assert.equal(replay.ok, false);
    if (replay.ok) assert.fail('indeterminate envelope replayed');
    assert.equal(replay.reason, 'envelope_replayed');
    assert.equal(replay.invoked, false);
    assert.equal(calls, 1);
  });
});

describe('Postgres consequence actuator store', () => {
  function mockPool(
    results: ConsequenceActuatorPgQueryResult[],
    principal = 'tenant_1_consequence_executor',
  ) {
    const calls: Array<{ text: string; values: readonly unknown[] }> = [];
    return {
      calls,
      pool: {
        principal,
        async query(text: string, values: readonly unknown[]) {
          calls.push({ text, values });
          const result = results.shift();
          if (result === undefined) {
            throw new Error('unexpected query');
          }
          return result;
        },
      },
    };
  }

  it('requires a dedicated non-privileged executor principal and matching pool', () => {
    const servicePool = mockPool([], 'service_role');
    assert.throws(
      () => createPostgresConsequenceActuatorStore({
        tenantId: 'tenant-1',
        executorPrincipal: 'service_role',
        executorPool: servicePool.pool,
      }),
      /dedicated tenant executor principal/,
    );

    const mismatched = mockPool([], 'other_executor');
    assert.throws(
      () => createPostgresConsequenceActuatorStore({
        tenantId: 'tenant-1',
        executorPrincipal: 'tenant_1_consequence_executor',
        executorPool: mismatched.pool,
      }),
      /dedicated tenant executor principal/,
    );
  });

  it('binds reserve to the exact RPC and positional arguments', async () => {
    const row = reservation();
    const mock = mockPool([{
      rowCount: 1,
      rows: [{ envelope_digest: row.envelopeDigest }],
    }]);
    const store = createPostgresConsequenceActuatorStore({
      tenantId: 'tenant-1',
      executorPrincipal: mock.pool.principal,
      executorPool: mock.pool,
    });

    assert.equal(store.durable, true);
    assert.equal(store.atomic, true);
    assert.equal(store.permanentConsumption, true);
    assert.equal(await store.reserve(row), true);
    assert.equal(mock.calls.length, 1);
    assert.equal(mock.calls[0].text, CONSEQUENCE_ACTUATOR_SQL.reserve);
    assert.match(
      mock.calls[0].text,
      /^SELECT envelope_digest\nFROM consequence_actuator_private\.reserve_envelope\(/,
    );
    assert.doesNotMatch(mock.calls[0].text, /\b(?:INSERT|UPDATE|DELETE)\b/);
    assert.deepEqual(mock.calls[0].values, [
      row.tenantId,
      row.attemptId,
      row.actionDigest,
      row.caid,
      row.providerAccountId,
      row.targetDigest,
      row.operation,
      row.idempotencyKey,
      row.nonce,
      row.issuedAt,
      row.expiresAt,
      row.envelopeDigest,
    ]);
  });

  it('binds consume to the exact RPC and outcome argument', async () => {
    const row: ConsequenceActuatorConsumption = {
      ...reservation(),
      outcome: 'INDETERMINATE',
    };
    const mock = mockPool([{
      rowCount: 1,
      rows: [{ envelope_digest: row.envelopeDigest }],
    }]);
    const store = createPostgresConsequenceActuatorStore({
      tenantId: 'tenant-1',
      executorPrincipal: mock.pool.principal,
      executorPool: mock.pool,
    });

    assert.equal(await store.consume(row), true);
    assert.equal(mock.calls[0].text, CONSEQUENCE_ACTUATOR_SQL.consume);
    assert.match(
      mock.calls[0].text,
      /^SELECT envelope_digest\nFROM consequence_actuator_private\.consume_envelope\(/,
    );
    assert.doesNotMatch(mock.calls[0].text, /\b(?:INSERT|UPDATE|DELETE)\b/);
    assert.deepEqual(mock.calls[0].values, [
      row.tenantId,
      row.attemptId,
      row.actionDigest,
      row.caid,
      row.providerAccountId,
      row.targetDigest,
      row.operation,
      row.idempotencyKey,
      row.nonce,
      row.envelopeDigest,
      row.outcome,
    ]);
  });

  it('distinguishes a zero-row replay from ambiguous acknowledgements', async () => {
    const row = reservation();
    const zero = mockPool([{ rowCount: 0, rows: [] }]);
    const zeroStore = createPostgresConsequenceActuatorStore({
      tenantId: 'tenant-1',
      executorPrincipal: zero.pool.principal,
      executorPool: zero.pool,
    });
    assert.equal(await zeroStore.reserve(row), false);

    for (const result of [
      { rowCount: null, rows: [{ envelope_digest: row.envelopeDigest }] },
      { rowCount: 1, rows: [] },
      { rowCount: 1, rows: [{ envelope_digest: OTHER_ACTION_DIGEST }] },
      {
        rowCount: 2,
        rows: [
          { envelope_digest: row.envelopeDigest },
          { envelope_digest: row.envelopeDigest },
        ],
      },
    ] satisfies ConsequenceActuatorPgQueryResult[]) {
      const ambiguous = mockPool([result]);
      const store = createPostgresConsequenceActuatorStore({
        tenantId: 'tenant-1',
        executorPrincipal: ambiguous.pool.principal,
        executorPool: ambiguous.pool,
      });
      await assert.rejects(
        () => store.reserve(row),
        /ambiguous acknowledgement/,
      );
    }
  });

  it('refuses cross-tenant bindings before touching the executor pool', async () => {
    const mock = mockPool([]);
    const store = createPostgresConsequenceActuatorStore({
      tenantId: 'tenant-1',
      executorPrincipal: mock.pool.principal,
      executorPool: mock.pool,
    });

    await assert.rejects(
      () => store.reserve(reservation({ tenantId: 'tenant-2' })),
      /does not match the store tenant/,
    );
    assert.equal(mock.calls.length, 0);
  });
});
