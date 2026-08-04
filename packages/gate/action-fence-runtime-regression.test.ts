// SPDX-License-Identifier: Apache-2.0

import test from 'node:test';
import assert from 'node:assert/strict';
import { generateKeyPairSync, sign } from 'node:crypto';
import { createRequire } from 'node:module';
import { canonicalize } from './execution-binding.js';
import {
  CAPABILITY_ALLOWANCE_SCOPE_PROFILE,
  CAPABILITY_CAID_SCOPE_PROFILE,
  CAPABILITY_SCOPE_PROFILE,
  CAPABILITY_SQL,
  CAPABILITY_STATE_DDL,
  capabilityActionDigest,
  createMemoryCapabilityStore,
  createPostgresCapabilityStore,
  executeWithCapability,
  mintCapabilityReceipt,
} from './capability-receipt.js';

const NOW = Date.parse('2026-08-03T12:00:00.000Z');
const PROVIDER_ENTRY_TIMEOUT_MS = 1_000;
const POSTGRES_URL = process.env.ADMISSION_STORE_POSTGRES_TEST_URL;
const require = createRequire(import.meta.url);

function baseReceipt({ privateKey, publicKey, receiptId = 'action_fence_regression_base' }) {
  const payload = {
    receipt_id: receiptId,
    created_at: new Date(NOW - 1_000).toISOString(),
    subject: 'operator@example.test',
    claim: { action_type: 'payment.release', outcome: 'allow', capability_only: true },
  };
  return {
    '@version': 'EP-RECEIPT-v1',
    payload,
    signature: {
      algorithm: 'Ed25519',
      value: sign(null, Buffer.from(canonicalize(payload)), privateKey).toString('base64url'),
    },
    public_key: publicKey.export({ type: 'spki', format: 'der' }).toString('base64url'),
  };
}

function issuer() {
  const keys = generateKeyPairSync('ed25519');
  return {
    ...keys,
    receipt: baseReceipt({ privateKey: keys.privateKey, publicKey: keys.publicKey }),
  };
}

function action(operationId: string, overrides: Record<string, unknown> = {}) {
  return {
    operation_id: operationId,
    action_type: 'payment.release',
    amount: 1,
    currency: 'USD',
    destination: 'acct_expected',
    ...overrides,
  };
}

function mintFixture(capabilityId: string, scopedAction = action(`${capabilityId}-scope`)) {
  const keys = issuer();
  const minted = mintCapabilityReceipt(keys.receipt, {
    capabilityId,
    issuerPrivateKey: keys.privateKey,
    budget: { amount: 10, currency: 'USD' },
    expiry: NOW + 60_000,
    scope: {
      profile: CAPABILITY_SCOPE_PROFILE,
      operation_id_field: 'operation_id',
      action_digests: [capabilityActionDigest(scopedAction)],
    },
  });
  return { keys, minted };
}

async function registerFixture(store: any, capabilityId: string) {
  const fixture = mintFixture(capabilityId);
  const reference = createMemoryCapabilityStore();
  assert.equal(reference.registerCapability(fixture.minted.capabilityReceipt), true);
  const referenceState = reference.getState(capabilityId);
  assert.equal(await store.registerCapability(fixture.minted.capabilityReceipt), true);
  return {
    ...fixture,
    capabilityId,
    capabilityFingerprint: referenceState.capability_fingerprint,
  };
}

async function createPostgresHarness(t: any, label: string) {
  const { Pool } = require('pg') as { Pool: new (options: Record<string, unknown>) => any };
  const pool = new Pool({ connectionString: POSTGRES_URL, max: 2 });
  const schema = `ep_action_fence_contract_${label}_${process.pid}_${Date.now()}`
    .replace(/[^a-zA-Z0-9_]/g, '_');
  let transactionCount = 0;

  await pool.query(`CREATE SCHEMA ${schema}`);
  const setup = await pool.connect();
  try {
    await setup.query(`SET search_path TO ${schema}, public`);
    await setup.query(CAPABILITY_STATE_DDL);
  } finally {
    setup.release();
  }

  const transaction = async (callback: (query: Function) => any) => {
    transactionCount += 1;
    const client = await pool.connect();
    try {
      await client.query('BEGIN');
      await client.query(`SET LOCAL search_path TO ${schema}, public`);
      const result = await callback(async (sql: string, params: unknown[] = []) => {
        const queried = await client.query(sql, [...params]);
        return { rowCount: queried.rowCount ?? 0, rows: queried.rows };
      });
      await client.query('COMMIT');
      return result;
    } catch (error) {
      await client.query('ROLLBACK');
      throw error;
    } finally {
      client.release();
    }
  };

  t.after(async () => {
    await pool.query(`DROP SCHEMA IF EXISTS ${schema} CASCADE`);
    await pool.end();
  });

  return {
    store: createPostgresCapabilityStore({ transaction, providerEntryTimeoutMs: PROVIDER_ENTRY_TIMEOUT_MS }),
    transactionCount: () => transactionCount,
  };
}

test('a failed CAID resolver object refuses before any effect or spend', async () => {
  const keys = issuer();
  const operationId = 'failed-caid-resolution';
  const exactAction = action(operationId);
  const caid = `caid:1:payment.release.1:jcs-sha256:${'A'.repeat(43)}`;
  const minted = mintCapabilityReceipt(keys.receipt, {
    capabilityId: 'failed_caid_resolution_capability',
    issuerPrivateKey: keys.privateKey,
    budget: { amount: 10, currency: 'USD' },
    expiry: NOW + 60_000,
    scope: {
      profile: CAPABILITY_CAID_SCOPE_PROFILE,
      operation_id_field: 'operation_id',
      caids: [caid],
    },
  });
  const store = createMemoryCapabilityStore();
  assert.equal(store.registerCapability(minted.capabilityReceipt), true);
  let effects = 0;

  const result = await executeWithCapability({
    capabilityReceipt: minted.capabilityReceipt,
    secret: minted.secret,
    action: exactAction,
    operationId,
    store,
    trustedIssuerKeys: [keys.receipt.public_key],
    verifyBaseReceipt: () => true,
    resolveCaid: () => ({ ok: false, caid, reason: 'material_fields_lost' }),
    executeAction: async () => {
      effects += 1;
      return 'entered';
    },
    now: NOW,
  });

  assert.equal(effects, 0, 'a failed CAID resolution must not enter the effect');
  assert.equal(result.ok, false);
  assert.equal(result.reason, 'capability_caid_resolution_failed');
  assert.equal(store.getOperation(operationId, minted.capabilityReceipt.capability.id), null);
  assert.equal(store.getState(minted.capabilityReceipt.capability.id).reserved_amount, 0);
  assert.equal(store.getState(minted.capabilityReceipt.capability.id).consumed_amount, 0);
});

test('allowance profile requires one trusted semantic fence across wrapper operation ids', async () => {
  const profileId = 'allowance:semantic-fence-regression:01';
  const profileDigest = `sha256:${'b'.repeat(64)}`;
  const statusHeadDigest = `sha256:${'c'.repeat(64)}`;
  const actions = [
    action('wrapper-operation-a'),
    action('wrapper-operation-b'),
  ];
  const semanticFenceDigest = capabilityActionDigest({
    action_type: 'payment.release',
    amount: 1,
    currency: 'USD',
    destination: 'acct_expected',
  });
  assert.notEqual(capabilityActionDigest(actions[0]), capabilityActionDigest(actions[1]));

  const setup = (capabilityId: string) => {
    const keys = issuer();
    const minted = mintCapabilityReceipt(keys.receipt, {
      capabilityId,
      issuerPrivateKey: keys.privateKey,
      budget: { amount: 10, currency: 'USD' },
      expiry: NOW + 60_000,
      scope: {
        profile: CAPABILITY_ALLOWANCE_SCOPE_PROFILE,
        profile_id: profileId,
        profile_digest: profileDigest,
        operation_id_field: 'operation_id',
      },
    });
    const store = createMemoryCapabilityStore();
    assert.equal(store.registerCapability(minted.capabilityReceipt), true);
    const allowanceStatus = {
      allowance_profile_id: profileId,
      allowance_digest: profileDigest,
      revision: 1,
      status_epoch: 1,
      status_head_digest: statusHeadDigest,
    };
    assert.equal(store.advanceAllowanceStatus({
      ...allowanceStatus,
      expected_status_epoch: null,
      expected_status_head_digest: null,
      status: 'active',
    }).ok, true);
    return { keys, minted, store, allowanceStatus };
  };

  const execute = async (
    fixture: ReturnType<typeof setup>,
    candidate: ReturnType<typeof action>,
    verifyActionProfile: (...args: any[]) => any,
    effects: string[],
  ) => executeWithCapability({
    capabilityReceipt: fixture.minted.capabilityReceipt,
    secret: fixture.minted.secret,
    action: candidate,
    operationId: candidate.operation_id,
    store: fixture.store,
    trustedIssuerKeys: [fixture.keys.receipt.public_key],
    verifyBaseReceipt: () => true,
    verifyActionProfile,
    allowanceStatus: fixture.allowanceStatus,
    executeAction: async () => {
      effects.push(candidate.operation_id);
      return candidate.operation_id;
    },
    now: NOW,
  });

  const missingFence = setup('allowance_missing_semantic_fence');
  const missingFenceEffects: string[] = [];
  const missingFenceResults = [];
  for (const candidate of actions) {
    missingFenceResults.push(await execute(
      missingFence,
      candidate,
      () => ({ ok: true }),
      missingFenceEffects,
    ));
  }
  assert.deepEqual(
    missingFenceResults.map(({ ok, reason }) => ({ ok, reason })),
    actions.map(() => ({ ok: false, reason: 'capability_action_fence_digest_required' })),
  );
  assert.deepEqual(missingFenceEffects, [], 'neither wrapper may enter the effect without a trusted semantic fence');
  assert.equal(missingFence.store.getState('allowance_missing_semantic_fence').reserved_amount, 0);
  assert.equal(missingFence.store.getState('allowance_missing_semantic_fence').consumed_amount, 0);
  for (const candidate of actions) {
    assert.equal(missingFence.store.getOperation(candidate.operation_id), null);
  }

  const fenced = setup('allowance_explicit_semantic_fence');
  const fencedEffects: string[] = [];
  const verifier = () => ({ ok: true, action_fence_digest: semanticFenceDigest });
  const first = await execute(fenced, actions[0], verifier, fencedEffects);
  const duplicate = await execute(fenced, actions[1], verifier, fencedEffects);
  assert.equal(first.ok, true);
  assert.equal(first.action_fence_digest, semanticFenceDigest);
  assert.equal(duplicate.ok, false);
  assert.equal(duplicate.reason, 'action_already_committed');
  assert.equal(duplicate.action_fence_digest, semanticFenceDigest);
  assert.equal(duplicate.holding_operation_id, actions[0].operation_id);
  assert.deepEqual(fencedEffects, [actions[0].operation_id]);
});

for (const amount of [0, -1]) {
  const label = amount === 0 ? 'zero' : 'negative';

  test(`memory reserveSpend rejects a ${label} amount at the API boundary`, async () => {
    const store = createMemoryCapabilityStore();
    const fixture = await registerFixture(store, `memory_${label}_amount`);
    const operationId = `memory-${label}-amount`;

    await assert.rejects(
      () => store.reserveSpend({
        capabilityId: fixture.capabilityId,
        capabilityFingerprint: fixture.capabilityFingerprint,
        operationId,
        actionDigest: capabilityActionDigest(action(operationId)),
        amount,
        currency: 'USD',
        now: NOW,
      }),
      (error: unknown) => error instanceof TypeError,
    );
    assert.equal(store.getOperation(operationId, fixture.capabilityId), null);
    assert.equal(store.getState(fixture.capabilityId).reserved_amount, 0);
    assert.equal(store.getState(fixture.capabilityId).consumed_amount, 0);
  });

  test(`PostgreSQL reserveSpend rejects a ${label} amount at the API boundary`, {
    skip: POSTGRES_URL ? false : 'ADMISSION_STORE_POSTGRES_TEST_URL is not configured',
  }, async (t) => {
    const harness = await createPostgresHarness(t, `amount_${label}`);
    const fixture = await registerFixture(harness.store, `postgres_${label}_amount`);
    const operationId = `postgres-${label}-amount`;
    const transactionsBeforeReserve = harness.transactionCount();

    await assert.rejects(
      () => harness.store.reserveSpend({
        capabilityId: fixture.capabilityId,
        capabilityFingerprint: fixture.capabilityFingerprint,
        operationId,
        actionDigest: capabilityActionDigest(action(operationId)),
        amount,
        currency: 'USD',
        now: NOW,
      }),
      (error: unknown) => error instanceof TypeError,
    );
    assert.equal(
      harness.transactionCount(),
      transactionsBeforeReserve,
      'invalid amounts must be rejected before opening a PostgreSQL transaction',
    );
  });
}

test('PostgreSQL refuses a quarantined legacy capability before reservation', async () => {
  const fixture = mintFixture('legacy_semantic_fence_quarantine');
  const reference = createMemoryCapabilityStore();
  assert.equal(reference.registerCapability(fixture.minted.capabilityReceipt), true);
  const state = reference.getState(fixture.minted.capabilityReceipt.capability.id);
  let queries = 0;
  const store = createPostgresCapabilityStore({
    transaction: async (callback) => callback(async (sql) => {
      queries += 1;
      assert.equal(sql, CAPABILITY_SQL.readState);
      return {
        rowCount: 1,
        rows: [{
          capability_id: state.capability_id,
          capability_fingerprint: state.capability_fingerprint,
          budget_amount: String(state.budget_amount),
          currency: state.currency,
          consumed_amount: '0',
          reserved_amount: '0',
          expires_at: new Date(state.expires_at).toISOString(),
          allowance_profile_id: null,
          allowance_digest: null,
          semantic_fence_ready: false,
        }],
      };
    }),
  });

  const operationId = 'legacy-semantic-fence-refusal';
  assert.deepEqual(await store.reserveSpend({
    capabilityId: state.capability_id,
    capabilityFingerprint: state.capability_fingerprint,
    operationId,
    actionDigest: capabilityActionDigest(action(operationId)),
    amount: 1,
    currency: 'USD',
    now: NOW,
  }), { ok: false, reason: 'capability_semantic_fence_migration_required' });
  assert.equal(queries, 1, 'the quarantined capability must fail before any write');
});

type StoreKind = 'memory' | 'postgres';
type ReconciliationPath = 'pre-entry' | 'indeterminate' | 'not-entered';

async function assertWrongDigestRefused(
  store: any,
  storeKind: StoreKind,
  path: ReconciliationPath,
) {
  const capabilityId = `${storeKind}_${path.replace('-', '_')}_wrong_digest`;
  const fixture = await registerFixture(store, capabilityId);
  const operationId = `${storeKind}-${path}-wrong-digest`;
  const exactAction = action(operationId);
  const exactDigest = capabilityActionDigest(exactAction);
  const wrongDigest = capabilityActionDigest({ ...exactAction, destination: 'acct_substituted' });
  assert.notEqual(wrongDigest, exactDigest);

  const reservation = await store.reserveSpend({
    capabilityId,
    capabilityFingerprint: fixture.capabilityFingerprint,
    operationId,
    actionDigest: exactDigest,
    amount: 1,
    currency: 'USD',
    now: NOW,
  });
  assert.equal(reservation.ok, true);

  if (path === 'pre-entry') {
    assert.deepEqual(await store.recoverPreEntrySpend({
      capabilityId,
      operationId,
      actionDigest: wrongDigest,
      now: NOW + PROVIDER_ENTRY_TIMEOUT_MS,
    }), { ok: false, reason: 'capability_reconciliation_action_mismatch' });
    assert.equal((await store.recoverPreEntrySpend({
      capabilityId,
      operationId,
      actionDigest: exactDigest,
      now: NOW + PROVIDER_ENTRY_TIMEOUT_MS,
    })).ok, true, 'the wrong digest must not consume the valid recovery transition');
    return;
  }

  assert.equal((await store.beginProviderEntry({
    capabilityId,
    operationId,
    reservationToken: reservation.reservation_token,
    now: NOW,
  })).ok, true);

  const evidenceDigest = capabilityActionDigest({ operation_id: operationId, evidence: path });
  if (path === 'indeterminate') {
    assert.equal((await store.commitSpend({
      capabilityId,
      operationId,
      reservationToken: reservation.reservation_token,
      outcome: 'indeterminate',
      now: NOW,
    })).ok, true);
    assert.deepEqual(await store.reconcileSpend({
      capabilityId,
      operationId,
      actionDigest: wrongDigest,
      evidenceDigest,
      outcome: 'executed',
      now: NOW + 1,
    }), { ok: false, reason: 'capability_reconciliation_action_mismatch' });
    assert.equal((await store.reconcileSpend({
      capabilityId,
      operationId,
      actionDigest: exactDigest,
      evidenceDigest,
      outcome: 'executed',
      now: NOW + 1,
    })).ok, true, 'the wrong digest must not consume the valid indeterminate reconciliation');
    return;
  }

  const evidenceProfile = 'urn:test:negative-provider-entry:v1';
  const evidenceObservedAt = new Date(NOW + PROVIDER_ENTRY_TIMEOUT_MS).toISOString();
  assert.deepEqual(await store.reconcileSpend({
    capabilityId,
    operationId,
    actionDigest: wrongDigest,
    evidenceDigest,
    evidenceProfile,
    evidenceFinal: true,
    evidenceObservedAt,
    outcome: 'not_entered',
    now: NOW + PROVIDER_ENTRY_TIMEOUT_MS,
  }), { ok: false, reason: 'capability_reconciliation_action_mismatch' });
  assert.equal((await store.reconcileSpend({
    capabilityId,
    operationId,
    actionDigest: exactDigest,
    evidenceDigest,
    evidenceProfile,
    evidenceFinal: true,
    evidenceObservedAt,
    outcome: 'not_entered',
    now: NOW + PROVIDER_ENTRY_TIMEOUT_MS,
  })).ok, true, 'the wrong digest must not consume the valid not-entered reconciliation');
}

for (const path of ['pre-entry', 'indeterminate', 'not-entered'] as const) {
  test(`memory ${path} recovery/reconciliation refuses the wrong exact action digest`, async () => {
    const store = createMemoryCapabilityStore({ providerEntryTimeoutMs: PROVIDER_ENTRY_TIMEOUT_MS });
    await assertWrongDigestRefused(store, 'memory', path);
  });

  test(`PostgreSQL ${path} recovery/reconciliation refuses the wrong exact action digest`, {
    skip: POSTGRES_URL ? false : 'ADMISSION_STORE_POSTGRES_TEST_URL is not configured',
  }, async (t) => {
    const harness = await createPostgresHarness(t, `wrong_digest_${path}`);
    await assertWrongDigestRefused(harness.store, 'postgres', path);
  });
}
