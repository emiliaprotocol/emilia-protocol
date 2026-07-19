// SPDX-License-Identifier: Apache-2.0
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { createEg1Harness } from '../../../packages/gate/index.js';
import { EVIDENCE_SQL } from '../../../packages/gate/evidence-postgres.js';
import { CONSUMPTION_SQL } from '../../../packages/gate/store-postgres.js';
import { validateGateServiceConfig } from '../src/config.js';
import {
  ACTION_STORE_SQL,
  createPostgresActionStore,
  createProductionGateConfig,
} from '../src/production-config.js';
import { OBSERVED_ACTION } from './helpers.js';

const TOKEN = 'production-gate-token-000000000000000001';

function environment() {
  const harness = createEg1Harness({ action: OBSERVED_ACTION });
  return {
    EMILIA_GATE_DATABASE_URL: 'postgresql://gate:secret@db.example/gate',
    GITHUB_TOKEN: 'github-production-token',
    EMILIA_GATE_API_TOKEN: TOKEN,
    EMILIA_GATE_PRINCIPAL_ID: 'operator:production',
    EMILIA_GATE_TENANT_ID: 'tenant:production',
    EMILIA_GATE_ID: 'gate:production',
    EMILIA_GATE_ALLOWED_REPOSITORIES: 'acme/prod,other/safe',
    EMILIA_GATE_TRUST_JSON: JSON.stringify({
      trustedKeys: [harness.publicKey],
      approverKeys: harness.approverKeys,
      rpId: harness.rpId,
      allowedOrigins: harness.allowedOrigins,
    }),
  };
}

class FakePool {
  static instances = [];

  constructor(options) {
    this.options = options;
    this.calls = [];
    this.closed = 0;
    FakePool.instances.push(this);
  }

  async query(text, params = []) {
    this.calls.push({ text, params });
    if (text === ACTION_STORE_SQL.health) {
      return { rowCount: 1, rows: [{ table_ready: true, can_use: true }] };
    }
    if (text === CONSUMPTION_SQL.health) {
      return { rowCount: 1, rows: [{ table_ready: true, can_use: true }] };
    }
    if (text === EVIDENCE_SQL.health) {
      return {
        rowCount: 1,
        rows: [{
          records_ready: true,
          heads_ready: true,
          append_ready: true,
          can_read_records: true,
          can_read_heads: true,
          can_write_records_directly: false,
          can_write_heads_directly: false,
          can_append: true,
        }],
      };
    }
    throw new Error('unexpected fake query');
  }

  async end() { this.closed += 1; }
}

test('built-in production config wires pinned Postgres adapters and scoped authorization from environment', async () => {
  FakePool.instances.length = 0;
  const candidate = await createProductionGateConfig({
    environment: environment(),
    PoolClass: FakePool,
    fetchImpl: async () => { throw new Error('network not expected'); },
  });
  const config = validateGateServiceConfig(candidate);

  assert.equal(FakePool.instances.length, 1);
  assert.equal(config.tenantId, 'tenant:production');
  assert.equal(config.gateId, 'gate:production');
  assert.equal(await config.authorizeAction(
    { id: 'operator:production' },
    'github.repo.delete',
    'Acme',
    'Prod',
  ), true);
  assert.equal(await config.authorizeAction(
    { id: 'operator:production' },
    'github.repo.delete',
    'Acme',
    'not-allowed',
  ), false);
  assert.equal(await config.authorizeEvidence(
    { id: 'operator:production' },
    'history',
    'tenant:production',
    'gate:production',
    'test-action-0000000000000001',
  ), true);
  assert.deepEqual(await config.authenticateRequest({
    headers: { authorization: `Bearer ${TOKEN}` },
    rawHeaders: ['Authorization', `Bearer ${TOKEN}`],
  }), { id: 'operator:production' });
  assert.deepEqual(await config.readiness(), { ok: true });
  await config.actionStore.close();
  assert.equal(FakePool.instances[0].closed, 1);
});

test('production config refuses missing allowlists and malformed trust instead of defaulting open', async () => {
  const missingAllowlist = environment();
  delete missingAllowlist.EMILIA_GATE_ALLOWED_REPOSITORIES;
  await assert.rejects(
    () => createProductionGateConfig({ environment: missingAllowlist, PoolClass: FakePool }),
    /ALLOWED_REPOSITORIES/,
  );

  const malformedTrust = { ...environment(), EMILIA_GATE_TRUST_JSON: '{"trustedKeys":' };
  await assert.rejects(
    () => createProductionGateConfig({ environment: malformedTrust, PoolClass: FakePool }),
    /TRUST_JSON/,
  );
});

test('Postgres action adapter scopes reads and updates and atomically claims resume transitions', async () => {
  const calls = [];
  const results = [
    { rowCount: 1, rows: [] },
    { rowCount: 1, rows: [{ record: {
      id: 'action-0000000000000001',
      principal_id: 'operator:a',
      tenant_id: 'tenant:a',
      gate_id: 'gate:a',
      status: 'challenged',
    } }] },
    { rowCount: 1, rows: [] },
    { rowCount: 1, rows: [] },
    { rowCount: 3, rows: [] },
  ];
  const store = createPostgresActionStore({
    tenantId: 'tenant:a',
    gateId: 'gate:a',
    query: async (text, params) => {
      calls.push({ text, params });
      return results.shift();
    },
  });
  const record = {
    id: 'action-0000000000000001',
    principal_id: 'operator:a',
    tenant_id: 'tenant:a',
    gate_id: 'gate:a',
    status: 'challenged',
  };

  assert.equal(await store.create(record), true);
  assert.deepEqual(await store.get(record.id, 'operator:a'), record);
  assert.equal(await store.update(record.id, 'operator:a', { status: 'observing' }), true);
  assert.equal(await store.transition(record.id, 'operator:a', ['challenged'], { status: 'observing' }), true);
  assert.equal(await store.reconcileInterrupted({
    action: 'github.repo.delete',
    statuses: ['executing'],
    patch: { status: 'indeterminate' },
  }), 3);
  assert.deepEqual(calls[1].params, [record.id, 'operator:a', 'tenant:a', 'gate:a']);
  assert.deepEqual(
    calls[3].params.slice(0, 5),
    [record.id, 'operator:a', 'tenant:a', 'gate:a', ['challenged']],
  );
  assert.deepEqual(
    calls[4].params.slice(0, 4),
    ['github.repo.delete', 'tenant:a', 'gate:a', ['executing']],
  );
});
