// SPDX-License-Identifier: Apache-2.0
import assert from 'node:assert/strict';
import test from 'node:test';
import {
  createEg1Harness,
  createTrustedActionFirewall,
} from '@emilia-protocol/gate';

import {
  createAebGateConsumptionAdapter,
  createGitHubIssueControlManifest,
  createGitHubIssueSelector,
  parseStrictEnvironmentJson,
  verifyDatabasePrincipalSeparation,
} from '../src/production-config.js';

const AEB_READINESS_CONTRACT = '20260723143500';
const PTE_READINESS_CONTRACT = '20260723150000';

function readinessRow({
  principal,
  recovery,
  overrides = {},
}) {
  return {
    principal_name: principal,
    expected_recovery: recovery,
    tenant_binding_ok: true,
    role_membership_ok: true,
    opposite_role_absent: true,
    rpc_grants_ok: true,
    schema_objects_ok: true,
    schema_contract: overrides.schema_contract,
    ...overrides,
  };
}

function readinessPool({
  principal,
  recovery,
  aebOverrides = {},
  pteOverrides = {},
  fail = false,
}) {
  const calls = [];
  return {
    calls,
    async query(sql, parameters) {
      calls.push([sql, parameters]);
      if (fail) throw new Error('database_unavailable');
      assert.deepEqual(parameters, ['tenant-canary', recovery]);
      if (sql.includes('ep_aeb_private.principal_readiness')) {
        return {
          rowCount: 1,
          rows: [readinessRow({
            principal,
            recovery,
            overrides: {
              schema_contract: AEB_READINESS_CONTRACT,
              ...aebOverrides,
            },
          })],
        };
      }
      if (sql.includes('proposal_to_effect_private.principal_readiness')) {
        return {
          rowCount: 1,
          rows: [readinessRow({
            principal,
            recovery,
            overrides: {
              schema_contract: PTE_READINESS_CONTRACT,
              ...pteOverrides,
            },
          })],
        };
      }
      throw new Error('unexpected_readiness_query');
    },
  };
}

test('production JSON parser rejects duplicate members and non-object roots', () => {
  assert.deepEqual(
    parseStrictEnvironmentJson('{"one":1}', 'TEST_JSON'),
    { one: 1 },
  );
  assert.throws(
    () => parseStrictEnvironmentJson('{"one":1,"one":2}', 'TEST_JSON'),
    /TEST_JSON_invalid/,
  );
  assert.throws(
    () => parseStrictEnvironmentJson('[]', 'TEST_JSON'),
    /TEST_JSON_invalid/,
  );
});

test('Gate receipt consumption adapter keeps durable AEB ownership and replay semantics', async () => {
  const calls = [];
  const reservations = new Set();
  const store = {
    durable: true,
    ownershipFenced: true,
    permanentConsumption: true,
    atomicReplayFenced: true,
    async reserve(key, replayKeys) {
      calls.push(['reserve', key, replayKeys]);
      if (reservations.has(key)) return 'CONSUMPTION_CONFLICT';
      reservations.add(key);
      return 'RESERVED';
    },
    async commit(key) {
      calls.push(['commit', key]);
      return reservations.has(key);
    },
    async release(key) {
      calls.push(['release', key]);
      return reservations.delete(key);
    },
  };
  const adapter = createAebGateConsumptionAdapter(store);

  assert.equal(await adapter.reserve('receipt:one'), true);
  assert.equal(await adapter.commit('receipt:one'), true);
  assert.equal(await adapter.reserve('receipt:one'), false);
  assert.deepEqual(calls[0], [
    'reserve',
    'gate-receipt:receipt:one',
    ['gate-native:receipt:one'],
  ]);
  assert.equal(adapter.durable, true);
  assert.equal(adapter.permanentConsumption, true);
});

test('production GitHub control manifest guards and exactly binds the configured issue mutation', async () => {
  const action = {
    action_type: 'github.issue.update.1',
    owner: 'emiliaprotocol',
    repo: 'gate-smoke-target',
    issue_number: 1,
    title: 'Consequence control canary',
    body: 'Exact action body',
  };
  const harness = createEg1Harness({ action, idPrefix: 'consequence-service' });
  const gate = createTrustedActionFirewall({
    manifest: createGitHubIssueControlManifest({
      owner: action.owner,
      repo: action.repo,
      issueNumber: action.issue_number,
    }),
    trustedKeys: [harness.publicKey],
    approverKeys: harness.approverKeys,
    rpId: harness.rpId,
    allowedOrigins: harness.allowedOrigins,
    allowEphemeralStore: true,
  });
  const selector = createGitHubIssueSelector({
    owner: action.owner,
    repo: action.repo,
    issueNumber: action.issue_number,
  });
  const receipt = () => harness.mint({
    extra: {
      canonical_action: action,
      action_hash: `sha256:${harness.actionHash}`,
    },
  });

  const allowed = await gate.check({
    selector,
    receipt: receipt(),
    observedAction: action,
    consumptionMode: 'none',
  });
  assert.equal(allowed.allow, true, allowed.reason);
  assert.equal(allowed.requirement?.receipt_required, true);

  const drifted = await gate.check({
    selector,
    receipt: receipt(),
    observedAction: { ...action, body: 'Different action body' },
    consumptionMode: 'none',
  });
  assert.equal(drifted.allow, false);
  assert.match(drifted.reason, /execution|action|receipt_rejected/);
});

test('database readiness proves distinct exact executor and recovery principals', async () => {
  const executorPool = readinessPool({
    principal: 'ep_consequence_executor_login',
    recovery: false,
  });
  const recoveryPool = readinessPool({
    principal: 'ep_consequence_recovery_login',
    recovery: true,
  });

  assert.equal(await verifyDatabasePrincipalSeparation({
    executorPool,
    recoveryPool,
    tenantId: 'tenant-canary',
  }), true);
  assert.equal(executorPool.calls.length, 2);
  assert.equal(recoveryPool.calls.length, 2);
});

test('database readiness rejects two URLs that resolve to the same SESSION_USER', async () => {
  assert.equal(await verifyDatabasePrincipalSeparation({
    executorPool: readinessPool({
      principal: 'shared_login',
      recovery: false,
    }),
    recoveryPool: readinessPool({
      principal: 'shared_login',
      recovery: true,
    }),
    tenantId: 'tenant-canary',
  }), false);
});

test('database readiness rejects missing tenant rows, role separation, grants, objects, or contract', async () => {
  for (const [field, value] of [
    ['tenant_binding_ok', false],
    ['role_membership_ok', false],
    ['opposite_role_absent', false],
    ['rpc_grants_ok', false],
    ['schema_objects_ok', false],
    ['schema_contract', 'stale'],
  ]) {
    assert.equal(await verifyDatabasePrincipalSeparation({
      executorPool: readinessPool({
        principal: 'ep_consequence_executor_login',
        recovery: false,
        aebOverrides: { [field]: value },
      }),
      recoveryPool: readinessPool({
        principal: 'ep_consequence_recovery_login',
        recovery: true,
      }),
      tenantId: 'tenant-canary',
    }), false, field);
  }
});

test('database readiness rejects subsystem principal drift and database errors', async () => {
  assert.equal(await verifyDatabasePrincipalSeparation({
    executorPool: readinessPool({
      principal: 'ep_consequence_executor_login',
      recovery: false,
      pteOverrides: { principal_name: 'different_executor_login' },
    }),
    recoveryPool: readinessPool({
      principal: 'ep_consequence_recovery_login',
      recovery: true,
    }),
    tenantId: 'tenant-canary',
  }), false);

  assert.equal(await verifyDatabasePrincipalSeparation({
    executorPool: readinessPool({
      principal: 'ep_consequence_executor_login',
      recovery: false,
      fail: true,
    }),
    recoveryPool: readinessPool({
      principal: 'ep_consequence_recovery_login',
      recovery: true,
    }),
    tenantId: 'tenant-canary',
  }), false);
});
