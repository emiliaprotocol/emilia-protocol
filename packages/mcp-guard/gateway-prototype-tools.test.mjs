// SPDX-License-Identifier: Apache-2.0
import test from 'node:test';
import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import { ProvenanceLedger, withCustomerOwnedProtectionGateway } from './index.js';
import { createProtectionPlan } from '../gate/protection-plan.js';
import { signProtectionActivation, verifyProtectionActivation } from '../gate/protection-activation.js';

async function gatewayOptions(tool) {
  const pair = crypto.generateKeyPairSync('ed25519');
  const publicKey = pair.publicKey.export({ type: 'spki', format: 'der' }).toString('base64url');
  const plan = structuredClone(createProtectionPlan({
    planId: 'prototype-tool',
    createdAt: '2026-08-20T17:54:00.000Z',
    selections: [{ presetId: 'spend-money' }],
  }));
  plan.action_control_manifest.actions[0].match.tool = tool;
  const activation = signProtectionActivation({
    activation_id: 'activation:prototype-tool',
    tenant_id: 'tenant:prototype-tool',
    gateway_id: 'gateway:prototype-tool',
    epoch: 1,
    issued_at: '2026-08-20T17:55:00.000Z',
    valid_from: '2026-08-20T17:56:00.000Z',
    expires_at: '2026-08-21T18:00:00.000Z',
    plan,
  }, {
    issuer_id: 'customer:prototype-tool',
    key_id: 'key:prototype-tool',
    private_key: pair.privateKey,
  });
  const verified = verifyProtectionActivation(activation, {
    trusted_keys: {
      'key:prototype-tool': { issuer_id: 'customer:prototype-tool', public_key: publicKey },
    },
    expected: {
      activation_id: activation.activation_id,
      tenant_id: activation.tenant_id,
      gateway_id: activation.gateway_id,
      authorizer_id: 'customer:prototype-tool',
    },
    now: '2026-08-20T18:00:00.000Z',
  });
  assert.equal(verified.accepted, true);
  const ledger = await ProvenanceLedger.open({ store: {
    durable: true,
    async load() { return []; },
    async append() { return { ok: true }; },
  } });
  return {
    verifiedActivation: verified,
    expectedActivationDigest: verified.activation_digest,
    expectedOwnerId: 'customer:prototype-tool',
    expectedOwnerKeyId: 'key:prototype-tool',
    tenantId: activation.tenant_id,
    gatewayId: activation.gateway_id,
    ledger,
    store: {
      durable: true,
      async reserve() { return true; },
      async commit() { return true; },
      async release() { return true; },
    },
  };
}

test('prototype-named protected tools cannot also be configured read-only', async () => {
  for (const tool of ['__proto__', 'constructor', 'toString']) {
    const options = await gatewayOptions(tool);
    assert.throws(() => withCustomerOwnedProtectionGateway(async () => {
      assert.fail('provider must not be entered');
    }, { ...options, readOnlyTools: [tool] }), /read-only tool conflicts with protection manifest/);
  }
});

test('a prototype-named protected tool retains its exact receipt requirement', async () => {
  const options = await gatewayOptions('__proto__');
  let calls = 0;
  const gateway = withCustomerOwnedProtectionGateway(async () => { calls += 1; }, options);
  const refused = await gateway('__proto__', { amount_usd: 10 });
  assert.equal(refused.ep_refused, true);
  assert.match(refused.required.action, /^payment\.release/);
  assert.equal(calls, 0);
  assert.deepEqual(gateway.protection.selected_mcp_tools, ['__proto__']);
});
