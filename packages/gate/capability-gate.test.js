// SPDX-License-Identifier: Apache-2.0

import test from 'node:test';
import assert from 'node:assert/strict';
import { generateKeyPairSync } from 'node:crypto';
import {
  createDefaultActionRiskManifest,
  createEg1Harness,
  createGate,
  createMemoryCapabilityStore,
  createRuntimeMonitor,
  mintCapabilityReceipt,
} from './index.js';

const NOW = Date.now();
const SELECTOR = { protocol: 'mcp', tool: 'release_payment' };
const ACTION = {
  action_type: 'payment.release',
  amount_usd: 40,
  currency: 'USD',
  payment_instruction_id: 'pi_capability_gate',
  beneficiary_account_hash: 'sha256:capability-beneficiary',
};

function fixture({ budget = 100, baseAction = ACTION } = {}) {
  const harness = createEg1Harness({ action: baseAction, now: () => NOW, idPrefix: 'cap-gate' });
  const issuer = generateKeyPairSync('ed25519');
  const issuerPublicKey = issuer.publicKey.export({ type: 'spki', format: 'der' }).toString('base64url');
  const baseReceipt = harness.mint({ outcome: 'allow_with_signoff' });
  const capability = mintCapabilityReceipt(baseReceipt, {
    issuerPrivateKey: issuer.privateKey,
    budget: { amount: budget, currency: 'USD' },
    expiry: NOW + 60_000,
    secret: Buffer.alloc(32, 7),
    capabilityId: `cap_${budget}`,
  });
  const capabilityStore = createMemoryCapabilityStore();
  assert.equal(capabilityStore.registerCapability(capability.capabilityReceipt), true);
  const runtimeMonitor = createRuntimeMonitor({ now: () => NOW });
  const gate = createGate({
    manifest: createDefaultActionRiskManifest(),
    trustedKeys: [harness.publicKey],
    approverKeys: harness.approverKeys,
    quorumPolicy: harness.quorumPolicy,
    rpId: harness.rpId,
    allowedOrigins: harness.allowedOrigins,
    capabilityStore,
    capabilityTrustedIssuerKeys: [issuerPublicKey],
    runtimeMonitor,
    allowEphemeralStore: true,
    now: () => NOW,
  });
  return { gate, harness, capabilityStore, capability, action: baseAction, runtimeMonitor };
}

function request(fixtureValue, { operationId, amount = 40, action = fixtureValue.action } = {}) {
  return {
    selector: SELECTOR,
    observedAction: action,
    capability: {
      capabilityReceipt: fixtureValue.capability.capabilityReceipt,
      secret: fixtureValue.capability.secret,
      action: { amount, currency: 'USD' },
      operationId,
    },
  };
}

test('gate capability path reserves and commits budget around the effect', async () => {
  const f = fixture();
  let effects = 0;
  const first = await f.gate.run(request(f, { operationId: 'cap-op-1' }), async () => {
    effects += 1;
    return 'settled';
  });

  assert.equal(first.ok, true, first.capability?.reason || first.authorization?.reason);
  assert.equal(first.result, 'settled');
  assert.equal(effects, 1);
  assert.equal(f.capabilityStore.getState('cap_100').consumed_amount, 40);
  assert.equal(f.capabilityStore.getOperation('cap-op-1').outcome, 'executed');
  assert.equal(first.authorization.evidence.consumption_mode, 'none');
  assert.equal(f.gate.evidence.verify().ok, true);
});

test('gate capability path refuses overspend before the effect', async () => {
  const f = fixture({ budget: 30 });
  let effects = 0;
  const out = await f.gate.run(request(f, { operationId: 'cap-op-too-large' }), async () => {
    effects += 1;
  });

  assert.equal(out.ok, false);
  assert.equal(out.capability.reason, 'budget_exceeded');
  assert.equal(out.status, 409);
  assert.equal(effects, 0);
  assert.equal(f.capabilityStore.getState('cap_30').consumed_amount, 0);
  assert.equal(f.runtimeMonitor.getMode(), 'normal');
});

test('gate capability path refuses a missing stable operation id before the effect', async () => {
  const f = fixture();
  let effects = 0;
  const out = await f.gate.run(request(f), async () => {
    effects += 1;
  });

  assert.equal(out.ok, false);
  assert.equal(out.capability.reason, 'capability_operation_id_required');
  assert.equal(effects, 0);
  assert.equal(f.capabilityStore.getState('cap_100').consumed_amount, 0);
});

test('capability-enabled gate requires an explicit role-scoped issuer pin', () => {
  const f = fixture();
  assert.throws(
    () => createGate({
      manifest: createDefaultActionRiskManifest(),
      trustedKeys: [f.harness.publicKey],
      approverKeys: f.harness.approverKeys,
      quorumPolicy: f.harness.quorumPolicy,
      rpId: f.harness.rpId,
      allowedOrigins: f.harness.allowedOrigins,
      capabilityStore: createMemoryCapabilityStore(),
      allowEphemeralStore: true,
    }),
    /capabilityTrustedIssuerKeys must explicitly pin/,
  );
});

test('gate capability path refuses operation replay while allowing a new bounded spend', async () => {
  const f = fixture();
  let effects = 0;
  const run = (operationId) => f.gate.run(request(f, { operationId, amount: 40 }), async () => {
    effects += 1;
    return effects;
  });

  const first = await run('cap-replay');
  const replay = await run('cap-replay');
  const secondOperation = await run('cap-second');

  assert.equal(first.ok, true);
  assert.equal(replay.ok, false);
  assert.equal(replay.capability.reason, 'operation_already_committed');
  assert.equal(secondOperation.ok, true);
  assert.equal(effects, 2);
  assert.equal(f.capabilityStore.getState('cap_100').consumed_amount, 80);
});

test('gate capability path binds the spend amount to the observed action', async () => {
  const f = fixture({ baseAction: { ...ACTION, amount_usd: 41 } });
  let effects = 0;
  const out = await f.gate.run(request(f, { operationId: 'cap-binding', amount: 40 }), async () => {
    effects += 1;
  });

  assert.equal(out.ok, false);
  assert.equal(out.authorization.reason, 'capability_action_binding_failed');
  assert.equal(effects, 0);
  assert.equal(f.capabilityStore.getState('cap_100').consumed_amount, 0);
});

test('gate capability path burns an indeterminate spend if the effect throws', async () => {
  const f = fixture();
  let effects = 0;
  await assert.rejects(
    () => f.gate.run(request(f, { operationId: 'cap-indeterminate' }), async () => {
      effects += 1;
      throw new Error('provider response lost');
    }),
    /provider response lost/,
  );

  assert.equal(effects, 1);
  assert.equal(f.capabilityStore.getState('cap_100').consumed_amount, 40);
  assert.equal(f.capabilityStore.getOperation('cap-indeterminate').outcome, 'indeterminate');
  assert.equal(f.gate.evidence.all().find((entry) => entry.kind === 'execution')?.outcome, 'indeterminate');
});

test('guard() can source a capability and still refuses its replay', async () => {
  const f = fixture();
  let effects = 0;
  const release = f.gate.guard(async () => {
    effects += 1;
    return 'settled';
  }, {
    selector: SELECTOR,
    observedAction: f.action,
    capability: () => ({
      capabilityReceipt: f.capability.capabilityReceipt,
      secret: f.capability.secret,
      action: { amount: 40, currency: 'USD' },
      operationId: 'cap-guard-replay',
    }),
  });

  assert.equal(await release(), 'settled');
  await assert.rejects(() => release(), /EMILIA Gate refused \(operation_already_committed\)/);
  assert.equal(effects, 1);
});
