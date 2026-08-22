// SPDX-License-Identifier: Apache-2.0

import test from 'node:test';
import assert from 'node:assert/strict';
import {
  composeProviderEntryGuards,
  createOrganizationStatusProviderEntryGuard,
  evaluateProviderEntryGuard,
  providerEntryContext,
  createDefaultActionRiskManifest,
  createEg1Harness,
  createGate,
} from './index.js';

const NOW = Date.parse('2026-08-03T12:00:00.000Z');
const ACTION = {
  action_type: 'payment.release',
  amount_usd: 40,
  amount: 40,
  amount_minor: 4_000,
  currency: 'USD',
  payment_instruction_id: 'pi_provider_entry',
  beneficiary_account_hash: 'sha256:provider-entry-beneficiary',
};
const SELECTOR = { protocol: 'mcp', tool: 'release_payment' };

test('provider-entry context is immutable and a throwing guard fails closed', async () => {
  const context = providerEntryContext({
    authorization: { allow: true },
    selector: SELECTOR,
    observedAction: ACTION,
    now: NOW,
  });
  assert.equal(context.checked_at, '2026-08-03T12:00:00.000Z');
  assert.equal(Object.isFrozen(context.observed_action), true);
  assert.throws(() => { (context.observed_action as any).amount = 1; }, TypeError);
  assert.deepEqual(
    await evaluateProviderEntryGuard(async () => { throw new Error('status down'); }, context),
    { ok: false, reason: 'provider_entry_guard_unavailable', status: 503, reservation: 'hold' },
  );
});

test('every unavailable or malformed provider-entry refusal pins the reservation to hold', async () => {
  const context = providerEntryContext({ authorization: {}, now: NOW });
  for (const guard of [
    'not-a-function' as any,
    async () => null as any,
    async () => ({ ok: 'yes' }) as any,
    async () => { throw new Error('status down'); },
  ]) {
    const result = await evaluateProviderEntryGuard(guard, context);
    assert.equal(result.ok, false);
    assert.equal(result.reservation, 'hold');
  }
});

test('organization status guard refuses stale, mismatched, unauthenticated, and suspended state', async () => {
  let observation: any = {
    organization_id: 'org_a',
    status: 'active',
    epoch: 4,
    observed_at: new Date(NOW).toISOString(),
    authenticated: true,
  };
  const guard = createOrganizationStatusProviderEntryGuard({
    organizationId: 'org_a',
    resolveStatus: async () => observation,
    now: NOW,
  });
  const context = providerEntryContext({ authorization: {}, now: NOW });
  assert.equal((await guard(context)).ok, true);
  observation = { ...observation, status: 'suspended', epoch: 5 };
  assert.deepEqual(await guard(context), {
    ok: false,
    reason: 'organization_suspended',
    status: 423,
    reservation: 'burn',
    evidence: { organization_id: 'org_a', status: 'suspended', epoch: 5 },
  });
  for (const [candidate, reason] of [
    [{ ...observation, status: 'active', authenticated: false }, 'organization_status_unauthenticated'],
    [{ ...observation, status: 'active', authenticated: true, organization_id: 'org_b' }, 'organization_status_mismatch'],
    [{ ...observation, status: 'active', organization_id: 'org_a', epoch: -1 }, 'organization_status_epoch_invalid'],
    [{ ...observation, status: 'active', organization_id: 'org_a', observed_at: new Date(NOW - 6_000).toISOString() }, 'organization_status_stale'],
  ] as const) {
    observation = candidate;
    const result = await guard(context);
    assert.equal(result.reason, reason);
    assert.equal(result.reservation, 'hold');
  }

  const unavailable = createOrganizationStatusProviderEntryGuard({
    organizationId: 'org_a',
    resolveStatus: async () => { throw new Error('status source down'); },
    now: NOW,
  });
  assert.deepEqual(await unavailable(context), {
    ok: false,
    reason: 'organization_status_unavailable',
    status: 503,
    reservation: 'hold',
  });
});

test('composed guards stop at the first refusal and preserve prior evidence', async () => {
  let second = 0;
  const guard = composeProviderEntryGuards(
    async () => ({ ok: true, evidence: { first: true } }),
    async () => { second += 1; return { ok: false, reason: 'panic' }; },
    async () => { throw new Error('must not run'); },
  );
  const result = await guard(providerEntryContext({ now: NOW }));
  assert.equal(result.ok, false);
  assert.equal(result.reason, 'panic');
  assert.equal(second, 1);
});

test('an observation-only organization guard cannot authorize an unserialized Gate path', async () => {
  const harness = createEg1Harness({ action: ACTION, now: () => NOW, idPrefix: 'provider-entry' });
  let status: 'active' | 'suspended' = 'suspended';
  const organizationGuard = createOrganizationStatusProviderEntryGuard({
    organizationId: 'org_a',
    resolveStatus: async () => ({
      organization_id: 'org_a',
      status,
      epoch: status === 'active' ? 2 : 1,
      observed_at: new Date(NOW).toISOString(),
      authenticated: true,
    }),
    now: () => NOW,
  });
  const gate = createGate({
    manifest: createDefaultActionRiskManifest(),
    trustedKeys: [harness.publicKey],
    approverKeys: harness.approverKeys,
    quorumPolicy: harness.quorumPolicy,
    rpId: harness.rpId,
    allowedOrigins: harness.allowedOrigins,
    providerEntryGuard: organizationGuard,
    allowEphemeralStore: true,
    now: () => NOW,
  });
  const receipt = harness.mint({ outcome: 'allow_with_signoff' });
  let effects = 0;
  const first = await gate.run({ selector: SELECTOR, receipt, observedAction: ACTION }, async () => { effects += 1; });
  assert.equal(first.ok, false);
  assert.equal(first.authorization.reason, 'provider_entry_serialized_control_domain_required');
  assert.equal(effects, 0);

  status = 'active';
  const replay = await gate.run({ selector: SELECTOR, receipt, observedAction: ACTION }, async () => { effects += 1; });
  assert.equal(replay.ok, false);
  assert.equal(replay.authorization.reason, 'replay_refused');
  assert.equal(effects, 0);
});
