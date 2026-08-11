#!/usr/bin/env node
// SPDX-License-Identifier: Apache-2.0
/**
 * Synthetic Dodo Payments refund fixture.
 *
 * This exercises the documented `client.refunds.create(...)` request shape
 * against EMILIA Gate without calling Dodo Payments or using an API key. It is
 * a compatibility fixture, not a Dodo implementation or endorsement.
 */
import assert from 'node:assert/strict';
import { createEg1Harness, createGate } from '../../packages/gate/index.js';
import { createAdapter, manifestFromPack } from '../../packages/gate/adapters/_kit.js';

export const DODO_REFUND_FIXTURE_VERSION = 'EP-DODO-REFUND-GATE-FIXTURE-v1';

export const EXACT_REFUND = Object.freeze({
  action_type: 'dodo.refund.create',
  payment_id: 'pay_test_001',
  items: Object.freeze([
    Object.freeze({ item_id: 'item_test_001', amount: 1_250, tax_inclusive: true }),
  ]),
  metadata: Object.freeze({ case: 'synthetic-review' }),
  reason: 'duplicate order',
});

const ACTION_PACK = Object.freeze([
  Object.freeze({
    id: 'dodo.refund.create',
    label: 'Dodo Payments refund',
    action_type: 'dodo.refund.create',
    risk: 'high',
    receipt_required: true,
    assurance_class: 'class_a',
    match: { protocol: 'dodo', tool: 'create_refund' },
    why: 'Returns funds. Bind every material request field before provider entry.',
    execution_binding: {
      required_fields: [
        'action_type',
        'payment_id',
        'items',
        'metadata',
        'reason',
      ],
    },
  }),
]);

const OPS = Object.freeze({
  'refund.create': Object.freeze({
    selector: Object.freeze({ protocol: 'dodo', tool: 'create_refund' }),
    observed: (params: any) => ({
      action_type: 'dodo.refund.create',
      payment_id: params.payment_id,
      items: params.items ?? null,
      metadata: params.metadata ?? {},
      reason: params.reason ?? null,
    }),
    perform: (client: any, action: any) => client.refunds.create({
      payment_id: action.payment_id,
      items: action.items,
      metadata: action.metadata,
      reason: action.reason,
    }),
  }),
});

const adapter = createAdapter({ system: 'dodo', ops: OPS });

function requestFrom(action: any = EXACT_REFUND) {
  return {
    payment_id: action.payment_id,
    items: structuredClone(action.items),
    metadata: structuredClone(action.metadata),
    reason: action.reason,
  };
}

function makeSubject({
  action = EXACT_REFUND,
  providerMode = 'success',
  idPrefix = 'dodo-refund',
}: {
  action?: any;
  providerMode?: 'success' | 'timeout';
  idPrefix?: string;
} = {}) {
  let nowMs = Date.parse('2026-08-10T12:00:00.000Z');
  const clock = () => nowMs;
  const harness = createEg1Harness({ action, idPrefix, now: clock });
  const gate = createGate({
    manifest: manifestFromPack(ACTION_PACK),
    trustedKeys: [harness.publicKey],
    approverKeys: harness.approverKeys,
    quorumPolicy: harness.quorumPolicy,
    rpId: harness.rpId,
    allowedOrigins: harness.allowedOrigins,
    maxAgeSec: 300,
    allowEphemeralStore: true,
    now: clock,
  });
  const calls: any[] = [];
  const client = {
    refunds: {
      create: async (params: any) => {
        calls.push(structuredClone(params));
        if (providerMode === 'timeout') throw new Error('synthetic_provider_timeout');
        return {
          refund_id: 'ref_test_001',
          payment_id: params.payment_id,
          status: 'succeeded',
          amount: params.items[0].amount,
        };
      },
    },
  };
  return {
    calls,
    client,
    gate,
    harness,
    advance(ms: number) { nowMs += ms; },
    run(params: any, receipt: any) {
      return adapter.guard(gate, client, {
        op: 'refund.create',
        params,
        receipt,
      });
    },
  };
}

function refusalReason(error: any) {
  return error?.gate?.reason
    || error?.emiliaGateOutcome?.reason
    || error?.message
    || 'unknown_refusal';
}

export async function runDodoRefundFixture() {
  const cases: any[] = [];

  const accepted = makeSubject({ idPrefix: 'dodo-accepted' });
  const acceptedReceipt = accepted.harness.mint({ outcome: 'allow_with_signoff' });
  const acceptedResult = await accepted.run(requestFrom(), acceptedReceipt);
  assert.equal(accepted.calls.length, 1);
  cases.push({
    id: 'exact-refund-admitted',
    expected: 'EXECUTED',
    observed: acceptedResult.result.status,
    provider_calls: accepted.calls.length,
  });

  const drift = makeSubject({ idPrefix: 'dodo-drift' });
  const driftReceipt = drift.harness.mint({ outcome: 'allow_with_signoff' });
  const changed = requestFrom();
  changed.items[0].amount = 5_000;
  await assert.rejects(
    () => drift.run(changed, driftReceipt),
    (error: any) => {
      cases.push({
        id: 'approve-a-execute-b-refused',
        expected: 'REFUSED',
        observed: refusalReason(error),
        provider_calls: drift.calls.length,
      });
      return /binding/.test(refusalReason(error));
    },
  );
  assert.equal(drift.calls.length, 0);

  const expired = makeSubject({ idPrefix: 'dodo-expired' });
  const expiredReceipt = expired.harness.mint({ outcome: 'allow_with_signoff' });
  expired.advance(301_000);
  await assert.rejects(
    () => expired.run(requestFrom(), expiredReceipt),
    (error: any) => {
      cases.push({
        id: 'expired-authority-refused',
        expected: 'REFUSED',
        observed: refusalReason(error),
        provider_calls: expired.calls.length,
      });
      return /stale|expired/i.test(refusalReason(error));
    },
  );
  assert.equal(expired.calls.length, 0);

  const replay = makeSubject({ idPrefix: 'dodo-replay' });
  const replayReceipt = replay.harness.mint({ outcome: 'allow_with_signoff' });
  await replay.run(requestFrom(), replayReceipt);
  await assert.rejects(
    () => replay.run(requestFrom(), replayReceipt),
    (error: any) => {
      cases.push({
        id: 'replay-refused',
        expected: 'REFUSED',
        observed: refusalReason(error),
        provider_calls: replay.calls.length,
      });
      return /replay/i.test(refusalReason(error));
    },
  );
  assert.equal(replay.calls.length, 1);

  const timedOut = makeSubject({ providerMode: 'timeout', idPrefix: 'dodo-timeout' });
  const timeoutReceipt = timedOut.harness.mint({ outcome: 'allow_with_signoff' });
  await assert.rejects(
    () => timedOut.run(requestFrom(), timeoutReceipt),
    (error: any) => {
      assert.equal(error?.emiliaGateOutcome?.outcome, 'indeterminate');
      cases.push({
        id: 'provider-timeout-is-indeterminate',
        expected: 'INDETERMINATE',
        observed: error.emiliaGateOutcome.reason,
        provider_calls: timedOut.calls.length,
      });
      return true;
    },
  );
  await assert.rejects(
    () => timedOut.run(requestFrom(), timeoutReceipt),
    (error: any) => /replay/i.test(refusalReason(error)),
  );
  assert.equal(timedOut.calls.length, 1);

  return {
    '@version': DODO_REFUND_FIXTURE_VERSION,
    disclaimer: 'Synthetic compatibility fixture. No Dodo API call or credential is used.',
    documented_provider_call: 'client.refunds.create({ payment_id, items, metadata, reason })',
    action: EXACT_REFUND,
    cases,
    invariant: 'Only the exact, current, unused refund authority reaches one provider attempt; a lost response is INDETERMINATE and is not blindly retried.',
  };
}

if (process.argv[1] && import.meta.url === new URL(`file://${process.argv[1]}`).href) {
  const result = await runDodoRefundFixture();
  console.log(JSON.stringify(result, null, 2));
}

