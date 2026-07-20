// SPDX-License-Identifier: Apache-2.0
import { describe, expect, it } from 'vitest';
import { loadTenantApprovalQueue, replayApprovalQueue } from './approval-queue.js';

const TENANT_ID = 'tenant_a';
const NOW = '2026-07-19T12:00:00.000Z';

function queryResult(result, calls) {
  const chain = {
    select(value) { calls.push(['select', value]); return chain; },
    eq(field, value) { calls.push(['eq', field, value]); return chain; },
    contains(field, value) { calls.push(['contains', field, value]); return chain; },
    like(field, value) { calls.push(['like', field, value]); return chain; },
    in(field, value) { calls.push(['in', field, value]); return chain; },
    order(field, value) { calls.push(['order', field, value]); return chain; },
    limit(value) { calls.push(['limit', value]); return Promise.resolve(result); },
  };
  return chain;
}

function created(receiptId, overrides = {}) {
  const actorId = overrides.actor_id ?? 'ep:cloud-key:payments';
  const afterState = {
    organization_id: TENANT_ID,
    action_hash: `sha256:${receiptId}`,
    action_type: 'large_payment_release',
    amount: 125000,
    currency: 'USD',
    target_resource_id: `wire:${receiptId}`,
    expires_at: '2026-07-20T12:00:00.000Z',
    canonical_action: {
      counterparty_name: 'Acme Treasury',
      action_caid: 'caid:1:payment.release.1:jcs-sha256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA',
      payment_destination_hash: `sha256:${'1'.repeat(64)}`,
      nonce: 'do-not-return',
      before_state: { balance: 1 },
      after_state: { balance: 0 },
    },
    ...overrides.after_state,
  };
  return {
    event_type: 'guard.trust_receipt.created',
    target_id: receiptId,
    actor_id: actorId,
    after_state: afterState,
    created_at: overrides.created_at ?? '2026-07-19T10:00:00.000Z',
  };
}

function requested(receiptId, overrides = {}) {
  return {
    event_type: 'guard.signoff.requested',
    target_id: receiptId,
    actor_id: overrides.actor_id ?? 'ep:cloud-key:payments',
    after_state: {
      signoff_id: overrides.signoff_id ?? `sig_${receiptId}`,
      approver_id: overrides.approver_id ?? 'ep:approver:cfo',
      action_hash: overrides.action_hash ?? `sha256:${receiptId}`,
      expires_at: overrides.expires_at ?? '2026-07-19T16:00:00.000Z',
    },
    created_at: overrides.created_at ?? '2026-07-19T10:01:00.000Z',
  };
}

function decision(receiptId, kind, overrides = {}) {
  return {
    event_type: `guard.signoff.${kind}`,
    target_id: receiptId,
    actor_id: overrides.actor_id ?? 'ep:approver:cfo',
    after_state: {
      signoff_id: overrides.signoff_id ?? `sig_${receiptId}`,
      approver_id: overrides.approver_id ?? 'ep:approver:cfo',
    },
    created_at: overrides.created_at ?? '2026-07-19T10:02:00.000Z',
  };
}

describe('tenant-scoped large-payment approval queue', () => {
  it('fails closed without storage or an authenticated tenant scope', async () => {
    const withoutStorage = await loadTenantApprovalQueue({ tenantId: TENANT_ID });
    expect(withoutStorage.approvals).toEqual([]);
    expect(withoutStorage.error).toMatch(/storage unavailable/i);

    const fromCalls = [];
    const withoutTenant = await loadTenantApprovalQueue({
      supabase: { from(table) { fromCalls.push(table); } },
      tenantId: null,
    });
    expect(withoutTenant.approvals).toEqual([]);
    expect(withoutTenant.error).toMatch(/tenant scope/i);
    expect(fromCalls).toEqual([]);
  });

  it('establishes tenant receipt ids before loading their timelines', async () => {
    const receiptId = 'tr_owned';
    const firstCalls = [];
    const secondCalls = [];
    let query = 0;
    const supabase = {
      from(table) {
        expect(table).toBe('audit_events');
        query += 1;
        if (query === 1) {
          return queryResult({ data: [{ target_id: receiptId }], error: null }, firstCalls);
        }
        return queryResult({
          data: [created(receiptId), requested(receiptId)],
          error: null,
        }, secondCalls);
      },
    };

    const result = await loadTenantApprovalQueue({
      supabase,
      tenantId: TENANT_ID,
      now: NOW,
    });

    expect(result.error).toBeNull();
    expect(result.approvals.map((request) => request.receipt_id)).toEqual([receiptId]);
    expect(firstCalls).toContainEqual(['eq', 'event_type', 'guard.trust_receipt.created']);
    expect(firstCalls).toContainEqual(['contains', 'after_state', { organization_id: TENANT_ID }]);
    expect(firstCalls).toContainEqual(['eq', 'after_state->>action_type', 'large_payment_release']);
    expect(firstCalls).toContainEqual(['like', 'actor_id', 'ep:cloud-key:%']);
    expect(secondCalls).toContainEqual(['in', 'target_id', [receiptId]]);
  });

  it('re-checks tenant, action type, and cloud-key creator when storage is overbroad', () => {
    const events = [
      created('owned'),
      requested('owned'),
      created('foreign', { after_state: { organization_id: 'tenant_b' } }),
      requested('foreign'),
      created('wrong_action', { after_state: { action_type: 'policy_rollout' } }),
      requested('wrong_action'),
      created('wrong_creator', { actor_id: 'ep:user:alice' }),
      requested('wrong_creator', { actor_id: 'ep:user:alice' }),
    ];

    const requests = replayApprovalQueue(
      events,
      ['owned', 'foreign', 'wrong_action', 'wrong_creator'],
      TENANT_ID,
      NOW,
    );

    expect(requests.map((request) => request.receipt_id)).toEqual(['owned']);
  });

  it('derives pending, approved, rejected, expired, and consumed from bound events', () => {
    const consumed = {
      event_type: 'guard.trust_receipt.consumed',
      target_id: 'consumed',
      actor_id: 'ep:executor:payments',
      after_state: {
        action_hash: 'sha256:consumed',
        consumed_at: '2026-07-19T10:03:00.000Z',
      },
      created_at: '2026-07-19T10:03:00.000Z',
    };
    const events = [
      created('pending'),
      requested('pending'),
      decision('pending', 'approved', { signoff_id: 'sig_spoofed' }),

      created('approved'),
      requested('approved'),
      decision('approved', 'approved'),

      created('rejected'),
      requested('rejected'),
      decision('rejected', 'rejected'),

      created('expired'),
      requested('expired', { expires_at: '2026-07-19T11:59:59.000Z' }),

      created('consumed'),
      requested('consumed'),
      decision('consumed', 'approved'),
      consumed,
    ];

    const requests = replayApprovalQueue(
      events,
      ['pending', 'approved', 'rejected', 'expired', 'consumed'],
      TENANT_ID,
      NOW,
    );
    const statuses = Object.fromEntries(requests.map((request) => [request.receipt_id, request.status]));

    expect(statuses).toEqual({
      pending: 'pending',
      approved: 'approved',
      rejected: 'rejected',
      expired: 'expired',
      consumed: 'consumed',
    });
  });

  it('ignores decisions not bound to the creator request or intended approver', () => {
    const receiptId = 'bound';
    const requests = replayApprovalQueue([
      created(receiptId),
      requested(receiptId),
      requested(receiptId, {
        actor_id: 'ep:cloud-key:attacker',
        signoff_id: 'sig_attacker',
        approver_id: 'ep:approver:attacker',
      }),
      decision(receiptId, 'approved', {
        signoff_id: 'sig_attacker',
        approver_id: 'ep:approver:attacker',
        actor_id: 'ep:approver:attacker',
      }),
      decision(receiptId, 'approved', {
        approver_id: 'ep:approver:wrong',
        actor_id: 'ep:approver:wrong',
      }),
    ], [receiptId], TENANT_ID, NOW);

    expect(requests).toHaveLength(1);
    expect(requests[0].status).toBe('pending');
    expect(requests[0].signoff_id).toBe('sig_bound');
    expect(requests[0].approver_id).toBe('ep:approver:cfo');
  });

  it('fails closed when the creator request has no action-hash binding', () => {
    const receiptId = 'missing_hash';
    const requests = replayApprovalQueue([
      created(receiptId, { after_state: { action_hash: '' } }),
      requested(receiptId, { action_hash: '' }),
    ], [receiptId], TENANT_ID, NOW);

    expect(requests).toEqual([]);
  });

  it('ignores consume events that are not bound to the created action hash', () => {
    const receiptId = 'consume_binding';
    const [request] = replayApprovalQueue([
      created(receiptId),
      requested(receiptId),
      decision(receiptId, 'approved'),
      {
        event_type: 'guard.trust_receipt.consumed',
        target_id: receiptId,
        actor_id: 'ep:executor:payments',
        after_state: {
          action_hash: 'sha256:different-action',
          consumed_at: '2026-07-19T10:03:00.000Z',
        },
        created_at: '2026-07-19T10:03:00.000Z',
      },
    ], [receiptId], TENANT_ID, NOW);

    expect(request.status).toBe('approved');
    expect(request.consumed_at).toBeNull();
  });

  it('returns only the console-safe projection', () => {
    const receiptId = 'safe';
    const [request] = replayApprovalQueue([
      created(receiptId),
      requested(receiptId),
    ], [receiptId], TENANT_ID, NOW);

    expect(request).toEqual({
      receipt_id: receiptId,
      action_hash: `sha256:${receiptId}`,
      action_caid: 'caid:1:payment.release.1:jcs-sha256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA',
      action_type: 'large_payment_release',
      amount: 125000,
      currency: 'USD',
      counterparty_name: 'Acme Treasury',
      target_resource_id: `wire:${receiptId}`,
      payment_destination_hash: `sha256:${'1'.repeat(64)}`,
      created_at: '2026-07-19T10:00:00.000Z',
      expires_at: '2026-07-19T16:00:00.000Z',
      status: 'pending',
      signoff_id: `sig_${receiptId}`,
      approver_id: 'ep:approver:cfo',
      review_path: `/signoff/sig_${receiptId}`,
      consumed_at: null,
    });
    expect(request).not.toHaveProperty('canonical_action');
    expect(request).not.toHaveProperty('nonce');
    expect(request).not.toHaveProperty('before_state');
    expect(request).not.toHaveProperty('after_state');
  });
});
