// SPDX-License-Identifier: Apache-2.0
import { describe, expect, it } from 'vitest';
import { loadTenantGuardReceipts, replayGuardReceipts } from './guard-receipts.js';

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

describe('tenant-scoped Guard receipt dashboard', () => {
  it('fails closed without an authenticated tenant scope', async () => {
    const fromCalls = [];
    const result = await loadTenantGuardReceipts({
      supabase: { from(table) { fromCalls.push(table); } },
      tenantId: null,
    });
    expect(result.receipts).toEqual([]);
    expect(result.error).toMatch(/tenant scope/i);
    expect(fromCalls).toEqual([]);
  });

  it('establishes tenant-owned receipt ids before querying their timelines', async () => {
    const firstCalls = [];
    const secondCalls = [];
    let query = 0;
    const supabase = {
      from(table) {
        expect(table).toBe('audit_events');
        query += 1;
        if (query === 1) return queryResult({ data: [{ target_id: 'rcpt_owned' }], error: null }, firstCalls);
        return queryResult({
          data: [{
            event_type: 'guard.trust_receipt.created',
            target_id: 'rcpt_owned',
            actor_id: 'agent',
            after_state: { organization_id: 'tenant_a', action_type: 'payment.release', receipt_status: 'issued' },
            created_at: '2026-07-16T12:00:00.000Z',
          }],
          error: null,
        }, secondCalls);
      },
    };
    const result = await loadTenantGuardReceipts({ supabase, tenantId: 'tenant_a' });
    expect(result.error).toBeNull();
    expect(result.receipts.map((receipt) => receipt.receipt_id)).toEqual(['rcpt_owned']);
    expect(firstCalls).toContainEqual(['eq', 'event_type', 'guard.trust_receipt.created']);
    expect(firstCalls).toContainEqual(['contains', 'after_state', { organization_id: 'tenant_a' }]);
    expect(secondCalls).toContainEqual(['in', 'target_id', ['rcpt_owned']]);
  });

  it('drops cross-tenant rows even if the storage response is overbroad', () => {
    const receipts = replayGuardReceipts([
      { event_type: 'guard.trust_receipt.created', target_id: 'owned', after_state: { organization_id: 'tenant_a' }, created_at: '2026-07-16T12:00:00Z' },
      { event_type: 'guard.trust_receipt.created', target_id: 'foreign', after_state: { organization_id: 'tenant_b' }, created_at: '2026-07-16T12:01:00Z' },
    ], ['owned']);
    expect(receipts.map((receipt) => receipt.receipt_id)).toEqual(['owned']);
  });
});
