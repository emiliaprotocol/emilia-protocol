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
    gte(field, value) { calls.push(['gte', field, value]); return chain; },
    lte(field, value) { calls.push(['lte', field, value]); return chain; },
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

  it('fails closed without an authenticated environment scope', async () => {
    const fromCalls = [];
    const result = await loadTenantGuardReceipts({
      supabase: { from(table) { fromCalls.push(table); } },
      tenantId: 'tenant_a',
      environment: null,
    });
    expect(result.receipts).toEqual([]);
    expect(result.error).toMatch(/environment scope/i);
    expect(fromCalls).toEqual([]);
  });

  it('authorizes exact event ids through tenant/environment bindings before loading audit rows', async () => {
    const firstCalls = [];
    const secondCalls = [];
    const thirdCalls = [];
    const tables = [];
    let query = 0;
    const createdBinding = {
      event_id: 'event-created',
      receipt_id: 'rcpt_owned',
      tenant_id: 'tenant_a',
      environment: 'production',
      event_type: 'guard.trust_receipt.created',
      event_created_at: '2026-07-16T12:00:00.000Z',
    };
    const supabase = {
      from(table) {
        tables.push(table);
        query += 1;
        if (query === 1) return queryResult({ data: [createdBinding], error: null }, firstCalls);
        if (query === 2) return queryResult({ data: [createdBinding], error: null }, secondCalls);
        return queryResult({
          data: [{
            id: 'event-created',
            event_type: 'guard.trust_receipt.created',
            target_id: 'rcpt_owned',
            actor_id: 'agent',
            after_state: { organization_id: 'tenant_a', action_type: 'payment.release', receipt_status: 'issued' },
            created_at: '2026-07-16T12:00:00.000Z',
          }],
          error: null,
        }, thirdCalls);
      },
    };
    const result = await loadTenantGuardReceipts({
      supabase,
      tenantId: 'tenant_a',
      environment: 'production',
    });
    expect(result.error).toBeNull();
    expect(result.receipts.map((receipt) => receipt.receipt_id)).toEqual(['rcpt_owned']);
    expect(tables).toEqual([
      'guard_receipt_event_bindings',
      'guard_receipt_event_bindings',
      'audit_events',
    ]);
    expect(firstCalls).toContainEqual(['eq', 'event_type', 'guard.trust_receipt.created']);
    expect(firstCalls).toContainEqual(['eq', 'tenant_id', 'tenant_a']);
    expect(firstCalls).toContainEqual(['eq', 'environment', 'production']);
    expect(secondCalls).toContainEqual(['eq', 'tenant_id', 'tenant_a']);
    expect(secondCalls).toContainEqual(['eq', 'environment', 'production']);
    expect(secondCalls).toContainEqual(['in', 'receipt_id', ['rcpt_owned']]);
    expect(thirdCalls).toContainEqual(['in', 'id', ['event-created']]);
    expect(thirdCalls.some((call) => call[1] === 'target_id')).toBe(false);
  });

  it('drops cross-tenant rows even if the storage response is overbroad', () => {
    const receipts = replayGuardReceipts([
      { event_type: 'guard.trust_receipt.created', target_id: 'owned', tenant_id: 'tenant_a', environment: 'production', after_state: { organization_id: 'tenant_a' }, created_at: '2026-07-16T12:00:00Z' },
      { event_type: 'guard.trust_receipt.created', target_id: 'foreign', tenant_id: 'tenant_b', environment: 'production', after_state: { organization_id: 'tenant_b' }, created_at: '2026-07-16T12:01:00Z' },
    ], ['owned'], 'tenant_a', 'production');
    expect(receipts.map((receipt) => receipt.receipt_id)).toEqual(['owned']);
  });

  it('requires the replayed creation event itself to match the authenticated tenant', () => {
    const receipts = replayGuardReceipts([
      { event_type: 'guard.trust_receipt.created', target_id: 'collision', tenant_id: 'tenant_b', environment: 'production', after_state: { organization_id: 'tenant_b' }, created_at: '2026-07-16T12:00:00Z' },
      { event_type: 'guard.trust_receipt.consumed', target_id: 'collision', tenant_id: 'tenant_a', environment: 'production', after_state: {}, created_at: '2026-07-16T12:01:00Z' },
    ], ['collision'], 'tenant_a', 'production');
    expect(receipts).toEqual([]);
  });

  it('does not let a same-target foreign lifecycle event alter an owned snapshot', () => {
    const receipts = replayGuardReceipts([
      {
        event_type: 'guard.trust_receipt.created',
        target_id: 'collision',
        tenant_id: 'tenant_a',
        environment: 'production',
        after_state: { organization_id: 'tenant_a', receipt_status: 'issued' },
        created_at: '2026-07-16T12:00:00Z',
      },
      {
        event_type: 'guard.trust_receipt.consumed',
        target_id: 'collision',
        tenant_id: 'tenant_b',
        environment: 'production',
        after_state: {},
        created_at: '2026-07-16T12:01:00Z',
      },
      {
        event_type: 'guard.trust_receipt.consumed',
        target_id: 'collision',
        tenant_id: 'tenant_a',
        environment: 'staging',
        after_state: {},
        created_at: '2026-07-16T12:02:00Z',
      },
    ], ['collision'], 'tenant_a', 'production');

    expect(receipts).toHaveLength(1);
    expect(receipts[0].status).toBe('issued');
  });

  it('bounds and date-scopes the tenant-owned receipt prequery', async () => {
    const firstCalls = [];
    const supabase = {
      from() {
        return queryResult({ data: [], error: null }, firstCalls);
      },
    };
    const result = await loadTenantGuardReceipts({
      supabase,
      tenantId: 'tenant_a',
      environment: 'production',
      limit: 25,
      dateFrom: '2026-07-01T00:00:00Z',
      dateTo: '2026-07-21T00:00:00Z',
    });
    expect(result.error).toBeNull();
    expect(firstCalls).toContainEqual(['gte', 'event_created_at', '2026-07-01T00:00:00Z']);
    expect(firstCalls).toContainEqual(['lte', 'event_created_at', '2026-07-21T00:00:00Z']);
    expect(firstCalls).toContainEqual(['limit', 25]);
  });
});
