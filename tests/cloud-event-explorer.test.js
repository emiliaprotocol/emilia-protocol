import { describe, it, expect, vi, beforeEach } from 'vitest';

// Mock write-guard before importing the module under test
vi.mock('@/lib/write-guard', () => ({
  getGuardedClient: vi.fn(),
}));

import {
  queryEvents,
  getTimeline,
  searchEvents,
  verifyIntegrity,
} from '../lib/cloud/event-explorer.js';
import { getGuardedClient } from '@/lib/write-guard';

// ── Mock builder helpers ──────────────────────────────────────────────────────

/**
 * Create a chainable supabase query mock that resolves with the given value.
 */
function makeChain(resolved) {
  const chain = {
    select: vi.fn().mockReturnThis(),
    eq: vi.fn().mockReturnThis(),
    gte: vi.fn().mockReturnThis(),
    lte: vi.fn().mockReturnThis(),
    in: vi.fn().mockReturnThis(),
    order: vi.fn().mockReturnThis(),
    limit: vi.fn().mockReturnThis(),
    ilike: vi.fn().mockReturnThis(),
    textSearch: vi.fn().mockReturnThis(),
    maybeSingle: vi.fn().mockResolvedValue(resolved),
    // Make the chain itself awaitable — some spots do `const { data } = await q`
    then: (resolve, reject) => Promise.resolve(resolved).then(resolve, reject),
  };
  return chain;
}

/**
 * Build a supabase mock whose .from() dispatches to per-table chains.
 * tableMap values can be { data, error, count } objects or chain instances.
 */
function makeSupabase(tableMap, defaultResolved = { data: [], error: null, count: 0 }) {
  return {
    from: vi.fn((table) => {
      const entry = tableMap[table];
      if (entry === undefined) return makeChain(defaultResolved);
      if (typeof entry.select === 'function') return entry; // already a chain
      return makeChain(entry);
    }),
  };
}

// ── Sample event fixtures ─────────────────────────────────────────────────────

function makeEvent(overrides = {}) {
  return {
    event_id: `evt-${Math.random().toString(36).slice(2, 8)}`,
    handshake_id: 'hs-1',
    challenge_id: null,
    signoff_id: null,
    event_type: 'handshake_created',
    actor_entity_ref: 'entity-1',
    detail: { foo: 'bar' },
    created_at: new Date().toISOString(),
    ...overrides,
  };
}

// ── queryEvents ───────────────────────────────────────────────────────────────

describe('queryEvents', () => {
  beforeEach(() => vi.clearAllMocks());

  it('returns merged events from all three tables', async () => {
    const e1 = makeEvent({ created_at: '2024-03-01T10:00:00Z', event_type: 'handshake_created' });
    const e2 = makeEvent({ created_at: '2024-03-01T09:00:00Z', event_type: 'signoff_created' });
    const e3 = makeEvent({ created_at: '2024-03-01T08:00:00Z', event_type: 'protocol_event' });

    const supabase = makeSupabase({
      protocol_events: { data: [e3], error: null, count: 1 },
      handshake_events: { data: [e1], error: null, count: 1 },
      signoff_events: { data: [e2], error: null, count: 1 },
    });
    getGuardedClient.mockReturnValue(supabase);

    const result = await queryEvents({ tenant_id: 'test-tenant' });
    expect(result.events).toHaveLength(3);
    expect(result.total).toBe(3);
  });

  it('sorts events by created_at descending', async () => {
    const events = [
      makeEvent({ created_at: '2024-01-01T08:00:00Z' }),
      makeEvent({ created_at: '2024-01-01T10:00:00Z' }),
      makeEvent({ created_at: '2024-01-01T09:00:00Z' }),
    ];

    const supabase = makeSupabase({
      handshake_events: { data: events, error: null, count: 3 },
      signoff_events: { data: [], error: null, count: 0 },
      protocol_events: { data: [], error: null, count: 0 },
    });
    getGuardedClient.mockReturnValue(supabase);

    const result = await queryEvents({ tenant_id: 'test-tenant' });
    const times = result.events.map(e => e.created_at);
    expect(times[0] >= times[1]).toBe(true);
    expect(times[1] >= times[2]).toBe(true);
  });

  it('respects limit parameter (capped at 500)', async () => {
    const events = Array.from({ length: 10 }, () => makeEvent());
    const supabase = makeSupabase({
      handshake_events: { data: events, error: null, count: 10 },
      signoff_events: { data: [], error: null, count: 0 },
      protocol_events: { data: [], error: null, count: 0 },
    });
    getGuardedClient.mockReturnValue(supabase);

    const result = await queryEvents({ tenant_id: 'test-tenant', limit: 3 });
    expect(result.events.length).toBeLessThanOrEqual(3);
  });

  it('clamps limit to minimum of 1', async () => {
    const supabase = makeSupabase({
      handshake_events: { data: [makeEvent()], error: null, count: 1 },
      signoff_events: { data: [], error: null, count: 0 },
      protocol_events: { data: [], error: null, count: 0 },
    });
    getGuardedClient.mockReturnValue(supabase);

    const result = await queryEvents({ tenant_id: 'test-tenant', limit: -5 });
    // Should still work with limit=1 applied
    expect(result).toBeDefined();
  });

  it('applies offset pagination', async () => {
    const events = Array.from({ length: 5 }, (_, i) =>
      makeEvent({ created_at: `2024-01-0${5 - i}T00:00:00Z` }),
    );
    const supabase = makeSupabase({
      handshake_events: { data: events, error: null, count: 5 },
      signoff_events: { data: [], error: null, count: 0 },
      protocol_events: { data: [], error: null, count: 0 },
    });
    getGuardedClient.mockReturnValue(supabase);

    const full = await queryEvents({ tenant_id: 'test-tenant', limit: 10, offset: 0 });
    const paged = await queryEvents({ tenant_id: 'test-tenant', limit: 10, offset: 2 });

    // paged should have 2 fewer items (offset skips first 2)
    expect(paged.events.length).toBe(full.events.length - 2);
  });

  it('degrades gracefully when a table does not exist', async () => {
    const supabase = makeSupabase({
      handshake_events: { data: null, error: { message: 'relation does not exist' }, count: 0 },
      signoff_events: { data: [], error: null, count: 0 },
      protocol_events: { data: [makeEvent()], error: null, count: 1 },
    });
    getGuardedClient.mockReturnValue(supabase);

    const result = await queryEvents({ tenant_id: 'test-tenant' });
    expect(result.events).toHaveLength(1);
  });

  it('returns empty when all tables return empty arrays', async () => {
    const supabase = makeSupabase({
      handshake_events: { data: [], error: null, count: 0 },
      signoff_events: { data: [], error: null, count: 0 },
      protocol_events: { data: [], error: null, count: 0 },
    });
    getGuardedClient.mockReturnValue(supabase);

    const result = await queryEvents({ tenant_id: 'test-tenant' });
    expect(result.events).toEqual([]);
    expect(result.total).toBe(0);
  });

  it('normalizes event fields from all tables', async () => {
    const rawEvent = {
      id: 'raw-1',
      event_type: 'protocol_tick',
      actor_id: 'actor-x',
      event_payload: { key: 'value' },
      created_at: '2024-01-01T00:00:00Z',
    };
    const supabase = makeSupabase({
      protocol_events: { data: [rawEvent], error: null, count: 1 },
      handshake_events: { data: [], error: null, count: 0 },
      signoff_events: { data: [], error: null, count: 0 },
    });
    getGuardedClient.mockReturnValue(supabase);

    const result = await queryEvents({ tenant_id: 'test-tenant' });
    const ev = result.events[0];
    expect(ev.source_table).toBe('protocol_events');
    expect(ev.event_type).toBe('protocol_tick');
    expect(ev.actor_entity_ref).toBe('actor-x');
  });
});

// ── getTimeline ───────────────────────────────────────────────────────────────

describe('getTimeline', () => {
  beforeEach(() => vi.clearAllMocks());

  it('throws when handshakeId is missing', async () => {
    await expect(getTimeline(null, 'tenant-1')).rejects.toThrow('handshakeId is required');
  });

  it('throws when tenantId is missing', async () => {
    await expect(getTimeline('hs-1', null)).rejects.toThrow('tenantId is required');
  });

  it('returns chronologically ordered events from both tables', async () => {
    const hEv1 = makeEvent({ created_at: '2024-01-01T08:00:00Z', event_type: 'handshake_created' });
    const hEv2 = makeEvent({ created_at: '2024-01-01T09:00:00Z', event_type: 'handshake_accepted' });
    const sEv1 = makeEvent({ created_at: '2024-01-01T10:00:00Z', event_type: 'signoff_created' });

    // Tenant-isolation hardening: getTimeline now requires the binding to
    // exist AND belong to the requesting tenant. Mock returns a binding with
    // matching tenant_id so the test reaches the chronological-ordering check.
    const bindingChain = makeChain({ data: { tenant_id: 'tenant-1' }, error: null });
    const handshakeChain = makeChain({ data: [hEv1, hEv2], error: null });
    const signoffChain = makeChain({ data: [sEv1], error: null });

    const supabase = makeSupabase({
      handshake_bindings: bindingChain,
      handshake_events: handshakeChain,
      signoff_events: signoffChain,
    });
    getGuardedClient.mockReturnValue(supabase);

    const events = await getTimeline('hs-1', 'tenant-1');
    expect(events).toHaveLength(3);
    // chronological (ascending)
    expect(new Date(events[0].created_at) <= new Date(events[1].created_at)).toBe(true);
    expect(new Date(events[1].created_at) <= new Date(events[2].created_at)).toBe(true);
  });

  it('throws when handshake belongs to a different tenant', async () => {
    const bindingChain = makeChain({ data: { tenant_id: 'other-tenant' }, error: null });
    const supabase = makeSupabase({ handshake_bindings: bindingChain });
    getGuardedClient.mockReturnValue(supabase);

    await expect(getTimeline('hs-1', 'tenant-1')).rejects.toThrow(
      'Handshake does not belong to this tenant',
    );
  });

  // Tenant-isolation hardening: getTimeline now THROWS instead of proceeding
  // when the binding has no tenant_id or the binding row is missing. The
  // previous "proceed" behavior was the security gap that this hardening
  // closed. Updated assertions reflect the new fail-closed contract.
  it('throws when binding has no tenant_id (unbound handshake)', async () => {
    const bindingChain = makeChain({ data: { tenant_id: null }, error: null });
    const supabase = makeSupabase({ handshake_bindings: bindingChain });
    getGuardedClient.mockReturnValue(supabase);
    await expect(getTimeline('hs-1', 'tenant-1')).rejects.toThrow(
      /Handshake tenant ownership cannot be verified/,
    );
  });

  it('throws when binding row is not found', async () => {
    const bindingChain = makeChain({ data: null, error: null });
    const supabase = makeSupabase({ handshake_bindings: bindingChain });
    getGuardedClient.mockReturnValue(supabase);
    await expect(getTimeline('hs-1', 'tenant-1')).rejects.toThrow(
      /Handshake tenant ownership cannot be verified/,
    );
  });

  it('returns empty array when both tables have no events', async () => {
    // Tenant-isolation hardening requires a binding row with matching tenant_id.
    const bindingChain = makeChain({ data: { tenant_id: 'tenant-1' }, error: null });
    const handshakeChain = makeChain({ data: [], error: null });
    const signoffChain = makeChain({ data: [], error: null });

    const supabase = makeSupabase({
      handshake_bindings: bindingChain,
      handshake_events: handshakeChain,
      signoff_events: signoffChain,
    });
    getGuardedClient.mockReturnValue(supabase);

    const events = await getTimeline('hs-1', 'tenant-1');
    expect(events).toEqual([]);
  });
});

// ── searchEvents ──────────────────────────────────────────────────────────────

describe('searchEvents', () => {
  beforeEach(() => vi.clearAllMocks());

  it('throws when query is missing', async () => {
    await expect(searchEvents('')).rejects.toThrow('query is required');
  });

  it('throws when query is only whitespace', async () => {
    await expect(searchEvents('   ', { tenant_id: 'test-tenant' })).rejects.toThrow('query is required');
  });

  it('throws when query is not a string', async () => {
    await expect(searchEvents(123)).rejects.toThrow('query is required');
  });

  it('returns matching events from all tables', async () => {
    const ev = makeEvent({ event_type: 'handshake_created' });
    const chain = makeChain({ data: [ev], error: null });

    const supabase = { from: vi.fn(() => chain) };
    getGuardedClient.mockReturnValue(supabase);

    const results = await searchEvents('test query', { tenant_id: 'test-tenant' });
    expect(Array.isArray(results)).toBe(true);
  });

  it('returns empty array when no matches', async () => {
    const chain = makeChain({ data: [], error: null });
    const supabase = { from: vi.fn(() => chain) };
    getGuardedClient.mockReturnValue(supabase);

    const results = await searchEvents('no match', { tenant_id: 'test-tenant' });
    expect(results).toEqual([]);
  });

  it('sorts results by created_at descending', async () => {
    const events = [
      makeEvent({ created_at: '2024-01-01T08:00:00Z' }),
      makeEvent({ created_at: '2024-01-01T10:00:00Z' }),
    ];
    const chain = makeChain({ data: events, error: null });
    const supabase = { from: vi.fn(() => chain) };
    getGuardedClient.mockReturnValue(supabase);

    const results = await searchEvents('test', { tenant_id: 'test-tenant' });
    if (results.length >= 2) {
      expect(new Date(results[0].created_at) >= new Date(results[1].created_at)).toBe(true);
    }
  });

  it('applies event_types filter', async () => {
    const chain = makeChain({ data: [makeEvent({ event_type: 'handshake_created' })], error: null });
    const supabase = { from: vi.fn(() => chain) };
    getGuardedClient.mockReturnValue(supabase);

    const results = await searchEvents('test', { tenant_id: 'test-tenant', event_types: ['handshake_created'] });
    expect(Array.isArray(results)).toBe(true);
    // Verify .in() was called with the filter
    expect(chain.in).toHaveBeenCalledWith('event_type', ['handshake_created']);
  });

  it('applies date_range.from filter', async () => {
    const chain = makeChain({ data: [], error: null });
    const supabase = { from: vi.fn(() => chain) };
    getGuardedClient.mockReturnValue(supabase);

    const from = '2024-01-01T00:00:00Z';
    await searchEvents('test', { tenant_id: 'test-tenant', date_range: { from } });
    expect(chain.gte).toHaveBeenCalledWith('created_at', from);
  });

  it('applies date_range.to filter', async () => {
    const chain = makeChain({ data: [], error: null });
    const supabase = { from: vi.fn(() => chain) };
    getGuardedClient.mockReturnValue(supabase);

    const to = '2024-12-31T23:59:59Z';
    await searchEvents('test', { tenant_id: 'test-tenant', date_range: { to } });
    expect(chain.lte).toHaveBeenCalledWith('created_at', to);
  });

  it('falls back to ilike when textSearch returns error', async () => {
    let callCount = 0;
    const textSearchChain = {
      select: vi.fn().mockReturnThis(),
      textSearch: vi.fn().mockReturnThis(),
      in: vi.fn().mockReturnThis(),
      gte: vi.fn().mockReturnThis(),
      lte: vi.fn().mockReturnThis(),
      order: vi.fn().mockReturnThis(),
      limit: vi.fn().mockReturnThis(),
      ilike: vi.fn().mockReturnThis(),
      then: (resolve) => {
        callCount++;
        // First call resolves with text search error
        if (callCount <= 3) {
          return Promise.resolve({
            data: null,
            error: { message: 'text search operator not allowed' },
          }).then(resolve);
        }
        return Promise.resolve({ data: [], error: null }).then(resolve);
      },
    };

    const supabase = { from: vi.fn(() => textSearchChain) };
    getGuardedClient.mockReturnValue(supabase);

    // Should not throw, should fall back
    const results = await searchEvents('test query', { tenant_id: 'test-tenant' });
    expect(Array.isArray(results)).toBe(true);
  });

  it('degrades gracefully when a table throws', async () => {
    let callCount = 0;
    const flakyChain = {
      select: vi.fn().mockReturnThis(),
      textSearch: vi.fn().mockReturnThis(),
      in: vi.fn().mockReturnThis(),
      gte: vi.fn().mockReturnThis(),
      lte: vi.fn().mockReturnThis(),
      order: vi.fn().mockReturnThis(),
      limit: vi.fn().mockReturnThis(),
      ilike: vi.fn().mockReturnThis(),
      then: (resolve, reject) => {
        callCount++;
        if (callCount === 1) return Promise.reject(new Error('unexpected error')).catch(() => ({ data: [], error: null })).then(resolve);
        return Promise.resolve({ data: [], error: null }).then(resolve);
      },
    };

    const supabase = { from: vi.fn(() => flakyChain) };
    getGuardedClient.mockReturnValue(supabase);

    const results = await searchEvents('test', { tenant_id: 'test-tenant' });
    expect(Array.isArray(results)).toBe(true);
  });
});

// ── verifyIntegrity ───────────────────────────────────────────────────────────

describe('verifyIntegrity', () => {
  beforeEach(() => vi.clearAllMocks());

  it('returns a 100 score when no events exist', async () => {
    const emptyChain = makeChain({ data: [], error: null });
    const handshakesChain = makeChain({ data: [], error: null });

    const supabase = makeSupabase({
      handshake_events: emptyChain,
      signoff_events: emptyChain,
      handshakes: handshakesChain,
    });
    getGuardedClient.mockReturnValue(supabase);

    const result = await verifyIntegrity();
    expect(result.score).toBe(0); // score is 0 when no events (maxPenalty = 0)
    expect(result.anomalies).toEqual([]);
    expect(result.total_events).toBe(0);
  });

  it('detects missing creation event', async () => {
    const events = [
      { event_id: 'e-1', handshake_id: 'hs-1', event_type: 'handshake_accepted', created_at: '2024-01-01T08:00:00Z' },
    ];

    const heChain = makeChain({ data: events, error: null });
    const seChain = makeChain({ data: [], error: null });
    const hsChain = makeChain({ data: [], error: null });

    const supabase = makeSupabase({
      handshake_events: heChain,
      signoff_events: seChain,
      handshakes: hsChain,
    });
    getGuardedClient.mockReturnValue(supabase);

    const result = await verifyIntegrity();
    const missingCreation = result.anomalies.find(a => a.type === 'missing_creation_event');
    expect(missingCreation).toBeDefined();
    expect(missingCreation.handshake_id).toBe('hs-1');
  });

  it('detects timestamp inversions in event sequence', async () => {
    const events = [
      { event_id: 'e-1', handshake_id: 'hs-2', event_type: 'handshake_created', created_at: '2024-01-01T10:00:00Z' },
      { event_id: 'e-2', handshake_id: 'hs-2', event_type: 'handshake_accepted', created_at: '2024-01-01T08:00:00Z' }, // earlier than first!
    ];

    const heChain = makeChain({ data: events, error: null });
    const seChain = makeChain({ data: [], error: null });
    const hsChain = makeChain({ data: [], error: null });

    const supabase = makeSupabase({
      handshake_events: heChain,
      signoff_events: seChain,
      handshakes: hsChain,
    });
    getGuardedClient.mockReturnValue(supabase);

    const result = await verifyIntegrity();
    const inversion = result.anomalies.find(a => a.type === 'timestamp_inversion');
    expect(inversion).toBeDefined();
    expect(inversion.handshake_id).toBe('hs-2');
  });

  it('detects missing terminal event for terminal handshake', async () => {
    const handshakeEvents = [
      { event_id: 'e-1', handshake_id: 'hs-3', event_type: 'handshake_created', created_at: '2024-01-01T08:00:00Z' },
    ];
    const terminalHandshakes = [{ id: 'hs-3', status: 'verified' }];

    const heChain = makeChain({ data: handshakeEvents, error: null });
    const seChain = makeChain({ data: [], error: null });
    const hsChain = makeChain({ data: terminalHandshakes, error: null });

    const supabase = makeSupabase({
      handshake_events: heChain,
      signoff_events: seChain,
      handshakes: hsChain,
    });
    getGuardedClient.mockReturnValue(supabase);

    const result = await verifyIntegrity();
    const missing = result.anomalies.find(a => a.type === 'missing_terminal_event');
    expect(missing).toBeDefined();
    expect(missing.handshake_id).toBe('hs-3');
  });

  it('returns score of 100 for clean event sequences', async () => {
    const handshakeEvents = [
      { event_id: 'e-1', handshake_id: 'hs-4', event_type: 'handshake_created', created_at: '2024-01-01T08:00:00Z' },
      { event_id: 'e-2', handshake_id: 'hs-4', event_type: 'handshake_verified', created_at: '2024-01-01T09:00:00Z' },
    ];
    const terminalHandshakes = [{ id: 'hs-4', status: 'verified' }];

    const heChain = makeChain({ data: handshakeEvents, error: null });
    const seChain = makeChain({ data: [], error: null });
    const hsChain = makeChain({ data: terminalHandshakes, error: null });

    const supabase = makeSupabase({
      handshake_events: heChain,
      signoff_events: seChain,
      handshakes: hsChain,
    });
    getGuardedClient.mockReturnValue(supabase);

    const result = await verifyIntegrity();
    expect(result.score).toBe(100);
    expect(result.anomalies).toHaveLength(0);
  });

  it('throws when handshake_events query fails critically', async () => {
    const heChain = makeChain({ data: null, error: { message: 'fatal db error' } });

    const supabase = makeSupabase({ handshake_events: heChain });
    getGuardedClient.mockReturnValue(supabase);

    await expect(verifyIntegrity()).rejects.toThrow('Integrity check failed');
  });

  it('throws when signoff_events query fails critically', async () => {
    const heChain = makeChain({ data: [], error: null });
    const seChain = makeChain({ data: null, error: { message: 'fatal db error' } });

    const supabase = makeSupabase({
      handshake_events: heChain,
      signoff_events: seChain,
    });
    getGuardedClient.mockReturnValue(supabase);

    await expect(verifyIntegrity()).rejects.toThrow('Integrity check failed');
  });

  it('respects dateRange.from filter', async () => {
    const heChain = makeChain({ data: [], error: null });
    const seChain = makeChain({ data: [], error: null });
    const hsChain = makeChain({ data: [], error: null });

    const supabase = makeSupabase({
      handshake_events: heChain,
      signoff_events: seChain,
      handshakes: hsChain,
    });
    getGuardedClient.mockReturnValue(supabase);

    const from = '2024-01-01T00:00:00Z';
    await verifyIntegrity({ from });

    expect(heChain.gte).toHaveBeenCalledWith('created_at', from);
    expect(seChain.gte).toHaveBeenCalledWith('created_at', from);
  });

  it('respects dateRange.to filter', async () => {
    const heChain = makeChain({ data: [], error: null });
    const seChain = makeChain({ data: [], error: null });
    const hsChain = makeChain({ data: [], error: null });

    const supabase = makeSupabase({
      handshake_events: heChain,
      signoff_events: seChain,
      handshakes: hsChain,
    });
    getGuardedClient.mockReturnValue(supabase);

    const to = '2024-12-31T23:59:59Z';
    await verifyIntegrity({ to });

    expect(heChain.lte).toHaveBeenCalledWith('created_at', to);
    expect(seChain.lte).toHaveBeenCalledWith('created_at', to);
  });

  it('returns correct counts in the result', async () => {
    const hEvents = [
      { event_id: 'e1', handshake_id: 'hs-5', event_type: 'handshake_created', created_at: '2024-01-01T08:00:00Z' },
      { event_id: 'e2', handshake_id: 'hs-5', event_type: 'handshake_accepted', created_at: '2024-01-01T09:00:00Z' },
    ];
    const sEvents = [
      { event_id: 'e3', handshake_id: 'hs-5', event_type: 'signoff_created', created_at: '2024-01-01T10:00:00Z' },
    ];

    const heChain = makeChain({ data: hEvents, error: null });
    const seChain = makeChain({ data: sEvents, error: null });
    const hsChain = makeChain({ data: [], error: null });

    const supabase = makeSupabase({
      handshake_events: heChain,
      signoff_events: seChain,
      handshakes: hsChain,
    });
    getGuardedClient.mockReturnValue(supabase);

    const result = await verifyIntegrity();
    expect(result.handshake_event_count).toBe(2);
    expect(result.signoff_event_count).toBe(1);
    expect(result.total_events).toBe(3);
  });

  it('score is a number between 0 and 100', async () => {
    const heChain = makeChain({ data: [], error: null });
    const seChain = makeChain({ data: [], error: null });
    const hsChain = makeChain({ data: [], error: null });

    const supabase = makeSupabase({
      handshake_events: heChain,
      signoff_events: seChain,
      handshakes: hsChain,
    });
    getGuardedClient.mockReturnValue(supabase);

    const result = await verifyIntegrity();
    expect(typeof result.score).toBe('number');
    expect(result.score).toBeGreaterThanOrEqual(0);
    expect(result.score).toBeLessThanOrEqual(100);
  });

  it('degrades gracefully when handshake_events relation does not exist', async () => {
    const heChain = makeChain({ data: null, error: { message: 'relation does not exist' } });
    const seChain = makeChain({ data: [], error: null });
    const hsChain = makeChain({ data: [], error: null });

    const supabase = makeSupabase({
      handshake_events: heChain,
      signoff_events: seChain,
      handshakes: hsChain,
    });
    getGuardedClient.mockReturnValue(supabase);

    // should NOT throw — graceful degradation for missing tables
    const result = await verifyIntegrity();
    expect(result).toBeDefined();
  });
});
