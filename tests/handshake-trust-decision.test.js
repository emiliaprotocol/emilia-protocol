/**
 * EMILIA Protocol — Handshake TrustDecision Bridge & Event Sourcing Tests
 *
 * Tests for:
 *   1. mapHandshakeToTrustDecision — outcome-to-decision mapping
 *   2. shouldTriggerDecision — gate for decision creation
 *   3. recordHandshakeEvent — append-only event recording
 *   4. getHandshakeEvents — ordered event retrieval
 *
 * Uses vi.mock for trust-decision.js so we can inspect the shape without
 * needing the full decision pipeline. Supabase is simulated in-memory.
 *
 * @license Apache-2.0
 */

import { describe, it, expect, vi, beforeEach } from 'vitest';

// ============================================================================
// Mock: trust-decision.js
// ============================================================================

vi.mock('../lib/trust-decision.js', () => ({
  buildTrustDecision: vi.fn((params) => ({
    decision: params.decision,
    entity_id: params.entityId,
    policy_used: params.policyUsed,
    confidence: params.confidence,
    reasons: params.reasons || [],
    warnings: params.warnings || [],
    appeal_path: params.appealPath || '/api/disputes/report',
    context_used: params.contextUsed || null,
    profile_summary: params.profileSummary || null,
    ...(params.extensions || {}),
  })),
}));

// ============================================================================
// Import modules under test (after mocks)
// ============================================================================

import {
  mapHandshakeToTrustDecision,
  shouldTriggerDecision,
} from '../lib/handshake/trust-decision-bridge.js';

import {
  recordHandshakeEvent,
  getHandshakeEvents,
  HANDSHAKE_EVENT_TYPES,
  HandshakeEventError,
  generateIdempotencyKey,
} from '../lib/handshake/events.js';

// ============================================================================
// Helpers
// ============================================================================

function makeHandshakeResult(overrides = {}) {
  return {
    handshake_id: 'hs_test_001',
    outcome: 'accepted',
    reason_codes: [],
    assurance_achieved: 'high',
    policy_version: 'policy_v1',
    commit_ref: 'epc_abc123',
    ...overrides,
  };
}

/**
 * Minimal Supabase mock with in-memory table storage.
 */
function createSupabaseMock() {
  const tables = {};

  function getTable(name) {
    if (!tables[name]) tables[name] = [];
    return tables[name];
  }

  function buildChain(tableName) {
    let filters = [];
    let orderCol = null;
    let orderAsc = true;

    const chain = {
      select: vi.fn().mockImplementation(() => chain),
      insert: vi.fn().mockImplementation((record) => {
        const rows = Array.isArray(record) ? record : [record];
        for (const row of rows) {
          getTable(tableName).push({ ...row, id: `id_${Math.random().toString(36).slice(2, 8)}` });
        }
        return chain;
      }),
      eq: vi.fn().mockImplementation((col, val) => {
        filters.push({ col, val });
        return chain;
      }),
      order: vi.fn().mockImplementation((col, opts) => {
        orderCol = col;
        orderAsc = opts?.ascending !== false;
        return chain;
      }),
      single: vi.fn().mockImplementation(() => {
        const rows = applyFilters(getTable(tableName), filters);
        filters = [];
        return { data: rows[0] || null, error: null };
      }),
      maybeSingle: vi.fn().mockImplementation(() => {
        const rows = applyFilters(getTable(tableName), filters);
        filters = [];
        return { data: rows[0] || null, error: null };
      }),
      then: undefined, // Force await to resolve the chain itself
    };

    // When chain is awaited directly (after select without single/maybeSingle),
    // resolve with data array
    Object.defineProperty(chain, 'then', {
      get() {
        // Capture current state
        const currentFilters = [...filters];
        const col = orderCol;
        const asc = orderAsc;
        filters = [];
        orderCol = null;
        orderAsc = true;

        return (resolve) => {
          let rows = applyFilters(getTable(tableName), currentFilters);
          if (col) {
            rows = rows.sort((a, b) => {
              if (a[col] < b[col]) return asc ? -1 : 1;
              if (a[col] > b[col]) return asc ? 1 : -1;
              return 0;
            });
          }
          resolve({ data: rows, error: null });
        };
      },
      configurable: true,
    });

    return chain;
  }

  function applyFilters(rows, filters) {
    let result = rows;
    for (const f of filters) {
      result = result.filter((r) => r[f.col] === f.val);
    }
    return result;
  }

  return {
    from: vi.fn((tableName) => buildChain(tableName)),
    _tables: tables,
  };
}

// ============================================================================
// Part 1: mapHandshakeToTrustDecision
// ============================================================================

describe('mapHandshakeToTrustDecision', () => {
  it('maps "accepted" outcome to decision "allow"', () => {
    const result = mapHandshakeToTrustDecision(makeHandshakeResult({ outcome: 'accepted' }));
    expect(result.decision).toBe('allow');
  });

  it('maps "rejected" outcome to decision "deny"', () => {
    const result = mapHandshakeToTrustDecision(makeHandshakeResult({ outcome: 'rejected', reason_codes: ['missing_binding'] }));
    expect(result.decision).toBe('deny');
  });

  it('maps "partial" outcome to decision "review"', () => {
    const result = mapHandshakeToTrustDecision(makeHandshakeResult({ outcome: 'partial', reason_codes: ['assurance_not_met_initiator'] }));
    expect(result.decision).toBe('review');
  });

  it('maps "expired" outcome to decision "review"', () => {
    const result = mapHandshakeToTrustDecision(makeHandshakeResult({ outcome: 'expired', reason_codes: ['binding_expired'] }));
    expect(result.decision).toBe('review');
  });
});

// ============================================================================
// Part 2: Confidence scores match assurance levels
// ============================================================================

describe('confidence scores from assurance levels', () => {
  it('high assurance yields confidence score 0.95', () => {
    const result = mapHandshakeToTrustDecision(makeHandshakeResult({ assurance_achieved: 'high' }));
    expect(result.evidence.confidence_score).toBe(0.95);
  });

  it('substantial assurance yields confidence score 0.85', () => {
    const result = mapHandshakeToTrustDecision(makeHandshakeResult({ assurance_achieved: 'substantial' }));
    expect(result.evidence.confidence_score).toBe(0.85);
  });

  it('medium assurance yields confidence score 0.70', () => {
    const result = mapHandshakeToTrustDecision(makeHandshakeResult({ assurance_achieved: 'medium' }));
    expect(result.evidence.confidence_score).toBe(0.70);
  });

  it('low assurance yields confidence score 0.50', () => {
    const result = mapHandshakeToTrustDecision(makeHandshakeResult({ assurance_achieved: 'low' }));
    expect(result.evidence.confidence_score).toBe(0.50);
  });
});

// ============================================================================
// Part 3: shouldTriggerDecision
// ============================================================================

describe('shouldTriggerDecision', () => {
  it('returns true for "accepted" outcome', () => {
    expect(shouldTriggerDecision(makeHandshakeResult({ outcome: 'accepted' }))).toBe(true);
  });

  it('returns true for "rejected" outcome', () => {
    expect(shouldTriggerDecision(makeHandshakeResult({ outcome: 'rejected' }))).toBe(true);
  });

  it('returns false for "partial" and "expired" outcomes', () => {
    expect(shouldTriggerDecision(makeHandshakeResult({ outcome: 'partial' }))).toBe(false);
    expect(shouldTriggerDecision(makeHandshakeResult({ outcome: 'expired' }))).toBe(false);
  });
});

// ============================================================================
// Part 4: TrustDecision evidence fields
// ============================================================================

describe('TrustDecision evidence fields', () => {
  it('includes handshake_id, policy_ref, and binding_hash in evidence', () => {
    const result = mapHandshakeToTrustDecision(makeHandshakeResult());
    expect(result.evidence).toBeDefined();
    expect(result.evidence.handshake_id).toBe('hs_test_001');
    expect(result.evidence.policy_ref).toBe('policy_v1');
    expect(result.evidence.binding_hash).toBe('epc_abc123');
  });

  it('includes structured reasons from reason_codes', () => {
    const result = mapHandshakeToTrustDecision(makeHandshakeResult({
      outcome: 'rejected',
      reason_codes: ['missing_binding', 'payload_hash_mismatch'],
    }));
    expect(result.reasons).toEqual([
      'handshake: missing_binding',
      'handshake: payload_hash_mismatch',
    ]);
  });
});

// ============================================================================
// Part 5: recordHandshakeEvent — validation
// ============================================================================

describe('recordHandshakeEvent', () => {
  let supabase;

  beforeEach(() => {
    supabase = createSupabaseMock();
  });

  it('rejects invalid event_type', async () => {
    await expect(
      recordHandshakeEvent(supabase, {
        handshake_id: 'hs_001',
        event_type: 'handshake_exploded',
      }),
    ).rejects.toThrow('Invalid event_type');
  });

  it('rejects missing event_type', async () => {
    await expect(
      recordHandshakeEvent(supabase, {
        handshake_id: 'hs_001',
      }),
    ).rejects.toThrow('event_type is required');
  });

  it('stores a valid event and returns it', async () => {
    const event = await recordHandshakeEvent(supabase, {
      handshake_id: 'hs_001',
      event_type: 'initiated',
      event_payload: { mode: 'basic' },
      actor_id: 'user_123',
    });

    expect(event).toBeDefined();
    expect(event.handshake_id).toBe('hs_001');
    expect(event.event_type).toBe('initiated');
    expect(event.actor_id).toBe('user_123');
  });
});

// ============================================================================
// Part 6: getHandshakeEvents — ordered results
// ============================================================================

describe('getHandshakeEvents', () => {
  it('returns events ordered by created_at ascending', async () => {
    const supabase = createSupabaseMock();

    // Insert events with explicit timestamps out of order
    await recordHandshakeEvent(supabase, {
      handshake_id: 'hs_order',
      event_type: 'verified',
      actor_id: 'actor_b',
      idempotency_key: 'key_b',
      event_payload: {},
    });
    // Manually adjust created_at for ordering test
    const table = supabase._tables['handshake_events'];
    table[0].created_at = '2025-01-01T00:00:02.000Z';

    await recordHandshakeEvent(supabase, {
      handshake_id: 'hs_order',
      event_type: 'initiated',
      actor_id: 'actor_a',
      idempotency_key: 'key_a',
      event_payload: {},
    });
    table[1].created_at = '2025-01-01T00:00:01.000Z';

    const events = await getHandshakeEvents(supabase, 'hs_order');
    expect(events.length).toBe(2);
    expect(events[0].event_type).toBe('initiated');
    expect(events[1].event_type).toBe('verified');
  });
});

// ============================================================================
// Part 7: Idempotent event recording
// ============================================================================

describe('idempotent event recording', () => {
  it('returns existing record when same idempotency key is used', async () => {
    const supabase = createSupabaseMock();
    const key = 'idem_fixed_key';

    const first = await recordHandshakeEvent(supabase, {
      handshake_id: 'hs_idem',
      event_type: 'initiated',
      actor_id: 'actor_1',
      idempotency_key: key,
    });

    const second = await recordHandshakeEvent(supabase, {
      handshake_id: 'hs_idem',
      event_type: 'initiated',
      actor_id: 'actor_1',
      idempotency_key: key,
    });

    // Should return the same record, not create a duplicate
    expect(second.id).toBe(first.id);
    expect(supabase._tables['handshake_events'].length).toBe(1);
  });
});

// ============================================================================
// Part 8: HANDSHAKE_EVENT_TYPES constant
// ============================================================================

describe('HANDSHAKE_EVENT_TYPES', () => {
  it('contains all expected event types', () => {
    const expected = [
      'initiated',
      'presentation_added',
      'status_changed',
      'verified',
      'rejected',
      'expired',
      'revoked',
    ];
    expect(HANDSHAKE_EVENT_TYPES).toEqual(expected);
  });
});
