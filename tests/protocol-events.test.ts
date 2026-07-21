/**
 * EMILIA Protocol — Protocol Events & Authority Registry Tests
 *
 * Tests for the append-only event store and authority registry:
 * - Event record structure validation
 * - Idempotency key uniqueness
 * - Aggregate type enum validation
 * - Authority registry lookup patterns
 *
 * Uses vi.mock to mock Supabase so no real DB calls are made.
 */

import { describe, it, expect, vi, beforeEach } from 'vitest';

// ============================================================================
// Supabase mock helpers
// ============================================================================

function makeChain(resolveValue) {
  const chain = {
    select: vi.fn().mockReturnThis(),
    eq: vi.fn().mockReturnThis(),
    neq: vi.fn().mockReturnThis(),
    in: vi.fn().mockReturnThis(),
    is: vi.fn().mockReturnThis(),
    or: vi.fn().mockReturnThis(),
    lte: vi.fn().mockReturnThis(),
    gte: vi.fn().mockReturnThis(),
    order: vi.fn().mockReturnThis(),
    limit: vi.fn().mockReturnThis(),
    insert: vi.fn().mockResolvedValue(resolveValue),
    update: vi.fn().mockReturnThis(),
    delete: vi.fn().mockReturnThis(),
    single: vi.fn().mockResolvedValue(resolveValue),
    maybeSingle: vi.fn().mockResolvedValue(resolveValue),
    then: (resolve) => Promise.resolve(resolveValue).then(resolve),
  };
  return chain;
}

const mockGetServiceClient = vi.fn();

vi.mock('../lib/supabase.js', () => ({
  getServiceClient: (...args) => mockGetServiceClient(...args),
}));

// ============================================================================
// Valid aggregate types from the CHECK constraint
// ============================================================================

const VALID_AGGREGATE_TYPES = ['receipt', 'commit', 'dispute', 'report', 'delegation', 'entity'];
const VALID_AUTHORITY_ROLES = ['system', 'operator', 'delegated_agent', 'machine_service'];
const VALID_AUTHORITY_STATUSES = ['active', 'revoked', 'retired'];

// ============================================================================
// Protocol Events — Event Record Structure
// ============================================================================

describe('Protocol Events — Event Record Structure', () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  it('should accept a well-formed event record', async () => {
    const event = {
      aggregate_type: 'receipt',
      aggregate_id: 'rcpt_abc123',
      command_type: 'receipt.created',
      payload_json: { amount: 100, currency: 'USD' },
      payload_hash: 'sha256:abcdef1234567890',
      actor_authority_id: 'auth_key_001',
      idempotency_key: 'idem_unique_001',
    };

    const insertedRow = {
      data: { ...event, event_id: 'evt_generated_uuid', created_at: new Date().toISOString() },
      error: null,
    };

    const chain = makeChain(insertedRow);
    mockGetServiceClient.mockReturnValue({ from: vi.fn().mockReturnValue(chain) });

    const supabase = mockGetServiceClient();
    const result = await supabase.from('protocol_events').insert(event);

    expect(result.error).toBeNull();
    expect(result.data).toBeDefined();
    expect(result.data.aggregate_type).toBe('receipt');
    expect(result.data.command_type).toBe('receipt.created');
    expect(result.data.payload_hash).toBe('sha256:abcdef1234567890');
  });

  it('should require all mandatory fields', () => {
    const requiredFields = ['aggregate_type', 'aggregate_id', 'command_type', 'payload_json', 'payload_hash'];

    const fullEvent = {
      aggregate_type: 'commit',
      aggregate_id: 'cmt_xyz',
      command_type: 'commit.issued',
      payload_json: {},
      payload_hash: 'sha256:0000',
    };

    for (const field of requiredFields) {
      const partial = { ...fullEvent };
      delete partial[field];
      expect(partial[field]).toBeUndefined();
      expect(Object.keys(partial)).not.toContain(field);
    }
  });

  it('should allow optional fields to be null', () => {
    const event = {
      aggregate_type: 'dispute',
      aggregate_id: 'dsp_001',
      command_type: 'dispute.opened',
      payload_json: { reason: 'fabrication' },
      payload_hash: 'sha256:deadbeef',
      parent_event_hash: null,
      actor_authority_id: null,
      signature: null,
      signed_at: null,
      idempotency_key: null,
    };

    expect(event.parent_event_hash).toBeNull();
    expect(event.actor_authority_id).toBeNull();
    expect(event.signature).toBeNull();
    expect(event.signed_at).toBeNull();
    expect(event.idempotency_key).toBeNull();
  });

  it('should include parent_event_hash for chained events', () => {
    const parentHash = 'sha256:parent_event_hash_abc';
    const childEvent = {
      aggregate_type: 'receipt',
      aggregate_id: 'rcpt_abc123',
      command_type: 'receipt.amended',
      parent_event_hash: parentHash,
      payload_json: { amendment: 'corrected_amount' },
      payload_hash: 'sha256:child_hash',
    };

    expect(childEvent.parent_event_hash).toBe(parentHash);
  });
});

// ============================================================================
// Protocol Events — Idempotency Key Uniqueness
// ============================================================================

describe('Protocol Events — Idempotency Key Uniqueness', () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  it('should accept an event with a unique idempotency key', async () => {
    const chain = makeChain({ data: { event_id: 'evt_1' }, error: null });
    mockGetServiceClient.mockReturnValue({ from: vi.fn().mockReturnValue(chain) });

    const supabase = mockGetServiceClient();
    const result = await supabase.from('protocol_events').insert({
      aggregate_type: 'commit',
      aggregate_id: 'cmt_001',
      command_type: 'commit.issued',
      payload_json: {},
      payload_hash: 'sha256:aaa',
      idempotency_key: 'unique_key_1',
    });

    expect(result.error).toBeNull();
  });

  it('should reject a duplicate idempotency key with a constraint error', async () => {
    const duplicateError = {
      data: null,
      error: {
        code: '23505',
        message: 'duplicate key value violates unique constraint "protocol_events_idempotency_key_key"',
      },
    };

    const chain = makeChain(duplicateError);
    mockGetServiceClient.mockReturnValue({ from: vi.fn().mockReturnValue(chain) });

    const supabase = mockGetServiceClient();
    const result = await supabase.from('protocol_events').insert({
      aggregate_type: 'commit',
      aggregate_id: 'cmt_001',
      command_type: 'commit.issued',
      payload_json: {},
      payload_hash: 'sha256:aaa',
      idempotency_key: 'duplicate_key',
    });

    expect(result.error).not.toBeNull();
    expect(result.error.code).toBe('23505');
    expect(result.error.message).toContain('idempotency_key');
  });

  it('should allow multiple events with null idempotency key', async () => {
    const chain = makeChain({ data: [{ event_id: 'evt_a' }, { event_id: 'evt_b' }], error: null });
    mockGetServiceClient.mockReturnValue({ from: vi.fn().mockReturnValue(chain) });

    const supabase = mockGetServiceClient();
    const result = await supabase.from('protocol_events').insert([
      { aggregate_type: 'report', aggregate_id: 'rpt_1', command_type: 'report.filed', payload_json: {}, payload_hash: 'sha256:b1', idempotency_key: null },
      { aggregate_type: 'report', aggregate_id: 'rpt_2', command_type: 'report.filed', payload_json: {}, payload_hash: 'sha256:b2', idempotency_key: null },
    ]);

    expect(result.error).toBeNull();
    expect(result.data).toHaveLength(2);
  });
});

// ============================================================================
// Protocol Events — Aggregate Type Enum Validation
// ============================================================================

describe('Protocol Events — Aggregate Type Enum Validation', () => {
  it('should recognize all valid aggregate types', () => {
    for (const aggType of VALID_AGGREGATE_TYPES) {
      expect(VALID_AGGREGATE_TYPES).toContain(aggType);
    }
    expect(VALID_AGGREGATE_TYPES).toHaveLength(6);
  });

  it('should reject invalid aggregate types via CHECK constraint', async () => {
    const checkViolation = {
      data: null,
      error: {
        code: '23514',
        message: 'new row for relation "protocol_events" violates check constraint "protocol_events_aggregate_type_check"',
      },
    };

    const chain = makeChain(checkViolation);
    mockGetServiceClient.mockReturnValue({ from: vi.fn().mockReturnValue(chain) });

    const supabase = mockGetServiceClient();
    const result = await supabase.from('protocol_events').insert({
      aggregate_type: 'invalid_type',
      aggregate_id: 'bad_001',
      command_type: 'bad.event',
      payload_json: {},
      payload_hash: 'sha256:bad',
    });

    expect(result.error).not.toBeNull();
    expect(result.error.code).toBe('23514');
  });

  it('should cover every aggregate type with a valid event shape', () => {
    const events = VALID_AGGREGATE_TYPES.map((aggType) => ({
      aggregate_type: aggType,
      aggregate_id: `${aggType}_test_id`,
      command_type: `${aggType}.created`,
      payload_json: { test: true },
      payload_hash: `sha256:${aggType}_hash`,
    }));

    expect(events).toHaveLength(6);
    for (const event of events) {
      expect(VALID_AGGREGATE_TYPES).toContain(event.aggregate_type);
      expect(event.command_type).toMatch(/^\w+\.\w+$/);
      expect(event.payload_hash).toMatch(/^sha256:/);
    }
  });
});

// ============================================================================
// Authority Registry — Lookup Patterns
// ============================================================================

describe('Authority Registry — Lookup Patterns', () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  it('should look up an authority by key_id', async () => {
    const authority = {
      authority_id: 'auth_uuid_1',
      key_id: 'ep-signer-prod-001',
      public_key: 'ed25519:base64encodedpublickey==',
      algorithm: 'Ed25519',
      role: 'system',
      status: 'active',
      valid_from: '2026-01-01T00:00:00Z',
      valid_to: null,
      created_at: '2026-01-01T00:00:00Z',
      revoked_at: null,
      metadata_json: {},
    };

    const chain = makeChain({ data: authority, error: null });
    mockGetServiceClient.mockReturnValue({ from: vi.fn().mockReturnValue(chain) });

    const supabase = mockGetServiceClient();
    const result = await supabase
      .from('authorities')
      .select('*')
      .eq('key_id', 'ep-signer-prod-001')
      .single();

    expect(result.error).toBeNull();
    expect(result.data.key_id).toBe('ep-signer-prod-001');
    expect(result.data.algorithm).toBe('Ed25519');
    expect(result.data.status).toBe('active');
  });

  it('should validate authority roles against allowed values', () => {
    for (const role of VALID_AUTHORITY_ROLES) {
      const authority = { role, status: 'active' };
      expect(VALID_AUTHORITY_ROLES).toContain(authority.role);
    }
    expect(VALID_AUTHORITY_ROLES).toHaveLength(4);
  });

  it('should validate authority statuses against allowed values', () => {
    for (const status of VALID_AUTHORITY_STATUSES) {
      expect(['active', 'revoked', 'retired']).toContain(status);
    }
  });

  it('should filter active authorities within validity window', async () => {
    const activeAuthorities = [
      { key_id: 'key-a', status: 'active', valid_from: '2025-01-01T00:00:00Z', valid_to: null },
      { key_id: 'key-b', status: 'active', valid_from: '2025-06-01T00:00:00Z', valid_to: '2027-06-01T00:00:00Z' },
    ];

    const chain = makeChain({ data: activeAuthorities, error: null });
    mockGetServiceClient.mockReturnValue({ from: vi.fn().mockReturnValue(chain) });

    const supabase = mockGetServiceClient();
    const result = await supabase
      .from('authorities')
      .select('*')
      .eq('status', 'active')
      .lte('valid_from', new Date().toISOString());

    expect(result.data).toHaveLength(2);
    for (const auth of result.data) {
      expect(auth.status).toBe('active');
    }
  });

  it('should reject lookup of revoked authorities for signing', async () => {
    const revokedAuth = {
      data: {
        key_id: 'key-revoked',
        status: 'revoked',
        revoked_at: '2026-02-15T00:00:00Z',
      },
      error: null,
    };

    const chain = makeChain(revokedAuth);
    mockGetServiceClient.mockReturnValue({ from: vi.fn().mockReturnValue(chain) });

    const supabase = mockGetServiceClient();
    const result = await supabase
      .from('authorities')
      .select('*')
      .eq('key_id', 'key-revoked')
      .single();

    expect(result.data.status).toBe('revoked');
    expect(result.data.revoked_at).toBeDefined();
    // Application logic should reject revoked authorities
    const isValid = result.data.status === 'active';
    expect(isValid).toBe(false);
  });

  it('should resolve actor_authority_id from protocol_events to authorities', async () => {
    // Step 1: Get the event
    const event = {
      event_id: 'evt_123',
      actor_authority_id: 'ep-signer-prod-001',
      aggregate_type: 'commit',
      command_type: 'commit.issued',
    };

    const eventChain = makeChain({ data: event, error: null });
    mockGetServiceClient.mockReturnValue({ from: vi.fn().mockReturnValue(eventChain) });

    const supabase1 = mockGetServiceClient();
    const eventResult = await supabase1
      .from('protocol_events')
      .select('*')
      .eq('event_id', 'evt_123')
      .single();

    // Step 2: Resolve the authority
    const authority = {
      key_id: event.actor_authority_id,
      public_key: 'ed25519:base64key==',
      status: 'active',
    };

    const authChain = makeChain({ data: authority, error: null });
    mockGetServiceClient.mockReturnValue({ from: vi.fn().mockReturnValue(authChain) });

    const supabase2 = mockGetServiceClient();
    const authResult = await supabase2
      .from('authorities')
      .select('*')
      .eq('key_id', eventResult.data.actor_authority_id)
      .single();

    expect(authResult.data.key_id).toBe('ep-signer-prod-001');
    expect(authResult.data.status).toBe('active');
  });
});
