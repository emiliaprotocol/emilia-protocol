/**
 * write-guard-extended.test.js
 *
 * Extended coverage for lib/write-guard.js targeting uncovered lines:
 *   line 57-58: createWriteGuard returns client when client is null/missing .from
 *   lines 78-79: Proxy trap blocks insert/update/upsert/delete on trust tables
 *   line 94:     non-from property access falls through to Reflect.get
 *   Full TRUST_TABLES whitelist enforcement
 *   Direct mutation attempt verification
 *   Non-trust tables allow mutations
 */

import { describe, it, expect, vi, beforeEach } from 'vitest';

// Mock the supabase module
vi.mock('../lib/supabase.js', () => ({
  getServiceClient: vi.fn(),
}));

import { getGuardedClient, _internals } from '../lib/write-guard.js';
import { getServiceClient } from '../lib/supabase.js';

// =============================================================================
// Helpers
// =============================================================================

function makeRealClient(overrides = {}) {
  const queryBuilder = {
    select: vi.fn().mockReturnThis(),
    eq: vi.fn().mockReturnThis(),
    insert: vi.fn().mockResolvedValue({ data: null, error: null }),
    update: vi.fn().mockResolvedValue({ data: null, error: null }),
    upsert: vi.fn().mockResolvedValue({ data: null, error: null }),
    delete: vi.fn().mockResolvedValue({ data: null, error: null }),
    single: vi.fn().mockResolvedValue({ data: null, error: null }),
    ...overrides,
  };

  return {
    from: vi.fn().mockReturnValue(queryBuilder),
    auth: { getUser: vi.fn() },
    someOtherProp: 'test-value',
    _queryBuilder: queryBuilder,
  };
}

// =============================================================================
// _internals.TRUST_TABLES
// =============================================================================

describe('TRUST_TABLES list', () => {
  it('is frozen (immutable)', () => {
    expect(Object.isFrozen(_internals.TRUST_TABLES)).toBe(true);
  });

  it('contains receipts', () => {
    expect(_internals.TRUST_TABLES).toContain('receipts');
  });

  it('contains commits', () => {
    expect(_internals.TRUST_TABLES).toContain('commits');
  });

  it('contains disputes', () => {
    expect(_internals.TRUST_TABLES).toContain('disputes');
  });

  it('contains trust_reports', () => {
    expect(_internals.TRUST_TABLES).toContain('trust_reports');
  });

  it('contains protocol_events', () => {
    expect(_internals.TRUST_TABLES).toContain('protocol_events');
  });

  it('contains handshakes', () => {
    expect(_internals.TRUST_TABLES).toContain('handshakes');
  });

  it('contains signoff_challenges', () => {
    expect(_internals.TRUST_TABLES).toContain('signoff_challenges');
  });

  it('contains eye_observations', () => {
    expect(_internals.TRUST_TABLES).toContain('eye_observations');
  });

  it('has at least 18 entries', () => {
    expect(_internals.TRUST_TABLES.length).toBeGreaterThanOrEqual(18);
  });
});

// =============================================================================
// getGuardedClient — null/missing client passthrough (line 57-58)
// =============================================================================

describe('getGuardedClient — passthrough for null/invalid client', () => {
  it('returns null client as-is when getServiceClient returns null', () => {
    getServiceClient.mockReturnValue(null);
    const guarded = getGuardedClient();
    expect(guarded).toBeNull();
  });

  it('returns client without .from as-is (no proxy wrapping)', () => {
    const noFrom = { auth: { getUser: vi.fn() } };
    getServiceClient.mockReturnValue(noFrom);
    const guarded = getGuardedClient();
    expect(guarded).toBe(noFrom);
  });
});

// =============================================================================
// getGuardedClient — proxy behavior
// =============================================================================

describe('getGuardedClient — proxy wrapping', () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  it('returns a proxy object (not the original client reference)', () => {
    const realClient = makeRealClient();
    getServiceClient.mockReturnValue(realClient);
    const guarded = getGuardedClient();
    // The proxy is a different object from the original
    expect(guarded).not.toBe(realClient);
  });

  it('allows reads (select) on trust tables', () => {
    const realClient = makeRealClient();
    getServiceClient.mockReturnValue(realClient);
    const guarded = getGuardedClient();
    // select should be accessible without throwing
    const qb = guarded.from('receipts');
    expect(() => qb.select('*')).not.toThrow();
  });

  it('allows reads on non-trust tables', () => {
    const realClient = makeRealClient();
    getServiceClient.mockReturnValue(realClient);
    const guarded = getGuardedClient();
    const qb = guarded.from('entities');
    expect(() => qb.select('*')).not.toThrow();
    expect(() => qb.insert({ id: '1' })).not.toThrow();
  });
});

// =============================================================================
// Direct mutation attempts on trust tables — lines 78-79
// =============================================================================

describe('write guard — blocks mutations on trust tables', () => {
  const BLOCKED_OPS = ['insert', 'update', 'upsert', 'delete'];

  beforeEach(() => {
    const realClient = makeRealClient();
    getServiceClient.mockReturnValue(realClient);
  });

  for (const op of BLOCKED_OPS) {
    it(`throws on .${op}() against "receipts"`, () => {
      const guarded = getGuardedClient();
      const qb = guarded.from('receipts');
      expect(() => qb[op]({ some: 'data' })).toThrow('WRITE_DISCIPLINE_VIOLATION');
    });

    it(`throws on .${op}() against "commits"`, () => {
      const guarded = getGuardedClient();
      const qb = guarded.from('commits');
      expect(() => qb[op]({ some: 'data' })).toThrow('WRITE_DISCIPLINE_VIOLATION');
    });

    it(`throws on .${op}() against "disputes"`, () => {
      const guarded = getGuardedClient();
      const qb = guarded.from('disputes');
      expect(() => qb[op]({})).toThrow('protocolWrite');
    });
  }

  it('error message mentions the table name', () => {
    const guarded = getGuardedClient();
    const qb = guarded.from('trust_reports');
    try {
      qb.insert({ data: 'x' });
      expect.fail('should have thrown');
    } catch (e) {
      expect(e.message).toContain('trust_reports');
    }
  });

  it('error message mentions the operation type', () => {
    const guarded = getGuardedClient();
    const qb = guarded.from('protocol_events');
    try {
      qb.update({ data: 'x' });
      expect.fail('should have thrown');
    } catch (e) {
      expect(e.message).toContain('update');
    }
  });
});

// =============================================================================
// Non-trust tables — mutations are allowed
// =============================================================================

describe('write guard — non-trust tables are unguarded', () => {
  const NON_TRUST_TABLES = ['entities', 'needs', 'sessions', 'api_keys', 'profiles'];

  beforeEach(() => {
    const realClient = makeRealClient();
    getServiceClient.mockReturnValue(realClient);
  });

  for (const table of NON_TRUST_TABLES) {
    it(`allows insert on "${table}"`, () => {
      const guarded = getGuardedClient();
      const qb = guarded.from(table);
      expect(() => qb.insert({ id: '1' })).not.toThrow();
    });
  }
});

// =============================================================================
// Proxy passthrough — non-from properties (line 94)
// =============================================================================

describe('write guard — non-from properties pass through', () => {
  it('proxies auth property from original client', () => {
    const realClient = makeRealClient();
    getServiceClient.mockReturnValue(realClient);
    const guarded = getGuardedClient();
    expect(guarded.auth).toBe(realClient.auth);
  });

  it('proxies arbitrary string properties', () => {
    const realClient = makeRealClient();
    getServiceClient.mockReturnValue(realClient);
    const guarded = getGuardedClient();
    expect(guarded.someOtherProp).toBe('test-value');
  });

  it('does not mutate the original client — original client still allows mutations', () => {
    const realClient = makeRealClient();
    getServiceClient.mockReturnValue(realClient);
    getGuardedClient(); // create the guard

    // The original client's from() should still return an unguarded query builder
    const originalQb = realClient.from('receipts');
    expect(() => originalQb.insert({ id: '1' })).not.toThrow();
  });
});
