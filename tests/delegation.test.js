/**
 * Tests for lib/delegation.js
 *
 * Mocks @/lib/supabase so no real DB is needed.
 */

import { vi } from 'vitest';

// ---------------------------------------------------------------------------
// Supabase mock
// ---------------------------------------------------------------------------

const mockSupabase = {
  from: vi.fn(),
};

vi.mock('@/lib/supabase', () => ({
  getServiceClient: vi.fn(() => mockSupabase),
}));

import {
  EPError,
  createDelegation,
  verifyDelegation,
  revokeDelegation,
} from '@/lib/delegation.js';

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function makeDelegationRecord(overrides = {}) {
  return {
    delegation_id: 'ep_dlg_abc123',
    principal_id: 'principal-1',
    agent_entity_id: 'agent-ent-1',
    scope: ['submit', 'read'],
    max_value_usd: null,
    expires_at: new Date(Date.now() + 60 * 60 * 1000).toISOString(), // 1hr from now
    constraints: null,
    status: 'active',
    created_at: new Date().toISOString(),
    ...overrides,
  };
}

/**
 * Build a chainable mock for supabase table queries.
 * Supports patterns: .from().select().eq().maybeSingle() and
 * .from().insert().select().single() and
 * .from().update().eq().eq().select().maybeSingle()
 */
function buildQueryChain(resolveValue) {
  const chain = {};
  const methods = ['select', 'eq', 'maybeSingle', 'single', 'insert', 'update'];
  const terminal = vi.fn().mockResolvedValue(resolveValue);

  for (const m of methods) {
    chain[m] = vi.fn(() => chain);
  }
  // Override the terminal calls
  chain.maybeSingle = terminal;
  chain.single = terminal;
  return chain;
}

// ---------------------------------------------------------------------------
// EPError
// ---------------------------------------------------------------------------

describe('EPError', () => {
  it('is an instance of Error', () => {
    const err = new EPError('test');
    expect(err).toBeInstanceOf(Error);
  });

  it('has name "EPError"', () => {
    expect(new EPError('oops').name).toBe('EPError');
  });

  it('defaults status to 500 and code to INTERNAL_ERROR', () => {
    const err = new EPError('fail');
    expect(err.status).toBe(500);
    expect(err.code).toBe('INTERNAL_ERROR');
  });

  it('accepts custom status and code', () => {
    const err = new EPError('not found', 404, 'NOT_FOUND');
    expect(err.status).toBe(404);
    expect(err.code).toBe('NOT_FOUND');
    expect(err.message).toBe('not found');
  });
});

// ---------------------------------------------------------------------------
// createDelegation
// ---------------------------------------------------------------------------

describe('createDelegation', () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  it('throws EPError 400 when principalId is missing', async () => {
    await expect(
      createDelegation({ principalId: '', agentEntityId: 'agent-1', scope: ['read'] })
    ).rejects.toThrow(EPError);
  });

  it('throws EPError 400 when agentEntityId is missing', async () => {
    await expect(
      createDelegation({ principalId: 'p-1', agentEntityId: '', scope: ['read'] })
    ).rejects.toThrow(EPError);
  });

  it('throws EPError 400 when scope is empty', async () => {
    await expect(
      createDelegation({ principalId: 'p-1', agentEntityId: 'agent-1', scope: [] })
    ).rejects.toThrow(EPError);
  });

  it('throws EPError 400 when scope is null', async () => {
    await expect(
      createDelegation({ principalId: 'p-1', agentEntityId: 'agent-1', scope: null })
    ).rejects.toThrow(EPError);
  });

  it('validation error has code VALIDATION_ERROR and status 400', async () => {
    try {
      await createDelegation({ principalId: null, agentEntityId: 'a', scope: ['r'] });
    } catch (err) {
      expect(err.code).toBe('VALIDATION_ERROR');
      expect(err.status).toBe(400);
    }
  });

  it('throws ENTITY_NOT_FOUND when agent entity does not exist', async () => {
    // Agent lookup returns null
    const chain = buildQueryChain({ data: null, error: null });
    mockSupabase.from = vi.fn(() => chain);

    await expect(
      createDelegation({ principalId: 'p-1', agentEntityId: 'ghost-agent', scope: ['read'] })
    ).rejects.toMatchObject({ code: 'ENTITY_NOT_FOUND', status: 404 });
  });

  it('throws DELEGATION_STORE_UNAVAILABLE when table is missing (42P01)', async () => {
    // First call (agent lookup) succeeds; second call (insert) fails with 42P01
    const agentChain = buildQueryChain({ data: { id: 1, entity_id: 'agent-1', display_name: 'Agent' }, error: null });
    const insertChain = buildQueryChain({ data: null, error: { code: '42P01', message: 'table not found' } });

    let callCount = 0;
    mockSupabase.from = vi.fn(() => {
      callCount++;
      return callCount === 1 ? agentChain : insertChain;
    });

    await expect(
      createDelegation({ principalId: 'p-1', agentEntityId: 'agent-1', scope: ['read'] })
    ).rejects.toMatchObject({ code: 'DELEGATION_STORE_UNAVAILABLE', status: 503 });
  });

  it('throws DB_ERROR on generic insert failure', async () => {
    const agentChain = buildQueryChain({ data: { id: 1, entity_id: 'agent-1', display_name: 'Agent' }, error: null });
    const insertChain = buildQueryChain({ data: null, error: { code: 'OTHER', message: 'something broke' } });

    let callCount = 0;
    mockSupabase.from = vi.fn(() => {
      callCount++;
      return callCount === 1 ? agentChain : insertChain;
    });

    await expect(
      createDelegation({ principalId: 'p-1', agentEntityId: 'agent-1', scope: ['read'] })
    ).rejects.toMatchObject({ code: 'DB_ERROR' });
  });

  it('returns the created delegation record on success', async () => {
    const record = makeDelegationRecord();
    const agentChain = buildQueryChain({ data: { id: 1, entity_id: 'agent-ent-1', display_name: 'Agent' }, error: null });
    const insertChain = buildQueryChain({ data: record, error: null });

    let callCount = 0;
    mockSupabase.from = vi.fn(() => {
      callCount++;
      return callCount === 1 ? agentChain : insertChain;
    });

    const result = await createDelegation({
      principalId: 'principal-1',
      agentEntityId: 'agent-ent-1',
      scope: ['submit', 'read'],
    });

    expect(result).toEqual(record);
  });

  it('defaults expiry to roughly 24 hours when expiresAt is null', async () => {
    const record = makeDelegationRecord();
    const agentChain = buildQueryChain({ data: { id: 1, entity_id: 'agent-ent-1', display_name: 'Agent' }, error: null });

    // Capture the insert payload
    let capturedPayload;
    const insertFn = vi.fn((payload) => {
      capturedPayload = payload;
      return {
        select: vi.fn(() => ({ single: vi.fn().mockResolvedValue({ data: record, error: null }) })),
      };
    });

    let callCount = 0;
    mockSupabase.from = vi.fn(() => {
      callCount++;
      if (callCount === 1) return agentChain;
      return { insert: insertFn };
    });

    await createDelegation({
      principalId: 'p-1',
      agentEntityId: 'agent-ent-1',
      scope: ['read'],
      expiresAt: null,
    });

    // Check that an expiry was calculated
    expect(capturedPayload).toBeDefined();
    const expiry = new Date(capturedPayload.expires_at);
    const diff = expiry - Date.now();
    expect(diff).toBeGreaterThan(23 * 60 * 60 * 1000); // > 23 hrs
    expect(diff).toBeLessThan(25 * 60 * 60 * 1000); // < 25 hrs
  });
});

// ---------------------------------------------------------------------------
// verifyDelegation
// ---------------------------------------------------------------------------

describe('verifyDelegation', () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  it('returns not_found when table missing (42P01 error)', async () => {
    const chain = buildQueryChain({ data: null, error: { code: '42P01' } });
    mockSupabase.from = vi.fn(() => chain);

    const result = await verifyDelegation('ep_dlg_missing');
    expect(result.valid).toBe(false);
    expect(result.status).toBe('not_found');
  });

  it('returns not_found when delegation does not exist', async () => {
    const chain = buildQueryChain({ data: null, error: null });
    mockSupabase.from = vi.fn(() => chain);

    const result = await verifyDelegation('ep_dlg_ghost');
    expect(result.valid).toBe(false);
    expect(result.status).toBe('not_found');
  });

  it('returns valid: false for a revoked delegation', async () => {
    const record = makeDelegationRecord({ status: 'revoked' });
    const chain = buildQueryChain({ data: record, error: null });
    mockSupabase.from = vi.fn(() => chain);

    const result = await verifyDelegation('ep_dlg_revoked');
    expect(result.valid).toBe(false);
    expect(result.reason).toMatch(/revoked/i);
  });

  it('returns valid: false and expired status for an expired delegation', async () => {
    const record = makeDelegationRecord({
      expires_at: new Date(Date.now() - 1000).toISOString(),
      status: 'active',
    });

    // Need to handle the update call on expiry
    const updateChain = {
      update: vi.fn(() => ({ eq: vi.fn(() => Promise.resolve({ data: null, error: null })) })),
    };
    const selectChain = buildQueryChain({ data: record, error: null });

    let callCount = 0;
    mockSupabase.from = vi.fn(() => {
      callCount++;
      return callCount === 1 ? selectChain : updateChain;
    });

    const result = await verifyDelegation('ep_dlg_expired');
    expect(result.valid).toBe(false);
    expect(result.status).toBe('expired');
  });

  it('returns valid: true for an active, non-expired delegation', async () => {
    const record = makeDelegationRecord();
    const chain = buildQueryChain({ data: record, error: null });
    mockSupabase.from = vi.fn(() => chain);

    const result = await verifyDelegation('ep_dlg_abc123');
    expect(result.valid).toBe(true);
  });

  it('checks action_permitted when actionType is provided and in scope', async () => {
    const record = makeDelegationRecord({ scope: ['submit', 'read'] });
    const chain = buildQueryChain({ data: record, error: null });
    mockSupabase.from = vi.fn(() => chain);

    const result = await verifyDelegation('ep_dlg_abc123', 'submit');
    expect(result.action_permitted).toBe(true);
    expect(result.action_type).toBe('submit');
  });

  it('marks action_permitted false for an action not in scope', async () => {
    const record = makeDelegationRecord({ scope: ['read'] });
    const chain = buildQueryChain({ data: record, error: null });
    mockSupabase.from = vi.fn(() => chain);

    const result = await verifyDelegation('ep_dlg_abc123', 'delete');
    expect(result.valid).toBe(true);
    expect(result.action_permitted).toBe(false);
    expect(result.reason).toMatch(/delete/);
  });

  it('wildcard scope "*" permits any action', async () => {
    const record = makeDelegationRecord({ scope: ['*'] });
    const chain = buildQueryChain({ data: record, error: null });
    mockSupabase.from = vi.fn(() => chain);

    const result = await verifyDelegation('ep_dlg_abc123', 'anything');
    expect(result.action_permitted).toBe(true);
  });

  it('does not set action_permitted when actionType is null', async () => {
    const record = makeDelegationRecord();
    const chain = buildQueryChain({ data: record, error: null });
    mockSupabase.from = vi.fn(() => chain);

    const result = await verifyDelegation('ep_dlg_abc123', null);
    expect(result.action_permitted).toBeUndefined();
  });
});

// ---------------------------------------------------------------------------
// revokeDelegation
// ---------------------------------------------------------------------------

describe('revokeDelegation', () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  it('resolves successfully when revocation matches', async () => {
    const record = makeDelegationRecord({ status: 'revoked' });
    const chain = {
      update: vi.fn(() => ({
        eq: vi.fn(() => ({
          eq: vi.fn(() => ({
            select: vi.fn(() => ({
              maybeSingle: vi.fn().mockResolvedValue({ data: record, error: null }),
            })),
          })),
        })),
      })),
    };
    mockSupabase.from = vi.fn(() => chain);

    await expect(revokeDelegation('ep_dlg_abc123', 'principal-1')).resolves.toBeUndefined();
  });

  it('throws NOT_FOUND when no matching delegation+principal row', async () => {
    const chain = {
      update: vi.fn(() => ({
        eq: vi.fn(() => ({
          eq: vi.fn(() => ({
            select: vi.fn(() => ({
              maybeSingle: vi.fn().mockResolvedValue({ data: null, error: null }),
            })),
          })),
        })),
      })),
    };
    mockSupabase.from = vi.fn(() => chain);

    await expect(
      revokeDelegation('ep_dlg_ghost', 'wrong-principal')
    ).rejects.toMatchObject({ code: 'NOT_FOUND', status: 404 });
  });

  it('throws DB_ERROR on supabase error during revocation', async () => {
    const chain = {
      update: vi.fn(() => ({
        eq: vi.fn(() => ({
          eq: vi.fn(() => ({
            select: vi.fn(() => ({
              maybeSingle: vi.fn().mockResolvedValue({ data: null, error: { message: 'timeout' } }),
            })),
          })),
        })),
      })),
    };
    mockSupabase.from = vi.fn(() => chain);

    await expect(
      revokeDelegation('ep_dlg_abc123', 'p-1')
    ).rejects.toMatchObject({ code: 'DB_ERROR' });
  });
});
