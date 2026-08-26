/**
 * EP-IX Identity Continuity Core — Unit Tests
 *
 * Covers: registerPrincipal, createBinding, verifyBinding, fileContinuityClaim,
 * challengeContinuity, resolveContinuity, getPrincipal, getLineage,
 * expireContinuityClaims, and emitAudit.
 *
 * All supabase calls are mocked.
 */

import { describe, it, expect, vi, beforeEach } from 'vitest';

// ── Supabase chain helper ────────────────────────────────────────────────────

function makeChain(resolveValue = { data: null, error: null }) {
  const chain = {
    select: vi.fn().mockReturnThis(),
    eq: vi.fn().mockReturnThis(),
    neq: vi.fn().mockReturnThis(),
    in: vi.fn().mockReturnThis(),
    is: vi.fn().mockReturnThis(),
    lt: vi.fn().mockReturnThis(),
    order: vi.fn().mockReturnThis(),
    limit: vi.fn().mockReturnThis(),
    insert: vi.fn().mockResolvedValue(resolveValue),
    update: vi.fn().mockReturnThis(),
    single: vi.fn().mockResolvedValue(resolveValue),
    maybeSingle: vi.fn().mockResolvedValue(resolveValue),
    then: (resolve) => Promise.resolve(resolveValue).then(resolve),
  };
  return chain;
}

// ── Mock declarations ────────────────────────────────────────────────────────

const mockGetServiceClient = vi.fn();

vi.mock('../lib/supabase.js', () => ({
  getServiceClient: (...args) => mockGetServiceClient(...args),
}));

// Import after mocks
import {
  registerPrincipal,
  createBinding,
  verifyBinding,
  fileContinuityClaim,
  challengeContinuity,
  resolveContinuity,
  getPrincipal,
  getLineage,
  expireContinuityClaims,
  emitAudit,
} from '../lib/ep-ix.js';

// ── Fixtures ─────────────────────────────────────────────────────────────────

function makePrincipal(overrides = {}) {
  return {
    id: 'db-p-001',
    principal_id: 'ep_principal_aabbccdd',
    principal_type: 'organization',
    display_name: 'ACME Corp',
    status: 'active',
    bootstrap_verified: false,
    metadata: {},
    ...overrides,
  };
}

function makeClaim(overrides = {}) {
  return {
    id: 'db-claim-001',
    continuity_id: 'ep_ix_aabbccdd',
    principal_id: 'db-p-001',
    old_entity_id: 'old-acme',
    new_entity_id: 'new-acme',
    reason: 'rebrand',
    continuity_mode: 'linear',
    status: 'pending',
    challenge_deadline: new Date(Date.now() + 7 * 24 * 60 * 60 * 1000).toISOString(),
    expires_at: new Date(Date.now() + 30 * 24 * 60 * 60 * 1000).toISOString(),
    transfer_budget: 1.0,
    ...overrides,
  };
}

// ── Setup ────────────────────────────────────────────────────────────────────

let mockSupabase;

beforeEach(() => {
  vi.clearAllMocks();

  mockSupabase = {
    from: vi.fn().mockReturnValue(makeChain({ data: null, error: null })),
  };
  mockGetServiceClient.mockReturnValue(mockSupabase);
});

// ── registerPrincipal ─────────────────────────────────────────────────────────

describe('registerPrincipal', () => {
  it('registers a new principal and returns it', async () => {
    const principal = makePrincipal();
    const insertChain = makeChain({ data: principal, error: null });
    insertChain.insert = vi.fn().mockReturnThis();
    insertChain.select = vi.fn().mockReturnThis();
    insertChain.single = vi.fn().mockResolvedValue({ data: principal, error: null });
    mockSupabase.from.mockReturnValue(insertChain);

    const result = await registerPrincipal({
      principal_type: 'organization',
      display_name: 'ACME Corp',
    });

    expect(result.principal).toEqual(principal);
    expect(result.error).toBeUndefined();
  });

  it('uses provided principal_id when given', async () => {
    const principal = makePrincipal({ principal_id: 'custom_id_123' });
    const insertChain = makeChain({ data: principal, error: null });
    insertChain.insert = vi.fn().mockReturnThis();
    insertChain.select = vi.fn().mockReturnThis();
    insertChain.single = vi.fn().mockResolvedValue({ data: principal, error: null });
    mockSupabase.from.mockReturnValue(insertChain);

    const result = await registerPrincipal({
      principal_id: 'custom_id_123',
      principal_type: 'individual',
      display_name: 'Alice',
    });

    const insertCall = insertChain.insert.mock.calls[0][0];
    expect(insertCall.principal_id).toBe('custom_id_123');
    expect(result.principal).toEqual(principal);
  });

  it('generates a principal_id when not provided', async () => {
    const principal = makePrincipal();
    const insertChain = makeChain({ data: principal, error: null });
    insertChain.insert = vi.fn().mockReturnThis();
    insertChain.select = vi.fn().mockReturnThis();
    insertChain.single = vi.fn().mockResolvedValue({ data: principal, error: null });
    mockSupabase.from.mockReturnValue(insertChain);

    await registerPrincipal({ principal_type: 'organization', display_name: 'Corp' });

    const insertCall = insertChain.insert.mock.calls[0][0];
    expect(insertCall.principal_id).toMatch(/^ep_principal_/);
  });

  it('returns 409 on duplicate (unique constraint violation)', async () => {
    const insertChain = makeChain({ data: null, error: { message: 'duplicate', code: '23505' } });
    insertChain.insert = vi.fn().mockReturnThis();
    insertChain.select = vi.fn().mockReturnThis();
    insertChain.single = vi.fn().mockResolvedValue({ data: null, error: { message: 'duplicate', code: '23505' } });
    mockSupabase.from.mockReturnValue(insertChain);

    const result = await registerPrincipal({ principal_type: 'org', display_name: 'Dup' });
    expect(result.error).toBe('duplicate');
    expect(result.status).toBe(409);
  });

  it('returns 500 on other errors', async () => {
    const insertChain = makeChain({ data: null, error: { message: 'DB error', code: '500' } });
    insertChain.insert = vi.fn().mockReturnThis();
    insertChain.select = vi.fn().mockReturnThis();
    insertChain.single = vi.fn().mockResolvedValue({ data: null, error: { message: 'DB error', code: '500' } });
    mockSupabase.from.mockReturnValue(insertChain);

    const result = await registerPrincipal({ principal_type: 'org', display_name: 'Fail' });
    expect(result.status).toBe(500);
  });

  it('sets bootstrap_verified from params', async () => {
    const principal = makePrincipal({ bootstrap_verified: true });
    const insertChain = makeChain({ data: principal, error: null });
    insertChain.insert = vi.fn().mockReturnThis();
    insertChain.select = vi.fn().mockReturnThis();
    insertChain.single = vi.fn().mockResolvedValue({ data: principal, error: null });
    mockSupabase.from.mockReturnValue(insertChain);

    await registerPrincipal({ principal_type: 'org', display_name: 'Corp', bootstrap_verified: true });

    const insertCall = insertChain.insert.mock.calls[0][0];
    expect(insertCall.bootstrap_verified).toBe(true);
  });
});

// ── createBinding ─────────────────────────────────────────────────────────────

describe('createBinding', () => {
  it('creates a binding when principal exists', async () => {
    const principal = makePrincipal();
    const binding = { binding_id: 'ep_bind_xyz', binding_type: 'github', status: 'pending' };

    let callCount = 0;
    mockSupabase.from.mockImplementation(() => {
      callCount++;
      if (callCount === 1) {
        // principal lookup
        const chain = makeChain({ data: principal, error: null });
        chain.single = vi.fn().mockResolvedValue({ data: principal, error: null });
        return chain;
      }
      // binding insert
      const chain = makeChain({ data: binding, error: null });
      chain.insert = vi.fn().mockReturnThis();
      chain.select = vi.fn().mockReturnThis();
      chain.single = vi.fn().mockResolvedValue({ data: binding, error: null });
      return chain;
    });

    const result = await createBinding({
      principal_id: 'ep_principal_aabbccdd',
      binding_type: 'github',
      binding_target: 'github:acme-org',
    });

    expect(result.binding).toEqual(binding);
    expect(result.error).toBeUndefined();
  });

  it('returns 404 when principal not found', async () => {
    const chain = makeChain({ data: null, error: null });
    chain.single = vi.fn().mockResolvedValue({ data: null, error: null });
    mockSupabase.from.mockReturnValue(chain);

    const result = await createBinding({
      principal_id: 'nonexistent',
      binding_type: 'github',
      binding_target: 'github:nobody',
    });

    expect(result.error).toBe('Principal not found');
    expect(result.status).toBe(404);
  });

  it('returns error when insert fails', async () => {
    const principal = makePrincipal();
    let callCount = 0;
    mockSupabase.from.mockImplementation(() => {
      callCount++;
      if (callCount === 1) {
        const chain = makeChain({ data: principal, error: null });
        chain.single = vi.fn().mockResolvedValue({ data: principal, error: null });
        return chain;
      }
      const chain = makeChain({ data: null, error: { message: 'insert failed' } });
      chain.insert = vi.fn().mockReturnThis();
      chain.select = vi.fn().mockReturnThis();
      chain.single = vi.fn().mockResolvedValue({ data: null, error: { message: 'insert failed' } });
      return chain;
    });

    const result = await createBinding({
      principal_id: 'ep_principal_aabbccdd',
      binding_type: 'github',
      binding_target: 'github:acme',
    });

    expect(result.error).toBe('insert failed');
    expect(result.status).toBe(500);
  });
});

// ── verifyBinding ─────────────────────────────────────────────────────────────

describe('verifyBinding', () => {
  it('returns 404 when binding not found or already verified', async () => {
    const chain = makeChain({ data: null, error: null });
    chain.update = vi.fn().mockReturnThis();
    chain.eq = vi.fn().mockReturnThis();
    chain.select = vi.fn().mockReturnThis();
    chain.single = vi.fn().mockResolvedValue({ data: null, error: null });
    mockSupabase.from.mockReturnValue(chain);

    const result = await verifyBinding('ep_bind_xyz', 'op_1');
    expect(result.error).toBe('Binding not found or already verified');
    expect(result.status).toBe(404);
  });

  it('returns updated binding on success', async () => {
    const binding = { binding_id: 'ep_bind_xyz', status: 'verified' };
    const auditChain = makeChain({ data: null, error: null });
    auditChain.insert = vi.fn().mockResolvedValue({ data: null, error: null });

    let callCount = 0;
    mockSupabase.from.mockImplementation(() => {
      callCount++;
      if (callCount === 1) {
        // binding update
        const chain = makeChain({ data: binding, error: null });
        chain.update = vi.fn().mockReturnThis();
        chain.eq = vi.fn().mockReturnThis();
        chain.select = vi.fn().mockReturnThis();
        chain.single = vi.fn().mockResolvedValue({ data: binding, error: null });
        return chain;
      }
      return auditChain;
    });

    const result = await verifyBinding('ep_bind_xyz', 'op_1');
    expect(result.binding).toEqual(binding);
  });

  it('refuses an anonymous/empty verifier and does not write (defense in depth)', async () => {
    // The route authorizes and passes a named operator_id; this guard ensures a
    // caller reaching verifyBinding without a named verifier cannot record an
    // unattributable verification. No supabase write should occur.
    mockSupabase.from.mockImplementation(() => {
      throw new Error('verifyBinding must not touch the DB without a named verifier');
    });

    for (const bad of [undefined, null, '', '   ']) {
      const result = await verifyBinding('ep_bind_xyz', bad);
      expect(result.status).toBe(400);
      expect(result.error).toMatch(/named verifier/i);
    }
    expect(mockSupabase.from).not.toHaveBeenCalled();
  });
});

// ── fileContinuityClaim ───────────────────────────────────────────────────────

describe('fileContinuityClaim', () => {
  it.each([
    [{ principal_id: '', old_entity_id: 'old', new_entity_id: 'new', reason: 'key_rotation' }, 'principal_id'],
    [{ principal_id: 'principal', old_entity_id: '', new_entity_id: 'new', reason: 'key_rotation' }, 'old_entity_id'],
    [{ principal_id: 'principal', old_entity_id: 'old', new_entity_id: '', reason: 'key_rotation' }, 'new_entity_id'],
    [{ principal_id: 'principal', old_entity_id: 'old', new_entity_id: 'new', reason: '' }, 'reason'],
  ])('rejects malformed filing input before database access', async (params, expected) => {
    const result = await fileContinuityClaim(params, 'filing-actor');
    expect(result.status).toBe(400);
    expect(result.error).toContain(expected);
    expect(mockSupabase.from).not.toHaveBeenCalled();
  });

  it('rejects equal continuity endpoints before database access', async () => {
    const result = await fileContinuityClaim({
      principal_id: 'principal',
      old_entity_id: 'same',
      new_entity_id: 'same',
      reason: 'key_rotation',
    }, 'filing-actor');
    expect(result.status).toBe(400);
    expect(result.error).toContain('distinct');
    expect(mockSupabase.from).not.toHaveBeenCalled();
  });

  it('rejects invalid transfer budgets before database access', async () => {
    for (const transfer_budget of [0, -0.1, 1.01, Number.NaN, Number.POSITIVE_INFINITY, '0.5']) {
      const result = await fileContinuityClaim({
        principal_id: 'principal',
        old_entity_id: 'old',
        new_entity_id: 'new',
        reason: 'key_rotation',
        transfer_budget: transfer_budget as any,
      }, 'filing-actor');
      expect(result.status).toBe(400);
      expect(result.error).toContain('transfer_budget');
    }
    expect(mockSupabase.from).not.toHaveBeenCalled();
  });
});

// ── challengeContinuity ───────────────────────────────────────────────────────

describe('challengeContinuity', () => {
  it.each([
    [{ continuity_id: '', challenger_id: 'entity-1', reason: 'reason' }, 'continuity_id'],
    [{ continuity_id: 'ep_ix_1', challenger_id: '', reason: 'reason' }, 'challenger'],
    [{ continuity_id: 'ep_ix_1', challenger_id: 'entity-1', reason: '' }, 'reason'],
  ])('rejects malformed transaction input before database access', async (params, expected) => {
    const result = await challengeContinuity(params);
    expect(result.status).toBe(400);
    expect(result.error).toContain(expected);
    expect(mockSupabase.from).not.toHaveBeenCalled();
  });

  it('rejects non-object evidence before database access', async () => {
    const result = await challengeContinuity({
      continuity_id: 'ep_ix_1',
      challenger_id: 'entity-1',
      reason: 'reason',
      evidence: [] as any,
    });
    expect(result.status).toBe(400);
    expect(result.error).toContain('evidence');
    expect(mockSupabase.from).not.toHaveBeenCalled();
  });
});

// ── resolveContinuity ─────────────────────────────────────────────────────────

describe('resolveContinuity', () => {
  it.each([
    ['', 'approved_full', [], 'operator', 'continuity_id'],
    ['ep_ix_aabbccdd', 'unsupported', [], 'operator', 'decision'],
    ['ep_ix_aabbccdd', 'approved_full', {} as any, 'operator', 'reasoning'],
    ['ep_ix_aabbccdd', 'approved_full', [], '', 'operator'],
  ])('rejects malformed resolution before database access', async (
    continuityId,
    decision,
    reasoning,
    operatorId,
    expected,
  ) => {
    const result = await resolveContinuity(continuityId, decision, reasoning, operatorId);
    expect(result.status).toBe(400);
    expect(result.error).toContain(expected);
    expect(mockSupabase.from).not.toHaveBeenCalled();
  });
});

// ── getPrincipal ──────────────────────────────────────────────────────────────

describe('getPrincipal', () => {
  it('returns 404 when principal not found', async () => {
    const chain = makeChain({ data: null, error: null });
    chain.single = vi.fn().mockResolvedValue({ data: null, error: null });
    mockSupabase.from.mockReturnValue(chain);

    const result = await getPrincipal('nonexistent');
    expect(result.error).toBe('Principal not found');
    expect(result.status).toBe(404);
  });

  it('returns principal with bindings, entities, and claims', async () => {
    const principal = makePrincipal();
    const bindings = [{ binding_id: 'b1', binding_type: 'github', status: 'verified' }];
    const entities = [{ entity_id: 'e1', display_name: 'ACME', entity_type: 'organization' }];
    const claims = [makeClaim()];

    let callCount = 0;
    mockSupabase.from.mockImplementation(() => {
      callCount++;
      if (callCount === 1) {
        const chain = makeChain({ data: principal, error: null });
        chain.single = vi.fn().mockResolvedValue({ data: principal, error: null });
        return chain;
      }
      if (callCount === 2) {
        return makeChain({ data: bindings, error: null });
      }
      if (callCount === 3) {
        return makeChain({ data: entities, error: null });
      }
      return makeChain({ data: claims, error: null });
    });

    const result = await getPrincipal('ep_principal_aabbccdd');
    expect(result.principal).toEqual(principal);
    expect(result.bindings).toEqual(bindings);
    expect(result.entities).toEqual(entities);
    expect(result.continuity_claims).toEqual(claims);
  });

  it('returns empty arrays when no bindings/entities/claims', async () => {
    const principal = makePrincipal();

    let callCount = 0;
    mockSupabase.from.mockImplementation(() => {
      callCount++;
      if (callCount === 1) {
        const chain = makeChain({ data: principal, error: null });
        chain.single = vi.fn().mockResolvedValue({ data: principal, error: null });
        return chain;
      }
      return makeChain({ data: null, error: null });
    });

    const result = await getPrincipal('ep_principal_aabbccdd');
    expect(result.bindings).toEqual([]);
    expect(result.entities).toEqual([]);
    expect(result.continuity_claims).toEqual([]);
  });
});

// ── getLineage ────────────────────────────────────────────────────────────────

describe('getLineage', () => {
  it('returns entity lineage with predecessors and successors', async () => {
    const asOld = [{ old_entity_id: 'old', new_entity_id: 'new-acme', reason: 'rebrand', status: 'approved_full', transfer_policy: 'full', continuity_decisions: [{ decided_at: '2026-01-01' }] }];
    const asNew = [{ old_entity_id: 'ancestor', new_entity_id: 'old', reason: 'rebrand', status: 'approved_full', transfer_policy: 'full', continuity_decisions: [] }];

    let callCount = 0;
    mockSupabase.from.mockImplementation(() => {
      callCount++;
      if (callCount === 1) return makeChain({ data: asOld, error: null });
      return makeChain({ data: asNew, error: null });
    });

    const result = await getLineage('old');
    expect(result.entity_id).toBe('old');
    expect(result.successors).toHaveLength(1);
    expect(result.predecessors).toHaveLength(1);
  });

  it('returns empty arrays when entity has no lineage', async () => {
    mockSupabase.from.mockReturnValue(makeChain({ data: null, error: null }));

    const result = await getLineage('standalone');
    expect(result.entity_id).toBe('standalone');
    expect(result.successors).toEqual([]);
    expect(result.predecessors).toEqual([]);
  });
});

// ── expireContinuityClaims ────────────────────────────────────────────────────

describe('expireContinuityClaims', () => {
  it('expires stale claims and returns count', async () => {
    const expiredClaims = [{ continuity_id: 'ep_ix_1' }, { continuity_id: 'ep_ix_2' }];
    const selectChain = makeChain({ data: expiredClaims, error: null });
    selectChain.then = (r) => Promise.resolve({ data: expiredClaims, error: null }).then(r);
    const updateChain = makeChain({ data: null, error: null });
    updateChain.update = vi.fn().mockReturnThis();
    updateChain.in = vi.fn().mockReturnThis();
    updateChain.then = (r) => Promise.resolve({ data: null, error: null }).then(r);

    let callCount = 0;
    mockSupabase.from.mockImplementation(() => {
      callCount++;
      if (callCount === 1) return selectChain;
      return updateChain;
    });

    const count = await expireContinuityClaims();
    expect(count).toBe(2);
  });

  it('returns 0 when no claims to expire', async () => {
    const chain = makeChain({ data: [], error: null });
    chain.then = (r) => Promise.resolve({ data: [], error: null }).then(r);
    mockSupabase.from.mockReturnValue(chain);

    const count = await expireContinuityClaims();
    expect(count).toBe(0);
  });

  it('returns 0 when DB returns null', async () => {
    const chain = makeChain({ data: null, error: null });
    chain.then = (r) => Promise.resolve({ data: null, error: null }).then(r);
    mockSupabase.from.mockReturnValue(chain);

    const count = await expireContinuityClaims();
    expect(count).toBe(0);
  });
});

// ── emitAudit ─────────────────────────────────────────────────────────────────

describe('emitAudit', () => {
  it('inserts audit event into audit_events table', async () => {
    const insertChain = makeChain({ data: null, error: null });
    insertChain.insert = vi.fn().mockResolvedValue({ data: null, error: null });
    mockSupabase.from.mockReturnValue(insertChain);

    // Should not throw
    await expect(
      emitAudit('binding.verified', 'op_1', 'operator', 'binding', 'b_1', 'verify', null, { status: 'verified' })
    ).resolves.not.toThrow();

    expect(mockSupabase.from).toHaveBeenCalledWith('audit_events');
  });

  it('does not report a false mutation failure after a legacy state write committed', async () => {
    mockSupabase.from.mockImplementation(() => {
      throw new Error('DB down');
    });

    await expect(
      emitAudit('test.event', 'actor', 'operator', 'target', 't_1', 'action', null, {})
    ).resolves.toBeUndefined();
  });

  it('does not throw a retry-inducing error for a database-returned audit failure', async () => {
    const insertChain = makeChain({ data: null, error: null });
    insertChain.insert = vi.fn().mockResolvedValue({ data: null, error: { message: 'audit denied' } });
    mockSupabase.from.mockReturnValue(insertChain);

    await expect(
      emitAudit('test.event', 'actor', 'operator', 'target', 't_1', 'action', null, {})
    ).resolves.toBeUndefined();
  });
});
