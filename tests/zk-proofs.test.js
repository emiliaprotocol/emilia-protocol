import { describe, it, expect, vi, beforeEach } from 'vitest';
import {
  generateReceiptCommitment,
  buildCommitmentTree,
  generateZKProof,
  verifyZKProof,
} from '../lib/zk-proofs.js';

// ============================================================================
// Supabase mock helpers
// ============================================================================

vi.mock('../lib/supabase.js', () => ({
  getServiceClient: vi.fn(),
}));

/**
 * makeChain builds a fluent Supabase query builder mock.
 */
function makeChain(resolveValue) {
  const chain = {
    select: vi.fn().mockReturnThis(),
    eq: vi.fn().mockReturnThis(),
    neq: vi.fn().mockReturnThis(),
    in: vi.fn().mockReturnThis(),
    is: vi.fn().mockReturnThis(),
    not: vi.fn().mockReturnThis(),
    gte: vi.fn().mockReturnThis(),
    order: vi.fn().mockReturnThis(),
    limit: vi.fn().mockReturnThis(),
    update: vi.fn().mockReturnThis(),
    insert: vi.fn().mockResolvedValue({ error: null }),
    single: vi.fn().mockResolvedValue(resolveValue),
    maybeSingle: vi.fn().mockResolvedValue(resolveValue),
    then: (resolve) => Promise.resolve(resolveValue).then(resolve),
  };
  return chain;
}

// ============================================================================
// Test receipts
// ============================================================================

function makeReceipt(overrides = {}) {
  return {
    id: overrides.id || 'receipt-uuid-1',
    entity_id: overrides.entity_id || 'entity-slug-1',
    created_at: overrides.created_at || '2025-01-15T10:00:00.000Z',
    agent_behavior: overrides.agent_behavior || 'completed',
    graph_weight: overrides.graph_weight ?? 1.0,
    provenance_tier: overrides.provenance_tier || 'bilateral',
    context: overrides.context || null,
    counterparty_id: overrides.counterparty_id || 'counterparty-entity-uuid',
    submitted_by: overrides.submitted_by || 'submitter-uuid',
    ...overrides,
  };
}

// ============================================================================
// generateReceiptCommitment
// ============================================================================

describe('generateReceiptCommitment', () => {
  it('produces consistent output for the same inputs', () => {
    const receipt = makeReceipt({ id: 'receipt-1', entity_id: 'entity-a', created_at: '2025-01-15T10:00:00.000Z' });
    const salt = 'fixed-salt-for-testing';

    const result1 = generateReceiptCommitment(receipt, salt);
    const result2 = generateReceiptCommitment(receipt, salt);

    expect(result1).toBe(result2);
    expect(typeof result1).toBe('string');
    expect(result1).toHaveLength(64); // SHA-256 / HMAC-SHA256 hex output
  });

  it('produces DIFFERENT output for different salts', () => {
    const receipt = makeReceipt({ id: 'receipt-1', entity_id: 'entity-a', created_at: '2025-01-15T10:00:00.000Z' });

    const result1 = generateReceiptCommitment(receipt, 'salt-alpha');
    const result2 = generateReceiptCommitment(receipt, 'salt-beta');

    expect(result1).not.toBe(result2);
  });

  it('does NOT include counterparty_id in the commitment (same hash despite different counterparties)', () => {
    const salt = 'same-salt';
    // Two receipts identical except counterparty_id — commitment should be the same
    const receipt1 = makeReceipt({
      id: 'receipt-1',
      entity_id: 'entity-a',
      created_at: '2025-01-15T10:00:00.000Z',
      counterparty_id: 'counterparty-uuid-A',
    });
    const receipt2 = makeReceipt({
      id: 'receipt-1',
      entity_id: 'entity-a',
      created_at: '2025-01-15T10:00:00.000Z',
      counterparty_id: 'counterparty-uuid-B', // different counterparty
    });

    const h1 = generateReceiptCommitment(receipt1, salt);
    const h2 = generateReceiptCommitment(receipt2, salt);

    // Commitment must be identical — counterparty must not affect the hash
    expect(h1).toBe(h2);
  });

  it('produces different commitments when receipt id differs', () => {
    const salt = 'same-salt';
    const base = { entity_id: 'entity-a', created_at: '2025-01-15T10:00:00.000Z' };

    const h1 = generateReceiptCommitment(makeReceipt({ ...base, id: 'receipt-1' }), salt);
    const h2 = generateReceiptCommitment(makeReceipt({ ...base, id: 'receipt-2' }), salt);

    expect(h1).not.toBe(h2);
  });

  it('throws when required fields are missing from the receipt', () => {
    expect(() => generateReceiptCommitment({ entity_id: 'e', created_at: 't' }, 'salt')).toThrow();
    expect(() => generateReceiptCommitment({ id: 'i', created_at: 't' }, 'salt')).toThrow();
    expect(() => generateReceiptCommitment({ id: 'i', entity_id: 'e' }, 'salt')).toThrow();
  });

  it('throws when salt is missing', () => {
    const receipt = makeReceipt();
    expect(() => generateReceiptCommitment(receipt, '')).toThrow();
    expect(() => generateReceiptCommitment(receipt, null)).toThrow();
    expect(() => generateReceiptCommitment(receipt, undefined)).toThrow();
  });
});

// ============================================================================
// buildCommitmentTree
// ============================================================================

describe('buildCommitmentTree', () => {
  it('produces consistent Merkle root for the same commitments', () => {
    const commitments = [
      'aabbcc'.padEnd(64, '0'),
      'ddeeff'.padEnd(64, '1'),
      '112233'.padEnd(64, '2'),
    ];

    const tree1 = buildCommitmentTree(commitments);
    const tree2 = buildCommitmentTree(commitments);

    expect(tree1.root).toBe(tree2.root);
    expect(typeof tree1.root).toBe('string');
  });

  it('root changes when any commitment changes', () => {
    const base = [
      'aabbcc'.padEnd(64, '0'),
      'ddeeff'.padEnd(64, '1'),
      '112233'.padEnd(64, '2'),
    ];
    const modified = [
      'aabbcc'.padEnd(64, '0'),
      'ffffff'.padEnd(64, 'f'), // changed
      '112233'.padEnd(64, '2'),
    ];

    const tree1 = buildCommitmentTree(base);
    const tree2 = buildCommitmentTree(modified);

    expect(tree1.root).not.toBe(tree2.root);
  });

  it('single commitment produces a tree with that commitment as root', () => {
    const commitment = 'abc123'.padEnd(64, 'a');
    const tree = buildCommitmentTree([commitment]);
    expect(tree.root).toBe(commitment);
    expect(tree.leafCount).toBe(1);
  });

  it('returns null root for empty commitments array', () => {
    const tree = buildCommitmentTree([]);
    expect(tree.root).toBeNull();
    expect(tree.leafCount).toBe(0);
  });

  it('returns null root for null/undefined input', () => {
    const tree1 = buildCommitmentTree(null);
    const tree2 = buildCommitmentTree(undefined);
    expect(tree1.root).toBeNull();
    expect(tree2.root).toBeNull();
  });
});

// ============================================================================
// generateZKProof
// ============================================================================

describe('generateZKProof', () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  function makeZKSupabase({
    entityData = { id: 'uuid-1', entity_id: 'my-entity', status: 'active' },
    entityError = null,
    receipts = [],
    anchorData = null,
    insertError = null,
  } = {}) {
    let fromCallCount = 0;
    return {
      from: vi.fn((table) => {
        fromCallCount += 1;

        if (table === 'entities') {
          return {
            select: vi.fn().mockReturnThis(),
            eq: vi.fn().mockReturnThis(),
            single: vi.fn().mockResolvedValue({ data: entityData, error: entityError }),
          };
        }

        if (table === 'receipts') {
          return makeChain({ data: receipts, error: null });
        }

        if (table === 'anchor_batches') {
          return {
            select: vi.fn().mockReturnThis(),
            not: vi.fn().mockReturnThis(),
            order: vi.fn().mockReturnThis(),
            limit: vi.fn().mockReturnThis(),
            single: vi.fn().mockResolvedValue({ data: anchorData, error: null }),
          };
        }

        if (table === 'zk_proofs') {
          return {
            insert: vi.fn().mockResolvedValue({ error: insertError }),
          };
        }

        return makeChain({ data: null, error: null });
      }),
    };
  }

  it('throws "claim_not_provable" when behavioral score is below threshold', async () => {
    const receipts = [
      makeReceipt({ id: 'r1', agent_behavior: 'abandoned', graph_weight: 1.0 }),
      makeReceipt({ id: 'r2', agent_behavior: 'disputed', graph_weight: 1.0 }),
    ];
    const mockSupabase = makeZKSupabase({ receipts });

    await expect(
      generateZKProof('my-entity', { type: 'score_above', threshold: 0.99 }, mockSupabase)
    ).rejects.toMatchObject({ code: 'claim_not_provable' });
  });

  it('generated proof contains commitment_root but NOT receipt details', async () => {
    const receipts = [
      makeReceipt({ id: 'r1', agent_behavior: 'completed', graph_weight: 1.0 }),
      makeReceipt({ id: 'r2', agent_behavior: 'completed', graph_weight: 1.0 }),
    ];
    const mockSupabase = makeZKSupabase({ receipts });

    const proof = await generateZKProof(
      'my-entity',
      { type: 'score_above', threshold: 0.5 },
      mockSupabase
    );

    expect(proof.commitment_root).toBeDefined();
    expect(typeof proof.commitment_root).toBe('string');
    // Proof must NOT contain raw receipt data
    expect(proof.receipts).toBeUndefined();
    expect(proof.receipt_data).toBeUndefined();
    expect(proof.counterparty_id).toBeUndefined();
    expect(proof.counterparty_ids).toBeUndefined();
  });

  it('generated proof contains correct receipt_count', async () => {
    const receipts = [
      makeReceipt({ id: 'r1', agent_behavior: 'completed', graph_weight: 1.0 }),
      makeReceipt({ id: 'r2', agent_behavior: 'completed', graph_weight: 1.0 }),
      makeReceipt({ id: 'r3', agent_behavior: 'completed', graph_weight: 1.0 }),
    ];
    const mockSupabase = makeZKSupabase({ receipts });

    const proof = await generateZKProof(
      'my-entity',
      { type: 'score_above', threshold: 0.5 },
      mockSupabase
    );

    expect(proof.receipt_count).toBe(3);
  });

  it('proof reveals threshold but not individual counterparty_ids', async () => {
    const receipts = [
      makeReceipt({ id: 'r1', agent_behavior: 'completed', counterparty_id: 'secret-cp-1' }),
      makeReceipt({ id: 'r2', agent_behavior: 'completed', counterparty_id: 'secret-cp-2' }),
    ];
    const mockSupabase = makeZKSupabase({ receipts });

    const proof = await generateZKProof(
      'my-entity',
      { type: 'score_above', threshold: 0.7 },
      mockSupabase
    );

    const proofStr = JSON.stringify(proof);
    // Threshold is disclosed
    expect(proof.claim.threshold).toBe(0.7);
    // Counterparty IDs must not appear in the proof
    expect(proofStr).not.toContain('secret-cp-1');
    expect(proofStr).not.toContain('secret-cp-2');
  });

  it('throws when entity is not found', async () => {
    const mockSupabase = makeZKSupabase({ entityData: null, entityError: { message: 'not found' } });

    await expect(
      generateZKProof('unknown-entity', { type: 'score_above', threshold: 0.5 }, mockSupabase)
    ).rejects.toThrow(/not found/i);
  });

  it('throws when entity is not active', async () => {
    const mockSupabase = makeZKSupabase({
      entityData: { id: 'uuid-1', entity_id: 'inactive-entity', status: 'suspended' },
    });

    await expect(
      generateZKProof('inactive-entity', { type: 'score_above', threshold: 0.5 }, mockSupabase)
    ).rejects.toThrow(/not active/i);
  });

  it('receipt_count_above claim is provable when count exceeds threshold', async () => {
    const receipts = Array(10).fill(null).map((_, i) =>
      makeReceipt({ id: `r-${i}`, agent_behavior: 'completed' })
    );
    const mockSupabase = makeZKSupabase({ receipts });

    const proof = await generateZKProof(
      'my-entity',
      { type: 'receipt_count_above', threshold: 5 },
      mockSupabase
    );

    expect(proof.receipt_count).toBe(10);
    expect(proof.claim.type).toBe('receipt_count_above');
  });

  it('receipt_count_above claim throws when count is below threshold', async () => {
    const receipts = [
      makeReceipt({ id: 'r1', agent_behavior: 'completed' }),
      makeReceipt({ id: 'r2', agent_behavior: 'completed' }),
    ];
    const mockSupabase = makeZKSupabase({ receipts });

    await expect(
      generateZKProof(
        'my-entity',
        { type: 'receipt_count_above', threshold: 100 },
        mockSupabase
      )
    ).rejects.toMatchObject({ code: 'claim_not_provable' });
  });
});

// ============================================================================
// verifyZKProof
// ============================================================================

describe('verifyZKProof', () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  function makeVerifySupabase({
    proofData = null,
    proofError = null,
    entityData = null,
    entityError = null,
    receipts = [],
    updateError = null,
  } = {}) {
    return {
      from: vi.fn((table) => {
        if (table === 'zk_proofs') {
          // Could be SELECT or UPDATE
          return {
            select: vi.fn().mockReturnThis(),
            eq: vi.fn().mockReturnThis(),
            single: vi.fn().mockResolvedValue({ data: proofData, error: proofError }),
            update: vi.fn().mockReturnThis(),
          };
        }

        if (table === 'entities') {
          return {
            select: vi.fn().mockReturnThis(),
            eq: vi.fn().mockReturnThis(),
            single: vi.fn().mockResolvedValue({ data: entityData, error: entityError }),
          };
        }

        if (table === 'receipts') {
          return makeChain({ data: receipts, error: null });
        }

        return makeChain({ data: null, error: null });
      }),
    };
  }

  it('returns valid=true for a fresh, valid proof whose claim is still met', async () => {
    const future = new Date(Date.now() + 10 * 24 * 60 * 60 * 1000).toISOString();
    const proofData = {
      proof_id: 'ep_zkp_abc123',
      entity_id: 'my-entity',
      claim_type: 'score_above',
      claim_threshold: 0.5,
      claim_domain: null,
      commitment_root: 'aabbcc'.padEnd(64, '0'),
      receipt_count: 3,
      salt: 'salt-hex',
      anchor_block: null,
      generated_at: new Date().toISOString(),
      expires_at: future,
      is_valid: true,
    };
    const entityData = { entity_id: 'my-entity', status: 'active' };
    const receipts = [
      makeReceipt({ id: 'r1', agent_behavior: 'completed', graph_weight: 1.0 }),
      makeReceipt({ id: 'r2', agent_behavior: 'completed', graph_weight: 1.0 }),
      makeReceipt({ id: 'r3', agent_behavior: 'completed', graph_weight: 1.0 }),
    ];

    const mockSupabase = makeVerifySupabase({ proofData, entityData, receipts });
    const result = await verifyZKProof('ep_zkp_abc123', mockSupabase);

    expect(result.valid).toBe(true);
    expect(result.entity_id).toBe('my-entity');
    expect(result.verified_at).toBeDefined();
  });

  it('returns valid=false for an expired proof', async () => {
    const past = new Date(Date.now() - 1000).toISOString(); // 1 second in the past
    const proofData = {
      proof_id: 'ep_zkp_expired',
      entity_id: 'my-entity',
      claim_type: 'score_above',
      claim_threshold: 0.5,
      claim_domain: null,
      commitment_root: 'aabbcc'.padEnd(64, '0'),
      receipt_count: 2,
      salt: 'salt-hex',
      anchor_block: null,
      generated_at: new Date(Date.now() - 31 * 24 * 60 * 60 * 1000).toISOString(),
      expires_at: past,
      is_valid: true,
    };

    const mockSupabase = makeVerifySupabase({ proofData });
    const result = await verifyZKProof('ep_zkp_expired', mockSupabase);

    expect(result.valid).toBe(false);
    expect(result.reason).toBe('proof_expired');
  });

  it('returns valid=false when proof is not found', async () => {
    const mockSupabase = makeVerifySupabase({ proofData: null, proofError: { message: 'not found' } });
    const result = await verifyZKProof('ep_zkp_nonexistent', mockSupabase);

    expect(result.valid).toBe(false);
    expect(result.reason).toBe('proof_not_found');
  });

  it('returns valid=false when entity is inactive', async () => {
    const future = new Date(Date.now() + 10 * 24 * 60 * 60 * 1000).toISOString();
    const proofData = {
      proof_id: 'ep_zkp_inactive',
      entity_id: 'suspended-entity',
      claim_type: 'score_above',
      claim_threshold: 0.5,
      claim_domain: null,
      commitment_root: 'aabbcc'.padEnd(64, '0'),
      receipt_count: 1,
      salt: 'salt-hex',
      anchor_block: null,
      generated_at: new Date().toISOString(),
      expires_at: future,
      is_valid: true,
    };
    const entityData = { entity_id: 'suspended-entity', status: 'suspended' };

    const mockSupabase = makeVerifySupabase({ proofData, entityData });
    const result = await verifyZKProof('ep_zkp_inactive', mockSupabase);

    expect(result.valid).toBe(false);
    expect(result.reason).toBe('entity_inactive_or_not_found');
  });

  it('returns valid=false when claim is no longer met at verification time', async () => {
    const future = new Date(Date.now() + 10 * 24 * 60 * 60 * 1000).toISOString();
    const proofData = {
      proof_id: 'ep_zkp_degraded',
      entity_id: 'degraded-entity',
      claim_type: 'score_above',
      claim_threshold: 0.99, // very high threshold
      claim_domain: null,
      commitment_root: 'aabbcc'.padEnd(64, '0'),
      receipt_count: 2,
      salt: 'salt-hex',
      anchor_block: null,
      generated_at: new Date().toISOString(),
      expires_at: future,
      is_valid: true,
    };
    const entityData = { entity_id: 'degraded-entity', status: 'active' };
    // Receipts now show poor behavior — claim no longer met
    const receipts = [
      makeReceipt({ id: 'r1', agent_behavior: 'abandoned', graph_weight: 1.0 }),
      makeReceipt({ id: 'r2', agent_behavior: 'disputed', graph_weight: 1.0 }),
    ];

    const mockSupabase = makeVerifySupabase({ proofData, entityData, receipts });
    const result = await verifyZKProof('ep_zkp_degraded', mockSupabase);

    expect(result.valid).toBe(false);
    expect(result.reason).toBe('claim_no_longer_met');
  });

  it('proof reveals threshold and count but not counterparty_ids', async () => {
    const future = new Date(Date.now() + 10 * 24 * 60 * 60 * 1000).toISOString();
    const proofData = {
      proof_id: 'ep_zkp_privacy',
      entity_id: 'privacy-entity',
      claim_type: 'score_above',
      claim_threshold: 0.6,
      claim_domain: null,
      commitment_root: 'aabbcc'.padEnd(64, '0'),
      receipt_count: 5,
      salt: 'salt-hex',
      anchor_block: null,
      generated_at: new Date().toISOString(),
      expires_at: future,
      is_valid: true,
    };
    const entityData = { entity_id: 'privacy-entity', status: 'active' };
    const receipts = [
      makeReceipt({ id: 'r1', agent_behavior: 'completed', counterparty_id: 'secret-cp-X' }),
      makeReceipt({ id: 'r2', agent_behavior: 'completed', counterparty_id: 'secret-cp-Y' }),
    ];

    const mockSupabase = makeVerifySupabase({ proofData, entityData, receipts });
    const result = await verifyZKProof('ep_zkp_privacy', mockSupabase);

    // Threshold and count are disclosed
    expect(result.claim.threshold).toBe(0.6);
    expect(result.receipt_count).toBe(5);

    // Counterparty identities must not appear in the verification result
    const resultStr = JSON.stringify(result);
    expect(resultStr).not.toContain('secret-cp-X');
    expect(resultStr).not.toContain('secret-cp-Y');
  });
});
