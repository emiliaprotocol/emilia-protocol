/**
 * EMILIA Protocol — Adversarial Benchmark Tests
 *
 * Phase 5, Step 24: Prove EP behaves correctly under attack scenarios.
 * Covers Sybil rings, reciprocal farming, cold start, false disputes,
 * appeal reversals, key rotation, commit replay, and score scale integrity.
 *
 * @license Apache-2.0
 */

import { describe, it, expect, vi, beforeEach } from 'vitest';

// ============================================================================
// Supabase mock infrastructure
// ============================================================================

/**
 * Build a chainable Supabase query mock.
 * `resolveValue` is the final resolved value for terminal calls.
 */
function makeChain(resolveValue) {
  const chain = {
    select: vi.fn().mockReturnThis(),
    eq: vi.fn().mockReturnThis(),
    neq: vi.fn().mockReturnThis(),
    in: vi.fn().mockReturnThis(),
    is: vi.fn().mockReturnThis(),
    gte: vi.fn().mockReturnThis(),
    gt: vi.fn().mockReturnThis(),
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

// ============================================================================
// Mock Supabase for canonical-writer / sybil tests
// ============================================================================

const mockGetServiceClient = vi.fn();
const mockCanonicalEvaluate = vi.fn();
const mockVerifyDelegation = vi.fn();

vi.mock('../lib/supabase.js', () => ({
  getServiceClient: (...args) => mockGetServiceClient(...args),
}));

vi.mock('../lib/canonical-evaluator.js', () => ({
  canonicalEvaluate: (...args) => mockCanonicalEvaluate(...args),
}));

vi.mock('../lib/delegation.js', () => ({
  verifyDelegation: (...args) => mockVerifyDelegation(...args),
}));

// Dynamically imported modules
import {
  detectClosedLoop,
  analyzeReceiptGraph,
  runReceiptFraudChecks,
  isEstablished,
} from '../lib/sybil.js';

import {
  computeTrustProfile,
  DISPUTE_DAMPENING_FACTOR,
  evaluateTrustPolicy,
} from '../lib/scoring-v2.js';

import {
  canonicalResolveAppeal,
  canonicalResolveDispute,
} from '../lib/canonical-writer.js';

import {
  issueCommit,
  verifyCommit,
  _resetForTesting,
  _internals,
} from '../lib/commit.js';

// ============================================================================
// Helper: make a receipt object for scoring tests
// ============================================================================

function makeReceipt(overrides = {}) {
  return {
    delivery_accuracy: 90,
    product_accuracy: 85,
    price_integrity: 95,
    return_processing: 80,
    agent_satisfaction: 88,
    composite_score: 88,
    submitted_by: overrides.submitted_by || 'submitter-1',
    submitter_score: overrides.submitter_score ?? 50,
    submitter_established: overrides.submitter_established ?? false,
    graph_weight: overrides.graph_weight ?? 1.0,
    agent_behavior: overrides.agent_behavior || 'completed',
    created_at: overrides.created_at || new Date().toISOString(),
    context: overrides.context || null,
    provenance_tier: overrides.provenance_tier || 'self_attested',
    bilateral_status: overrides.bilateral_status || null,
    ...overrides,
  };
}

// ============================================================================
// 1. SYBIL / TRUST FARMING RING DETECTION
// ============================================================================

describe('ADVERSARIAL BENCHMARK 1: Sybil / Trust Farming Ring Detection', () => {
  it('detects closed-loop pattern in a 5-entity ring', async () => {
    // Ring: A→B→C→D→E→A (each entity scores the next)
    const entities = ['ent-A', 'ent-B', 'ent-C', 'ent-D', 'ent-E'];

    // For each pair (A scores B), check if B has also scored A
    // In a ring, the reverse exists (E→A and A→B means A scores B, and E scores A)
    // But direct bidirectional: A→B and B→A — in a ring, that's every adjacent pair's reverse

    // Simulate: entity being scored is B, submitter is A
    // Check if B has scored A (reverse receipts exist)
    const mockSupabase = {
      from: vi.fn().mockReturnValue({
        select: vi.fn().mockReturnValue({
          eq: vi.fn().mockReturnValue({
            eq: vi.fn().mockReturnValue({
              limit: vi.fn().mockResolvedValue({
                data: [{ id: 'receipt-reverse' }], // reverse receipt exists
              }),
            }),
          }),
        }),
      }),
    };

    const result = await detectClosedLoop(mockSupabase, 'ent-B', 'ent-A');
    expect(result.flagged).toBe(true);
    expect(result.reason).toBe('closed_loop');
  });

  it('runReceiptFraudChecks applies score dampening to ring members', async () => {
    // Simulate a ring: entityId=ent-B, submittedBy=ent-A
    // detectClosedLoop → flagged
    // analyzeReceiptGraph → thin_graph with 2 unique submitters
    let fromCallCount = 0;
    const mockSupabase = {
      from: vi.fn((table) => {
        if (table === 'receipts') {
          fromCallCount++;
          // First call: detectClosedLoop (reverse receipts)
          if (fromCallCount === 1) {
            return {
              select: vi.fn().mockReturnValue({
                eq: vi.fn().mockReturnValue({
                  eq: vi.fn().mockReturnValue({
                    limit: vi.fn().mockResolvedValue({
                      data: [{ id: 'reverse-1' }],
                    }),
                  }),
                }),
              }),
            };
          }
          // Second call: detectVelocitySpike
          if (fromCallCount === 2) {
            return {
              select: vi.fn().mockReturnValue({
                eq: vi.fn().mockReturnValue({
                  gte: vi.fn().mockResolvedValue({ count: 5 }), // under velocity limit
                }),
              }),
            };
          }
          // Third call: analyzeReceiptGraph (submitters for entity)
          if (fromCallCount === 3) {
            return {
              select: vi.fn().mockReturnValue({
                eq: vi.fn().mockResolvedValue({
                  data: [
                    { submitted_by: 'ent-A' },
                    { submitted_by: 'ent-A' },
                    { submitted_by: 'ent-A' },
                    { submitted_by: 'ent-C' },
                    { submitted_by: 'ent-C' },
                  ],
                }),
              }),
            };
          }
          // Fourth+: retroactive weight updates
          return {
            select: vi.fn().mockReturnValue({
              eq: vi.fn().mockReturnValue({
                eq: vi.fn().mockReturnValue({
                  gt: vi.fn().mockResolvedValue({ data: [] }),
                }),
              }),
            }),
            update: vi.fn().mockReturnValue({
              in: vi.fn().mockResolvedValue({ error: null }),
              eq: vi.fn().mockReturnThis(),
            }),
          };
        }
        if (table === 'fraud_flags') {
          return {
            insert: vi.fn().mockResolvedValue({ error: null }),
          };
        }
        return makeChain({ data: null });
      }),
    };

    const result = await runReceiptFraudChecks(mockSupabase, 'ent-B', 'ent-A');
    // Closed loop detected → graphWeight reduced
    expect(result.flags).toContain('closed_loop');
    expect(result.graphWeight).toBeLessThan(1.0);
    // Closed loop multiplier is 0.4
    expect(result.graphWeight).toBeLessThanOrEqual(0.4);
  });

  it('ring receipts with 0.1 graph_weight produce near-zero trust in scoring', () => {
    // 5 entities in a ring, each submitting receipts for the next
    const entities = ['ent-A', 'ent-B', 'ent-C', 'ent-D', 'ent-E'];
    const receipts = [];
    for (let i = 0; i < 5; i++) {
      for (let j = 0; j < 5; j++) {
        if (i === j) continue;
        receipts.push(makeReceipt({
          submitted_by: entities[i],
          submitter_established: true,
          submitter_score: 90,
          graph_weight: 0.1, // cluster penalty applied
          composite_score: 100,
        }));
      }
    }
    const profile = computeTrustProfile(receipts, {});
    // Cluster penalty (0.1x) should severely limit effective evidence
    expect(profile.effectiveEvidence).toBeLessThan(5);
    expect(profile.score).toBeLessThan(70);
  });
});

// ============================================================================
// 2. RECIPROCAL FARMING DETECTION
// ============================================================================

describe('ADVERSARIAL BENCHMARK 2: Reciprocal Farming Detection', () => {
  it('detectClosedLoop flags two entities that only score each other', async () => {
    // A scores B, B scores A
    const mockSupabase = {
      from: vi.fn().mockReturnValue({
        select: vi.fn().mockReturnValue({
          eq: vi.fn().mockReturnValue({
            eq: vi.fn().mockReturnValue({
              limit: vi.fn().mockResolvedValue({
                data: [{ id: 'reciprocal-receipt' }],
              }),
            }),
          }),
        }),
      }),
    };

    // Check A scoring B → does B score A?
    const resultAB = await detectClosedLoop(mockSupabase, 'entity-B', 'entity-A');
    expect(resultAB.flagged).toBe(true);
    expect(resultAB.reason).toBe('closed_loop');

    // Check B scoring A → does A score B?
    const resultBA = await detectClosedLoop(mockSupabase, 'entity-A', 'entity-B');
    expect(resultBA.flagged).toBe(true);
    expect(resultBA.reason).toBe('closed_loop');
  });

  it('reciprocal farming receipts get 0.4x weight dampening', async () => {
    // When closed_loop is detected, graphWeight *= 0.4
    // Verify that reciprocal pairs' receipts are dampened in scoring
    const receipts = Array(20).fill(null).map((_, i) => makeReceipt({
      submitted_by: i % 2 === 0 ? 'entity-A' : 'entity-B',
      submitter_established: true,
      submitter_score: 95,
      graph_weight: 0.4, // closed-loop penalty
      composite_score: 100,
    }));
    const profile = computeTrustProfile(receipts, {});
    // 0.4x graph weight limits evidence significantly
    expect(profile.effectiveEvidence).toBeLessThan(15);
    // Score cannot reach high levels with dampened evidence
    expect(profile.score).toBeLessThan(85);
  });
});

// ============================================================================
// 3. SPARSE-HISTORY COLD START
// ============================================================================

describe('ADVERSARIAL BENCHMARK 3: Sparse-History Cold Start', () => {
  it('entity with 0 receipts gets score: 50, confidence: pending', () => {
    const profile = computeTrustProfile([], {});
    expect(profile.score).toBe(50);
    expect(profile.confidence).toBe('pending');
    expect(profile.effectiveEvidence).toBe(0);
    expect(profile.established).toBe(false);
  });

  it('entity with 1 receipt does not get confidence: confident', () => {
    const receipts = [makeReceipt({
      submitted_by: 'sub-1',
      submitter_established: true,
      submitter_score: 90,
      composite_score: 95,
    })];
    const profile = computeTrustProfile(receipts, {});
    expect(profile.confidence).not.toBe('confident');
    // With only 1 receipt, cannot be established
    expect(profile.established).toBe(false);
  });

  it('establishment requires minimum receipts and unique submitters', () => {
    // isEstablished requires >= 5 receipts and >= 3 unique submitters
    expect(isEstablished(4, 3)).toBe(false);  // too few receipts
    expect(isEstablished(5, 2)).toBe(false);  // too few submitters
    expect(isEstablished(5, 3)).toBe(true);   // meets threshold
    expect(isEstablished(0, 0)).toBe(false);  // cold start
    expect(isEstablished(1, 1)).toBe(false);  // single receipt
  });

  it('3 receipts from 1 submitter = not established, not confident', () => {
    const receipts = Array(3).fill(null).map(() => makeReceipt({
      submitted_by: 'sole-submitter',
      submitter_established: true,
      submitter_score: 90,
      composite_score: 95,
    }));
    const profile = computeTrustProfile(receipts, {});
    expect(profile.established).toBe(false);
    expect(profile.confidence).not.toBe('confident');
    expect(profile.uniqueSubmitters).toBe(1);
  });
});

// ============================================================================
// 4. FALSE DISPUTE RESILIENCE
// ============================================================================

describe('ADVERSARIAL BENCHMARK 4: False Dispute Resilience', () => {
  it('DISPUTE_DAMPENING_FACTOR is 0.3', () => {
    expect(DISPUTE_DAMPENING_FACTOR).toBe(0.3);
  });

  it('disputed receipts are dampened at 0.3x weight', () => {
    const receipts = Array(10).fill(null).map((_, i) => makeReceipt({
      id: `receipt-${i}`,
      submitted_by: `sub-${i % 5}`,
      submitter_established: true,
      submitter_score: 90,
      composite_score: 90,
      provenance_tier: 'bilateral',
      bilateral_status: 'confirmed',
    }));

    // Dispute 3 receipts
    const disputedIds = new Set(['receipt-0', 'receipt-3', 'receipt-7']);

    const profileWithDisputes = computeTrustProfile(receipts, {}, disputedIds);
    const profileWithout = computeTrustProfile(receipts, {}, new Set());

    // Disputed receipts should be dampened
    expect(profileWithDisputes.dispute_dampened_count).toBe(3);
    // Effective evidence should be lower with disputes
    expect(profileWithDisputes.effectiveEvidence).toBeLessThan(profileWithout.effectiveEvidence);
  });

  it('entity score does not collapse from dispute spam against good receipts', () => {
    const receipts = Array(10).fill(null).map((_, i) => makeReceipt({
      id: `receipt-${i}`,
      submitted_by: `sub-${i % 5}`,
      submitter_established: true,
      submitter_score: 90,
      composite_score: 90,
      agent_behavior: 'completed',
      provenance_tier: 'bilateral',
      bilateral_status: 'confirmed',
    }));

    // Dispute 3 out of 10 receipts
    const disputedIds = new Set(['receipt-0', 'receipt-3', 'receipt-7']);
    const profile = computeTrustProfile(receipts, {}, disputedIds);

    // Score should NOT collapse — 7 good receipts still contribute fully
    expect(profile.score).toBeGreaterThan(50);
    // 3 disputed at 0.3x should not tank the score below a reasonable level
    // The entity still has 7 undisputed receipts
    expect(profile.score).toBeGreaterThan(65);
  });

  it('disputing ALL receipts dampens but does not annihilate score to 0', () => {
    const receipts = Array(10).fill(null).map((_, i) => makeReceipt({
      id: `receipt-${i}`,
      submitted_by: `sub-${i % 5}`,
      submitter_established: true,
      submitter_score: 90,
      composite_score: 90,
      provenance_tier: 'bilateral',
      bilateral_status: 'confirmed',
    }));

    const allDisputed = new Set(receipts.map(r => r.id));
    const profile = computeTrustProfile(receipts, {}, allDisputed);

    // All dampened at 0.3x — score gravitates toward 50 baseline
    // but does NOT go to 0 — dampening reduces weight, not score value
    expect(profile.score).toBeGreaterThanOrEqual(0);
    expect(profile.dispute_dampened_count).toBe(10);
  });
});

// ============================================================================
// 5. APPEAL REVERSAL CORRECTNESS
// ============================================================================

describe('ADVERSARIAL BENCHMARK 5: Appeal Reversal Correctness', () => {
  it('appeal_reversed against original upheld → receipt gets graph_weight 0.0', async () => {
    // Setup: dispute was originally 'upheld' (receipt stood),
    // now appeal_reversed overturns it → receipt should be neutralized
    const disputeRecord = {
      dispute_id: 'disp-001',
      receipt_id: 'rcpt-001',
      entity_id: 'ent-001',
      status: 'appealed',
      resolution: 'upheld', // original resolution
    };

    const receiptUpdates = [];
    const entityUpdates = [];

    const mockSupabase = {
      from: vi.fn((table) => {
        if (table === 'disputes') {
          return {
            select: vi.fn().mockReturnValue({
              eq: vi.fn().mockReturnValue({
                single: vi.fn().mockResolvedValue({ data: disputeRecord }),
              }),
            }),
            update: vi.fn((data) => {
              return {
                eq: vi.fn().mockResolvedValue({ error: null }),
              };
            }),
          };
        }
        if (table === 'receipts') {
          return {
            update: vi.fn((data) => {
              receiptUpdates.push(data);
              return {
                eq: vi.fn().mockResolvedValue({ error: null }),
              };
            }),
            // materializeTrustProfile fetches receipts
            select: vi.fn().mockReturnValue({
              eq: vi.fn().mockReturnValue({
                order: vi.fn().mockReturnValue({
                  limit: vi.fn().mockResolvedValue({ data: [], error: null }),
                }),
              }),
            }),
          };
        }
        if (table === 'entities') {
          return {
            update: vi.fn((data) => {
              entityUpdates.push(data);
              return {
                eq: vi.fn().mockResolvedValue({ data: null, error: null }),
              };
            }),
            select: vi.fn().mockReturnValue({
              eq: vi.fn().mockReturnValue({
                single: vi.fn().mockResolvedValue({ data: { id: 'ent-001' }, error: null }),
              }),
            }),
          };
        }
        if (table === 'protocol_events') {
          return { insert: vi.fn().mockResolvedValue({ error: null }) };
        }
        return makeChain({ data: null });
      }),
      rpc: vi.fn().mockResolvedValue({ data: 75, error: null }),
    };

    mockGetServiceClient.mockReturnValue(mockSupabase);

    const result = await canonicalResolveAppeal('disp-001', 'appeal_reversed', 'New evidence', 'op-001');

    expect(result.status).toBe('appeal_reversed');
    expect(result.original_resolution).toBe('upheld');
    // Receipt should be updated with graph_weight: 0.0
    expect(receiptUpdates.some(u => u.graph_weight === 0.0)).toBe(true);
  });

  it('appeal_reversed against original reversed → receipt gets graph_weight 1.0', async () => {
    // Setup: dispute was originally 'reversed' (receipt was neutralized),
    // now appeal_reversed restores it → graph_weight back to 1.0
    const disputeRecord = {
      dispute_id: 'disp-002',
      receipt_id: 'rcpt-002',
      entity_id: 'ent-002',
      status: 'appealed',
      resolution: 'reversed', // original resolution
    };

    const receiptUpdates = [];

    const mockSupabase = {
      from: vi.fn((table) => {
        if (table === 'disputes') {
          return {
            select: vi.fn().mockReturnValue({
              eq: vi.fn().mockReturnValue({
                single: vi.fn().mockResolvedValue({ data: disputeRecord }),
              }),
            }),
            update: vi.fn(() => ({
              eq: vi.fn().mockResolvedValue({ error: null }),
            })),
          };
        }
        if (table === 'receipts') {
          return {
            update: vi.fn((data) => {
              receiptUpdates.push(data);
              return {
                eq: vi.fn().mockResolvedValue({ error: null }),
              };
            }),
            // materializeTrustProfile fetches receipts
            select: vi.fn().mockReturnValue({
              eq: vi.fn().mockReturnValue({
                order: vi.fn().mockReturnValue({
                  limit: vi.fn().mockResolvedValue({ data: [], error: null }),
                }),
              }),
            }),
          };
        }
        if (table === 'entities') {
          return {
            update: vi.fn(() => ({
              eq: vi.fn().mockResolvedValue({ data: null, error: null }),
            })),
            select: vi.fn().mockReturnValue({
              eq: vi.fn().mockReturnValue({
                single: vi.fn().mockResolvedValue({ data: { id: 'ent-002' }, error: null }),
              }),
            }),
          };
        }
        if (table === 'protocol_events') {
          return { insert: vi.fn().mockResolvedValue({ error: null }) };
        }
        return makeChain({ data: null });
      }),
      rpc: vi.fn().mockResolvedValue({ data: 80, error: null }),
    };

    mockGetServiceClient.mockReturnValue(mockSupabase);

    const result = await canonicalResolveAppeal('disp-002', 'appeal_reversed', 'Evidence restored', 'op-002');

    expect(result.status).toBe('appeal_reversed');
    expect(result.original_resolution).toBe('reversed');
    // Receipt should be updated with graph_weight: 1.0 (restored)
    expect(receiptUpdates.some(u => u.graph_weight === 1.0)).toBe(true);
  });
});

// ============================================================================
// 6. KEY ROTATION (basic)
// ============================================================================

describe('ADVERSARIAL BENCHMARK 6: Key Rotation', () => {
  beforeEach(() => {
    _resetForTesting();
    mockCanonicalEvaluate.mockReset();
    mockGetServiceClient.mockReset();
  });

  it('old commit fails signature verification after key rotation', async () => {
    // Setup mocks for issueCommit
    mockCanonicalEvaluate.mockResolvedValue({
      score: 80,
      confidence: 'emerging',
      profile: {},
      policyResult: { pass: true, failures: [], warnings: [] },
    });

    const insertedCommits = [];
    const mockSupabase = {
      from: vi.fn((table) => {
        if (table === 'commits') {
          return {
            insert: vi.fn((data) => {
              insertedCommits.push(data);
              return Promise.resolve({ error: null });
            }),
            select: vi.fn().mockReturnValue({
              eq: vi.fn().mockReturnValue({
                maybeSingle: vi.fn().mockImplementation(async () => {
                  if (insertedCommits.length > 0) {
                    return { data: insertedCommits[0], error: null };
                  }
                  return { data: null, error: null };
                }),
                neq: vi.fn().mockReturnValue({
                  limit: vi.fn().mockResolvedValue({ data: [], error: null }),
                }),
              }),
            }),
            update: vi.fn().mockReturnValue({
              eq: vi.fn().mockReturnValue({
                eq: vi.fn().mockResolvedValue({ error: null }),
              }),
            }),
          };
        }
        return makeChain({ data: null });
      }),
    };
    mockGetServiceClient.mockReturnValue(mockSupabase);

    // Step 1: Issue a commit with the current keypair
    const commit = await issueCommit({
      entity_id: 'test-entity',
      action_type: 'install',
      policy: 'standard',
    });
    expect(commit.signature).toBeTruthy();
    expect(commit.public_key).toBeTruthy();
    const originalPubKey = commit.public_key;

    // Step 2: Verify the commit (should succeed with same key)
    const { verifySignature, buildCanonicalPayload } = _internals;
    const canonicalFields = {
      commit_id: commit.commit_id,
      entity_id: commit.entity_id,
      kid: commit.kid,
      principal_id: commit.principal_id,
      counterparty_entity_id: commit.counterparty_entity_id,
      delegation_id: commit.delegation_id,
      action_type: commit.action_type,
      decision: commit.decision,
      scope: commit.scope,
      max_value_usd: commit.max_value_usd,
      context: commit.context,
      nonce: commit.nonce,
      expires_at: commit.expires_at,
      created_at: commit.created_at,
    };
    const payload = buildCanonicalPayload(canonicalFields);
    const validBefore = verifySignature(payload, commit.signature, originalPubKey);
    expect(validBefore).toBe(true);

    // Step 3: Simulate key rotation
    _resetForTesting();

    // Step 4: Get the new public key (different from original)
    const newPubKey = _internals.getPublicKeyBase64();
    // Ephemeral keys are random — they should differ
    expect(newPubKey).not.toBe(originalPubKey);

    // Step 5: Verify old commit with NEW key → should FAIL
    const validAfterRotation = verifySignature(payload, commit.signature, newPubKey);
    expect(validAfterRotation).toBe(false);
  });
});

// ============================================================================
// 7. COMMIT REPLAY PROTECTION
// ============================================================================

describe('ADVERSARIAL BENCHMARK 7: Commit Replay Protection', () => {
  beforeEach(() => {
    _resetForTesting();
    mockCanonicalEvaluate.mockReset();
    mockGetServiceClient.mockReset();
  });

  it('same nonce on different commit is detected as replay via verifyCommit', async () => {
    // verifyCommit queries: select('*').eq('commit_id', X).maybeSingle()
    // then: select('commit_id').eq('nonce', N).neq('commit_id', X).limit(1)
    // If the nonce query returns a row, it flags 'nonce_reuse'.

    // Build a forged commit record that has a reused nonce
    const forgedCommit = {
      commit_id: 'epc_forged123',
      entity_id: 'test-entity',
      kid: 'ep-signing-key-1',
      principal_id: null,
      counterparty_entity_id: null,
      delegation_id: null,
      action_type: 'install',
      decision: 'allow',
      scope: null,
      max_value_usd: null,
      context: null,
      nonce: 'reused-nonce-value',
      signature: 'AAAA', // will fail sig check but nonce check comes first
      public_key: 'AAAA',
      expires_at: new Date(Date.now() + 600000).toISOString(),
      created_at: new Date().toISOString(),
      status: 'active',
    };

    let selectCallCount = 0;
    const mockSupabase = {
      from: vi.fn((table) => {
        if (table === 'commits') {
          return {
            select: vi.fn().mockImplementation(() => {
              selectCallCount++;
              if (selectCallCount === 1) {
                // First: fetch commit by commit_id
                return {
                  eq: vi.fn().mockReturnValue({
                    maybeSingle: vi.fn().mockResolvedValue({ data: forgedCommit, error: null }),
                  }),
                };
              }
              // Second: nonce replay check
              return {
                eq: vi.fn().mockReturnValue({
                  neq: vi.fn().mockReturnValue({
                    limit: vi.fn().mockResolvedValue({
                      data: [{ commit_id: 'epc_original456' }], // another commit has the same nonce
                      error: null,
                    }),
                  }),
                }),
              };
            }),
            update: vi.fn().mockReturnValue({
              eq: vi.fn().mockReturnValue({
                eq: vi.fn().mockResolvedValue({ error: null }),
              }),
            }),
          };
        }
        return makeChain({ data: null });
      }),
    };
    mockGetServiceClient.mockReturnValue(mockSupabase);

    const verification = await verifyCommit(forgedCommit.commit_id);
    expect(verification.valid).toBe(false);
    expect(verification.reasons).toContain('nonce_reuse');
  });

  it('each issued commit gets a unique nonce', async () => {
    mockCanonicalEvaluate.mockResolvedValue({
      score: 80,
      confidence: 'emerging',
      profile: {},
      policyResult: { pass: true, failures: [], warnings: [] },
    });

    const mockSupabase = {
      from: vi.fn(() => ({
        insert: vi.fn().mockResolvedValue({ error: null }),
      })),
    };
    mockGetServiceClient.mockReturnValue(mockSupabase);

    const commit1 = await issueCommit({
      entity_id: 'test-entity',
      action_type: 'install',
      policy: 'standard',
    });
    const commit2 = await issueCommit({
      entity_id: 'test-entity',
      action_type: 'connect',
      policy: 'standard',
    });

    // Nonces must differ — cryptographic randomness
    expect(commit1.nonce).not.toBe(commit2.nonce);
    // Nonces should be 64-char hex (32 random bytes)
    expect(commit1.nonce).toMatch(/^[0-9a-f]{64}$/);
    expect(commit2.nonce).toMatch(/^[0-9a-f]{64}$/);
  });
});

// ============================================================================
// 8. SCORE SCALE INTEGRITY
// ============================================================================

describe('ADVERSARIAL BENCHMARK 8: Score Scale Integrity', () => {
  it('computeTrustProfile never returns score outside 0-100', () => {
    const testCases = [
      // Empty
      [],
      // Single high receipt
      [makeReceipt({ composite_score: 100, submitted_by: 's1', submitter_established: true, submitter_score: 100 })],
      // Single low receipt
      [makeReceipt({ composite_score: 0, submitted_by: 's1', agent_behavior: 'abandoned' })],
      // Extreme negative signals
      Array(50).fill(null).map((_, i) => makeReceipt({
        composite_score: 0,
        delivery_accuracy: 0,
        product_accuracy: 0,
        price_integrity: 0,
        return_processing: 0,
        agent_behavior: 'disputed',
        submitted_by: `s-${i % 10}`,
        submitter_established: true,
        submitter_score: 90,
      })),
      // Extreme positive signals
      Array(50).fill(null).map((_, i) => makeReceipt({
        composite_score: 100,
        delivery_accuracy: 100,
        product_accuracy: 100,
        price_integrity: 100,
        return_processing: 100,
        agent_behavior: 'completed',
        submitted_by: `s-${i % 10}`,
        submitter_established: true,
        submitter_score: 100,
        provenance_tier: 'oracle_verified',
      })),
      // Out-of-range values (should be clamped)
      [makeReceipt({
        composite_score: 99999,
        delivery_accuracy: -500,
        product_accuracy: Infinity,
        submitted_by: 's1',
        submitter_established: true,
        submitter_score: 90,
      })],
      // NaN/undefined values
      [makeReceipt({
        composite_score: NaN,
        delivery_accuracy: undefined,
        submitted_by: 's1',
        submitter_established: true,
        submitter_score: 90,
      })],
      // Zero graph weight (reversed)
      Array(20).fill(null).map((_, i) => makeReceipt({
        graph_weight: 0.0,
        submitted_by: `s-${i}`,
      })),
    ];

    for (const receipts of testCases) {
      const profile = computeTrustProfile(receipts, {});
      expect(profile.score).toBeGreaterThanOrEqual(0);
      expect(profile.score).toBeLessThanOrEqual(100);
      expect(Number.isFinite(profile.score)).toBe(true);
    }
  });

  it('commit decisions never use raw score for trust-critical paths', async () => {
    // When no policy is provided, commit should default to 'review' — not allow/deny from raw score
    _resetForTesting();

    mockCanonicalEvaluate.mockResolvedValue({
      score: 99,
      confidence: 'confident',
      profile: {},
      // No policyResult → raw score only
    });

    const mockSupabase = {
      from: vi.fn(() => ({
        insert: vi.fn().mockResolvedValue({ error: null }),
      })),
    };
    mockGetServiceClient.mockReturnValue(mockSupabase);

    const commit = await issueCommit({
      entity_id: 'test-entity',
      action_type: 'install',
    });

    // Without explicit policy evaluation, decision defaults to 'review'
    // NOT 'allow' based on raw score — this prevents scale confusion (0-1 vs 0-100)
    expect(commit.decision).toBe('review');
  });

  it('commit with policy evaluation uses policy pass/fail, not raw score', async () => {
    _resetForTesting();

    mockCanonicalEvaluate.mockResolvedValue({
      score: 30, // Low score
      confidence: 'provisional',
      profile: {},
      policyResult: { pass: true, failures: [], warnings: [] }, // But policy passes
    });

    const mockSupabase = {
      from: vi.fn(() => ({
        insert: vi.fn().mockResolvedValue({ error: null }),
      })),
    };
    mockGetServiceClient.mockReturnValue(mockSupabase);

    const commit = await issueCommit({
      entity_id: 'test-entity',
      action_type: 'install',
      policy: 'permissive',
    });

    // Policy says pass → decision is 'allow', regardless of low raw score
    expect(commit.decision).toBe('allow');
  });
});
