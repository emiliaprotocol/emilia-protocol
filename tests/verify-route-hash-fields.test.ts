// SPDX-License-Identifier: Apache-2.0
//
// Regression: the public verify route must recompute the receipt integrity hash
// over the SAME field set that create-receipt.js binds via computeReceiptHash.
// Previously the route's .select() and its computeReceiptHash() call omitted
// context / agent_behavior / claims / submitter_score / submitter_established,
// so authentic receipts carrying those fields recomputed to a different hash and
// falsely reported hash_valid:false. This test uses the REAL computeReceiptHash
// (no mock) so it fails if the route ever diverges from the create-time binding.

import { describe, it, expect, vi, beforeEach } from 'vitest';
import { computeReceiptHash } from '../lib/scoring.js';

const state = vi.hoisted(() => ({ receipt: null }));

// Mock only the DB client. Scoring is intentionally NOT mocked — the point of
// this test is to exercise the real hashing on both the create and verify sides.
vi.mock('@/lib/write-guard', () => ({
  getGuardedClient: () => ({
    from(table) {
      const chain = {
        select() { return chain; },
        eq() { return chain; },
        async single() {
          if (table === 'receipts') {
            return { data: state.receipt, error: state.receipt ? null : { message: 'not found' } };
          }
          return { data: null, error: null };
        },
      };
      return chain;
    },
  }),
}));

const { GET } = await import('../app/api/verify/[receiptId]/route.js');

function request() {
  return new Request('https://example.test/api/verify/ep_rcpt_test');
}
function params() {
  return { params: Promise.resolve({ receiptId: 'ep_rcpt_test' }) };
}

describe('/api/verify/[receiptId] hash field coverage', () => {
  beforeEach(() => {
    state.receipt = null;
  });

  it('recomputes hash_valid:true for a receipt carrying context + claims + agent_behavior', async () => {
    // Build the exact field set create-receipt.js binds (create-receipt.js
    // receiptData block), including the v2 fields the buggy route dropped.
    const previousHash = null;
    const receiptData = {
      entity_id: 'entity-1',
      submitted_by: 'submitter-1',
      transaction_ref: 'tx-1',
      transaction_type: 'service',
      context: { task_type: 'delivery', geo: 'US', risk_class: 'high' },
      delivery_accuracy: 90,
      product_accuracy: null,
      price_integrity: null,
      return_processing: null,
      agent_satisfaction: null,
      agent_behavior: 'completed',
      claims: { delivered: true, on_time: true, as_described: true },
      evidence: { source: 'unit-test' },
      submitter_score: 73,
      submitter_established: true,
    };

    // The hash the DB would hold, computed at create time.
    const storedHash = await computeReceiptHash(receiptData, previousHash);

    // What the verify route reads back from the DB (superset of receiptData).
    state.receipt = {
      receipt_id: 'ep_rcpt_test',
      ...receiptData,
      composite_score: 90,
      receipt_hash: storedHash,
      previous_hash: previousHash,
      anchor_batch_id: null,
      merkle_proof: null,
      merkle_leaf_index: null,
      created_at: '2026-06-28T00:00:00Z',
    };

    const res = await GET(request(), params());
    expect(res.status).toBe(200);
    const body = await res.json();

    expect(body.recomputed_hash).toBe(storedHash);
    expect(body.hash_valid).toBe(true);
    expect(body.chain.chain_intact).toBe(true);
    expect(body).not.toHaveProperty('revoked');
    expect(body.revocation).toEqual({
      status: 'unavailable',
      checked: false,
      basis: 'no authenticated current-status authority is configured for this receipt',
    });
  });

  it('reports hash_valid:false when a bound field (claims) is tampered after signing', async () => {
    const previousHash = null;
    const receiptData = {
      entity_id: 'entity-2',
      submitted_by: 'submitter-2',
      transaction_ref: 'tx-2',
      transaction_type: 'service',
      context: { task_type: 'delivery' },
      delivery_accuracy: 90,
      product_accuracy: null,
      price_integrity: null,
      return_processing: null,
      agent_satisfaction: null,
      agent_behavior: 'completed',
      claims: { delivered: true },
      evidence: {},
      submitter_score: 50,
      submitter_established: false,
    };
    const storedHash = await computeReceiptHash(receiptData, previousHash);

    // Tamper a hash-bound field AFTER the stored hash was computed. Because the
    // route now binds `claims`, the recomputed hash must diverge -> fail closed.
    state.receipt = {
      receipt_id: 'ep_rcpt_test',
      ...receiptData,
      claims: { delivered: false },
      composite_score: 90,
      receipt_hash: storedHash,
      previous_hash: previousHash,
      anchor_batch_id: null,
      merkle_proof: null,
      merkle_leaf_index: null,
      created_at: '2026-06-28T00:00:00Z',
    };

    const res = await GET(request(), params());
    expect(res.status).toBe(200);
    const body = await res.json();
    expect(body.hash_valid).toBe(false);
    expect(body.chain.chain_intact).toBe(false);
  });
});
