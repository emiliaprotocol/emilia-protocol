// SPDX-License-Identifier: Apache-2.0

import { describe, it, expect, vi, beforeEach } from 'vitest';
import { buildMerkleTree, MERKLE_V2_ALG } from '../lib/blockchain.js';

const state = vi.hoisted(() => ({
  receipt: null,
  batch: null,
  recomputedHash: null,
}));

vi.mock('@/lib/write-guard', () => ({
  getGuardedClient: () => ({
    from(table) {
      const chain = {
        select() { return chain; },
        eq() { return chain; },
        async single() {
          if (table === 'receipts') return { data: state.receipt, error: state.receipt ? null : { message: 'not found' } };
          if (table === 'anchor_batches') return { data: state.batch, error: state.batch ? null : { message: 'not found' } };
          return { data: null, error: null };
        },
      };
      return chain;
    },
  }),
}));

vi.mock('@/lib/scoring', () => ({
  computeReceiptHash: vi.fn(async () => state.recomputedHash),
}));

const { GET } = await import('../app/api/verify/[receiptId]/route.js');

function request() {
  return new Request('https://example.test/api/verify/ep_rcpt_test');
}

function params() {
  return { params: Promise.resolve({ receiptId: 'ep_rcpt_test' }) };
}

describe('/api/verify/[receiptId] Merkle strictness', () => {
  beforeEach(() => {
    state.recomputedHash = 'a'.repeat(64);
    state.receipt = {
      receipt_id: 'ep_rcpt_test',
      entity_id: 'entity-1',
      submitted_by: 'submitter-1',
      transaction_ref: 'tx-1',
      transaction_type: 'service',
      delivery_accuracy: 90,
      product_accuracy: null,
      price_integrity: null,
      return_processing: null,
      agent_satisfaction: null,
      agent_behavior: 'completed',
      composite_score: 90,
      evidence: {},
      receipt_hash: state.recomputedHash,
      previous_hash: null,
      anchor_batch_id: 'batch-1',
      merkle_proof: [],
      merkle_leaf_index: 0,
      created_at: '2026-06-28T00:00:00Z',
    };
  });

  it('accepts a v2 domain-separated batch proof', async () => {
    const tree = buildMerkleTree([state.recomputedHash], { v2: true });
    state.batch = {
      batch_id: 'batch-1',
      merkle_root: tree.root,
      merkle_alg: MERKLE_V2_ALG,
      transaction_hash: '0xabc',
      chain_id: 8453,
      block_number: 123,
      explorer_url: 'https://basescan.org/tx/0xabc',
      created_at: '2026-06-28T00:00:00Z',
    };

    const res = await GET(request(), params());
    expect(res.status).toBe(200);
    const body = await res.json();
    expect(body.anchor.proof_valid).toBe(true);
    expect(body.anchor.legacy_refused).toBe(false);
  });

  it('refuses legacy or missing merkle_alg even if a v1-style proof would fold', async () => {
    state.batch = {
      batch_id: 'batch-1',
      merkle_root: state.recomputedHash,
      merkle_alg: 'EP-MERKLE-v1',
      transaction_hash: '0xabc',
      chain_id: 8453,
      block_number: 123,
      explorer_url: 'https://basescan.org/tx/0xabc',
      created_at: '2026-06-28T00:00:00Z',
    };

    const res = await GET(request(), params());
    expect(res.status).toBe(200);
    const body = await res.json();
    expect(body.anchor.proof_valid).toBe(false);
    expect(body.anchor.legacy_refused).toBe(true);
  });
});
