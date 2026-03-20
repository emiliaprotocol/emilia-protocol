/**
 * Tests for POST /api/receipts/auto-submit route
 *
 * Covers:
 *  1.  Auth required: rejects requests without Bearer token or valid x-ep-auto-key
 *  2.  Auth works: accepts requests with valid Bearer token
 *  3.  Auth works: accepts requests with valid machine secret (x-ep-auto-key)
 *  4.  Invalid entity claim rejected
 *  5.  Schema-complete receipt creation (all required fields present)
 *  6.  Deduplication via idempotency keys
 *  7.  Batch limit enforcement (max 100)
 *  8.  Empty batch rejection
 *  9.  Invalid receipt shape rejection
 * 10.  Partial failure semantics (some accepted, some rejected)
 * 11.  Fully successful batch returns 201 — N/A, route returns 207 for any success
 * 12.  Mixed batch returns 207
 * 13.  All-rejected batch returns 422
 * 14.  DB error behavior (fails closed, not silent)
 * 15.  Idempotency key is returned in response
 * 16.  Duplicate idempotency key returns existing receipt_id
 */

import { describe, it, expect, vi, beforeEach } from 'vitest';

// ---------------------------------------------------------------------------
// Mocks — set up BEFORE importing the route
// ---------------------------------------------------------------------------

/** Controls what authenticateRequest returns */
let _mockAuthResult = { entity: null, error: 'unauthorized' };

vi.mock('@/lib/supabase', () => ({
  authenticateRequest: vi.fn(async () => _mockAuthResult),
  getServiceClient: vi.fn(() => ({})),
}));

/** Controls what canonicalSubmitAutoReceipt returns per call */
let _canonicalResults = [];
let _canonicalCallIndex = 0;

vi.mock('@/lib/canonical-writer', () => ({
  canonicalSubmitAutoReceipt: vi.fn(async (receipt, submitter) => {
    const result = _canonicalResults[_canonicalCallIndex] ?? { error: 'no mock configured' };
    _canonicalCallIndex++;
    return result;
  }),
}));

/** Controls what getAutoSubmitSecret returns */
let _mockSecret = 'test-machine-secret-abc123';

vi.mock('@/lib/env', () => ({
  getAutoSubmitSecret: vi.fn(() => _mockSecret),
}));

// Import after mocks
import { POST } from '@/app/api/receipts/auto-submit/route';

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

const VALID_ENTITY = {
  id: 'entity-uuid-1',
  entity_id: 'acme-corp',
  status: 'active',
  emilia_score: 72,
};

function makeRequest({ headers = {}, body = null } = {}) {
  const hdrs = new Headers(headers);
  return new Request('http://localhost/api/receipts/auto-submit', {
    method: 'POST',
    headers: hdrs,
    body: body !== null ? JSON.stringify(body) : undefined,
  });
}

function validReceipt(overrides = {}) {
  return {
    entity_id: 'acme-corp',
    transaction_ref: 'txn_001',
    transaction_type: 'service',
    ...overrides,
  };
}

async function parseResponse(response) {
  return response.json();
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

describe('POST /api/receipts/auto-submit', () => {
  beforeEach(() => {
    _mockAuthResult = { entity: null, error: 'unauthorized' };
    _canonicalResults = [];
    _canonicalCallIndex = 0;
    _mockSecret = 'test-machine-secret-abc123';
  });

  // ── 1. Auth required ───────────────────────────────────────────────────
  describe('authentication', () => {
    it('rejects requests without Bearer token or x-ep-auto-key', async () => {
      const req = makeRequest({
        body: { receipts: [validReceipt()] },
      });
      const res = await POST(req);
      expect(res.status).toBe(401);
      const data = await parseResponse(res);
      expect(data.detail).toMatch(/[Aa]uthenticat/);
    });

    it('rejects invalid Bearer token', async () => {
      _mockAuthResult = { entity: null, error: 'Invalid API key' };
      const req = makeRequest({
        headers: { Authorization: 'Bearer ep_live_invalid' },
        body: { receipts: [validReceipt()] },
      });
      const res = await POST(req);
      expect(res.status).toBe(401);
    });

    it('rejects invalid x-ep-auto-key', async () => {
      const req = makeRequest({
        headers: { 'x-ep-auto-key': 'wrong-secret-value' },
        body: { receipts: [validReceipt()] },
      });
      const res = await POST(req);
      expect(res.status).toBe(401);
    });

    // ── 2. Auth works: Bearer token ──────────────────────────────────────
    it('accepts requests with valid Bearer token', async () => {
      _mockAuthResult = { entity: VALID_ENTITY, error: null };
      _canonicalResults = [{ receipt: { receipt_id: 'ep_rcpt_aaa' } }];

      const req = makeRequest({
        headers: { Authorization: 'Bearer ep_live_valid_key' },
        body: { receipts: [validReceipt()] },
      });
      const res = await POST(req);
      expect([201, 207]).toContain(res.status);
      const data = await parseResponse(res);
      expect(data.accepted).toBe(1);
    });

    // ── 3. Auth works: machine secret ────────────────────────────────────
    it('accepts requests with valid x-ep-auto-key matching EP_AUTO_SUBMIT_SECRET', async () => {
      _canonicalResults = [{ receipt: { receipt_id: 'ep_rcpt_bbb' } }];

      const req = makeRequest({
        headers: { 'x-ep-auto-key': 'test-machine-secret-abc123' },
        body: { receipts: [validReceipt()] },
      });
      const res = await POST(req);
      expect([201, 207]).toContain(res.status);
      const data = await parseResponse(res);
      expect(data.accepted).toBe(1);
    });

    it('rejects x-ep-auto-key when EP_AUTO_SUBMIT_SECRET is not configured', async () => {
      _mockSecret = null;
      const req = makeRequest({
        headers: { 'x-ep-auto-key': 'some-key' },
        body: { receipts: [validReceipt()] },
      });
      const res = await POST(req);
      expect(res.status).toBe(401);
      const data = await parseResponse(res);
      expect(data.detail).toMatch(/not configured/);
    });
  });

  // ── 4. Invalid entity claim rejected ───────────────────────────────────
  describe('entity validation', () => {
    it('rejects receipt with missing entity_id', async () => {
      _canonicalResults = [];
      const req = makeRequest({
        headers: { 'x-ep-auto-key': 'test-machine-secret-abc123' },
        body: { receipts: [{ transaction_ref: 'txn_001' }] },
      });
      const res = await POST(req);
      const data = await parseResponse(res);
      expect(data.rejected).toBe(1);
      expect(data.validation_errors[0].reason).toMatch(/entity_id/);
    });

    it('rejects receipt with entity_id exceeding 200 characters', async () => {
      const req = makeRequest({
        headers: { 'x-ep-auto-key': 'test-machine-secret-abc123' },
        body: { receipts: [validReceipt({ entity_id: 'x'.repeat(201) })] },
      });
      const res = await POST(req);
      const data = await parseResponse(res);
      expect(data.rejected).toBe(1);
      expect(data.validation_errors[0].reason).toMatch(/200 characters/);
    });
  });

  // ── 5. Schema-complete receipt creation ────────────────────────────────
  describe('schema-complete receipt creation', () => {
    it('passes all required fields through to canonical writer', async () => {
      _canonicalResults = [{ receipt: { receipt_id: 'ep_rcpt_full' } }];

      const { canonicalSubmitAutoReceipt } = await import('@/lib/canonical-writer');
      canonicalSubmitAutoReceipt.mockClear();
      _canonicalCallIndex = 0;

      const receipt = validReceipt({
        context: { tool: 'web_search', session: 'sess_1' },
        outcome: { completed: true },
      });

      const req = makeRequest({
        headers: { 'x-ep-auto-key': 'test-machine-secret-abc123' },
        body: { receipts: [receipt] },
      });
      const res = await POST(req);
      const data = await parseResponse(res);

      expect(data.accepted).toBe(1);
      expect(data.receipt_ids).toContain('ep_rcpt_full');

      // Verify the canonical writer was called with a sanitized receipt
      expect(canonicalSubmitAutoReceipt).toHaveBeenCalledTimes(1);
      const [passedReceipt, passedSubmitter] = canonicalSubmitAutoReceipt.mock.calls[0];
      expect(passedReceipt.entity_id).toBe('acme-corp');
      expect(passedReceipt.transaction_ref).toBe('txn_001');
      expect(passedReceipt.idempotency_key).toBeDefined();
      expect(passedSubmitter).toBeDefined();
    });
  });

  // ── 6. Deduplication via idempotency keys ──────────────────────────────
  describe('deduplication', () => {
    it('computes deterministic idempotency keys for identical receipts', async () => {
      _canonicalResults = [
        { receipt: { receipt_id: 'ep_rcpt_dedup1' } },
        { receipt: { receipt_id: 'ep_rcpt_dedup2' } },
      ];

      const { canonicalSubmitAutoReceipt } = await import('@/lib/canonical-writer');

      const receipt = validReceipt();
      const req = makeRequest({
        headers: { 'x-ep-auto-key': 'test-machine-secret-abc123' },
        body: { receipts: [receipt, { ...receipt }] },
      });
      const res = await POST(req);
      const data = await parseResponse(res);

      // Both calls should have the same idempotency key (same content)
      const call1 = canonicalSubmitAutoReceipt.mock.calls[0][0];
      const call2 = canonicalSubmitAutoReceipt.mock.calls[1][0];
      expect(call1.idempotency_key).toBe(call2.idempotency_key);
    });

    // ── 16. Duplicate idempotency key returns existing receipt_id ─────────
    it('returns existing receipt_id for deduplicated receipts', async () => {
      _canonicalResults = [
        { receipt: { receipt_id: 'ep_rcpt_orig' }, deduplicated: true },
      ];

      const req = makeRequest({
        headers: { 'x-ep-auto-key': 'test-machine-secret-abc123' },
        body: { receipts: [validReceipt()] },
      });
      const res = await POST(req);
      const data = await parseResponse(res);

      expect(data.accepted).toBe(1);
      expect(data.receipt_ids).toContain('ep_rcpt_orig');
      expect(data.receipts[0].deduplicated).toBe(true);
    });
  });

  // ── 7. Batch limit enforcement ─────────────────────────────────────────
  describe('batch limits', () => {
    it('rejects batches exceeding 100 receipts', async () => {
      const receipts = Array.from({ length: 101 }, (_, i) =>
        validReceipt({ transaction_ref: `txn_${i}` })
      );

      const req = makeRequest({
        headers: { 'x-ep-auto-key': 'test-machine-secret-abc123' },
        body: { receipts },
      });
      const res = await POST(req);
      expect(res.status).toBe(400);
      const data = await parseResponse(res);
      expect(data.detail).toMatch(/100/);
    });

    it('accepts batch of exactly 100 receipts', async () => {
      _canonicalResults = Array.from({ length: 100 }, (_, i) => ({
        receipt: { receipt_id: `ep_rcpt_${i}` },
      }));

      const receipts = Array.from({ length: 100 }, (_, i) =>
        validReceipt({ transaction_ref: `txn_${i}` })
      );

      const req = makeRequest({
        headers: { 'x-ep-auto-key': 'test-machine-secret-abc123' },
        body: { receipts },
      });
      const res = await POST(req);
      expect([201, 207]).toContain(res.status);
      const data = await parseResponse(res);
      expect(data.accepted).toBe(100);
    });
  });

  // ── 8. Empty batch rejection ───────────────────────────────────────────
  describe('empty batch', () => {
    it('rejects empty receipts array', async () => {
      const req = makeRequest({
        headers: { 'x-ep-auto-key': 'test-machine-secret-abc123' },
        body: { receipts: [] },
      });
      const res = await POST(req);
      expect(res.status).toBe(400);
      const data = await parseResponse(res);
      expect(data.detail).toMatch(/empty/i);
    });

    it('rejects body without receipts key', async () => {
      const req = makeRequest({
        headers: { 'x-ep-auto-key': 'test-machine-secret-abc123' },
        body: { data: [] },
      });
      const res = await POST(req);
      expect(res.status).toBe(400);
    });
  });

  // ── 9. Invalid receipt shape rejection ─────────────────────────────────
  describe('invalid receipt shapes', () => {
    it('rejects non-object receipt (string)', async () => {
      const req = makeRequest({
        headers: { 'x-ep-auto-key': 'test-machine-secret-abc123' },
        body: { receipts: ['not-an-object'] },
      });
      const res = await POST(req);
      const data = await parseResponse(res);
      expect(data.rejected).toBe(1);
      expect(data.validation_errors[0].reason).toMatch(/plain object/i);
    });

    it('rejects non-object receipt (array)', async () => {
      const req = makeRequest({
        headers: { 'x-ep-auto-key': 'test-machine-secret-abc123' },
        body: { receipts: [[1, 2, 3]] },
      });
      const res = await POST(req);
      const data = await parseResponse(res);
      expect(data.rejected).toBe(1);
      expect(data.validation_errors[0].reason).toMatch(/plain object/i);
    });

    it('rejects null receipt', async () => {
      const req = makeRequest({
        headers: { 'x-ep-auto-key': 'test-machine-secret-abc123' },
        body: { receipts: [null] },
      });
      const res = await POST(req);
      const data = await parseResponse(res);
      expect(data.rejected).toBe(1);
    });

    it('rejects receipt missing transaction_ref', async () => {
      const req = makeRequest({
        headers: { 'x-ep-auto-key': 'test-machine-secret-abc123' },
        body: { receipts: [{ entity_id: 'acme-corp' }] },
      });
      const res = await POST(req);
      const data = await parseResponse(res);
      expect(data.rejected).toBe(1);
      expect(data.validation_errors[0].reason).toMatch(/transaction_ref/);
    });

    it('rejects receipt with transaction_ref exceeding 500 characters', async () => {
      const req = makeRequest({
        headers: { 'x-ep-auto-key': 'test-machine-secret-abc123' },
        body: { receipts: [validReceipt({ transaction_ref: 'x'.repeat(501) })] },
      });
      const res = await POST(req);
      const data = await parseResponse(res);
      expect(data.rejected).toBe(1);
      expect(data.validation_errors[0].reason).toMatch(/500 characters/);
    });
  });

  // ── 10. Partial failure semantics ──────────────────────────────────────
  describe('partial failure semantics', () => {
    it('accepts valid receipts and rejects invalid ones in the same batch', async () => {
      _canonicalResults = [{ receipt: { receipt_id: 'ep_rcpt_partial' } }];

      const req = makeRequest({
        headers: { 'x-ep-auto-key': 'test-machine-secret-abc123' },
        body: {
          receipts: [
            validReceipt(),                        // valid — index 0
            { entity_id: 'acme-corp' },            // invalid, missing transaction_ref — index 1
            'not-an-object',                       // invalid shape — index 2
          ],
        },
      });
      const res = await POST(req);
      const data = await parseResponse(res);

      expect(data.accepted).toBe(1);
      expect(data.rejected).toBe(2);
      expect(data.receipt_ids).toContain('ep_rcpt_partial');
      expect(data.validation_errors).toHaveLength(2);
    });
  });

  // ── 11 & 12. Status codes ──────────────────────────────────────────────
  describe('response status codes', () => {
    it('returns 207 for fully successful batch (multi-status)', async () => {
      _canonicalResults = [
        { receipt: { receipt_id: 'ep_rcpt_s1' } },
        { receipt: { receipt_id: 'ep_rcpt_s2' } },
      ];

      const req = makeRequest({
        headers: { 'x-ep-auto-key': 'test-machine-secret-abc123' },
        body: { receipts: [validReceipt(), validReceipt({ transaction_ref: 'txn_002' })] },
      });
      const res = await POST(req);
      // Route uses 207 whenever accepted > 0
      expect(res.status).toBe(207);
      const data = await parseResponse(res);
      expect(data.accepted).toBe(2);
      expect(data.rejected).toBe(0);
    });

    it('returns 207 for mixed batch (some accepted, some rejected)', async () => {
      _canonicalResults = [
        { receipt: { receipt_id: 'ep_rcpt_mix1' } },
        { error: 'Self-score prevention triggered' },
      ];

      const req = makeRequest({
        headers: { 'x-ep-auto-key': 'test-machine-secret-abc123' },
        body: {
          receipts: [
            validReceipt(),
            validReceipt({ entity_id: 'self-entity', transaction_ref: 'txn_self' }),
          ],
        },
      });
      const res = await POST(req);
      expect(res.status).toBe(207);
      const data = await parseResponse(res);
      expect(data.accepted).toBe(1);
      expect(data.rejected).toBe(1);
    });

    // ── 13. All-rejected batch returns 422 ───────────────────────────────
    it('returns 422 when all receipts are rejected', async () => {
      _canonicalResults = [
        { error: 'Entity not found' },
        { error: 'Entity not found' },
      ];

      const req = makeRequest({
        headers: { 'x-ep-auto-key': 'test-machine-secret-abc123' },
        body: {
          receipts: [
            validReceipt(),
            validReceipt({ transaction_ref: 'txn_fail2' }),
          ],
        },
      });
      const res = await POST(req);
      expect(res.status).toBe(422);
      const data = await parseResponse(res);
      expect(data.accepted).toBe(0);
      expect(data.rejected).toBe(2);
    });

    it('returns 422 when all receipts fail input validation', async () => {
      const req = makeRequest({
        headers: { 'x-ep-auto-key': 'test-machine-secret-abc123' },
        body: { receipts: [null, 'bad', { entity_id: 'x' }] },
      });
      const res = await POST(req);
      expect(res.status).toBe(422);
    });
  });

  // ── 14. DB error behavior (fails closed) ───────────────────────────────
  describe('DB error behavior', () => {
    it('catches canonical writer exceptions and reports as errors, not silently', async () => {
      _canonicalResults = [];
      // Override mock to throw
      const { canonicalSubmitAutoReceipt } = await import('@/lib/canonical-writer');
      canonicalSubmitAutoReceipt.mockImplementationOnce(async () => {
        throw new Error('Database connection failed');
      });

      const req = makeRequest({
        headers: { 'x-ep-auto-key': 'test-machine-secret-abc123' },
        body: { receipts: [validReceipt()] },
      });
      const res = await POST(req);
      const data = await parseResponse(res);

      // Should not silently swallow — rejected count must reflect the error
      expect(data.rejected).toBe(1);
      expect(data.accepted).toBe(0);
      expect(data.db_errors).toBeDefined();
      expect(data.db_errors[0].reason).toMatch(/[Ii]nternal write error/);
    });

    it('does not return 200 when canonical writer throws', async () => {
      const { canonicalSubmitAutoReceipt } = await import('@/lib/canonical-writer');
      canonicalSubmitAutoReceipt.mockImplementationOnce(async () => {
        throw new Error('timeout');
      });

      const req = makeRequest({
        headers: { 'x-ep-auto-key': 'test-machine-secret-abc123' },
        body: { receipts: [validReceipt()] },
      });
      const res = await POST(req);
      // Must not be 200/201 — fails closed means error is visible
      expect(res.status).toBeGreaterThanOrEqual(400);
    });
  });

  // ── 15. Idempotency key is returned in response ────────────────────────
  describe('idempotency key in response', () => {
    it('includes idempotency_key in each receipt result', async () => {
      _canonicalResults = [{ receipt: { receipt_id: 'ep_rcpt_idem' } }];

      const req = makeRequest({
        headers: { 'x-ep-auto-key': 'test-machine-secret-abc123' },
        body: { receipts: [validReceipt()] },
      });
      const res = await POST(req);
      const data = await parseResponse(res);

      expect(data.receipts).toHaveLength(1);
      expect(data.receipts[0].idempotency_key).toBeDefined();
      expect(typeof data.receipts[0].idempotency_key).toBe('string');
      expect(data.receipts[0].idempotency_key.length).toBeGreaterThan(0);
    });

    it('idempotency key is a hex SHA-256 hash (64 chars)', async () => {
      _canonicalResults = [{ receipt: { receipt_id: 'ep_rcpt_hex' } }];

      const req = makeRequest({
        headers: { 'x-ep-auto-key': 'test-machine-secret-abc123' },
        body: { receipts: [validReceipt()] },
      });
      const res = await POST(req);
      const data = await parseResponse(res);

      const key = data.receipts[0].idempotency_key;
      expect(key).toMatch(/^[0-9a-f]{64}$/);
    });
  });

  // ── Edge cases ─────────────────────────────────────────────────────────
  describe('edge cases', () => {
    it('handles invalid JSON body gracefully', async () => {
      const req = new Request('http://localhost/api/receipts/auto-submit', {
        method: 'POST',
        headers: new Headers({ 'x-ep-auto-key': 'test-machine-secret-abc123' }),
        body: 'not json {{{',
      });
      const res = await POST(req);
      expect(res.status).toBe(400);
      const data = await parseResponse(res);
      expect(data.detail).toMatch(/[Ii]nvalid JSON/);
    });

    it('sanitizes context and outcome to plain objects', async () => {
      _canonicalResults = [{ receipt: { receipt_id: 'ep_rcpt_sanitized' } }];
      const { canonicalSubmitAutoReceipt } = await import('@/lib/canonical-writer');

      const req = makeRequest({
        headers: { 'x-ep-auto-key': 'test-machine-secret-abc123' },
        body: {
          receipts: [
            validReceipt({
              context: { tool: 'test' },
              outcome: 'not-an-object', // should be sanitized to null
            }),
          ],
        },
      });
      const res = await POST(req);
      const data = await parseResponse(res);
      expect(data.accepted).toBe(1);

      const passedReceipt = canonicalSubmitAutoReceipt.mock.calls.at(-1)[0];
      expect(passedReceipt.context).toEqual({ tool: 'test' });
      expect(passedReceipt.outcome).toBeNull(); // string sanitized away
    });
  });
});
