import { describe, it, expect, vi, beforeEach } from 'vitest';
import { POST } from '../app/api/disputes/report/route.js';

// ============================================================================
// Report type consistency tests
// ============================================================================
// The DB schema (013_disputes.sql) defines exactly 5 canonical report types
// in the trust_reports table's CHECK constraint. Every surface that accepts
// or displays report types must stay in sync with these 5.
// ============================================================================

const CANONICAL_REPORT_TYPES = [
  'wrongly_downgraded',
  'harmed_by_trusted_entity',
  'fraudulent_entity',
  'inaccurate_profile',
  'other',
];

// Stale types that were previously accepted but are NOT in the DB schema.
// These must be rejected everywhere.
const STALE_REPORT_TYPES = [
  'fake_receipts',
  'unsafe_software',
  'misleading_identity',
  'terms_violation',
  'demo_challenge',
];

// Mock dependencies so we can test the route handler in isolation
vi.mock('@/lib/supabase', () => ({
  getServiceClient: vi.fn(() => ({})),
}));

vi.mock('@/lib/procedural-justice', () => ({
  checkAbuse: vi.fn(() => ({ allowed: true })),
}));

vi.mock('@/lib/canonical-writer', () => ({
  canonicalFileReport: vi.fn((params) => ({
    report_id: `ep_rpt_test_${Date.now()}`,
    entity_id: params.entity_id,
    display_name: 'Test Entity',
  })),
}));

vi.mock('@/lib/errors', () => ({
  EP_ERRORS: {
    BAD_REQUEST: (msg) => new Response(JSON.stringify({ error: msg }), { status: 400 }),
    INTERNAL: () => new Response(JSON.stringify({ error: 'Internal error' }), { status: 500 }),
  },
  epProblem: (status, code, msg, extra) =>
    new Response(JSON.stringify({ error: msg, code, ...extra }), { status }),
}));

function makeRequest(body) {
  return new Request('http://localhost/api/disputes/report', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(body),
  });
}

// ============================================================================
// Each canonical report type should be accepted
// ============================================================================

describe('Canonical report types are accepted', () => {
  for (const reportType of CANONICAL_REPORT_TYPES) {
    it(`accepts report_type="${reportType}"`, async () => {
      const req = makeRequest({
        entity_id: 'test-entity-001',
        report_type: reportType,
        description: `Testing ${reportType} report type`,
      });
      const res = await POST(req);
      expect(res.status).toBe(201);
      const data = await res.json();
      expect(data.report_id).toBeDefined();
    });
  }
});

// ============================================================================
// Stale report types must be rejected
// ============================================================================

describe('Stale report types are rejected', () => {
  for (const reportType of STALE_REPORT_TYPES) {
    it(`rejects report_type="${reportType}"`, async () => {
      const req = makeRequest({
        entity_id: 'test-entity-001',
        report_type: reportType,
        description: `Should fail for ${reportType}`,
      });
      const res = await POST(req);
      expect(res.status).toBe(400);
      const data = await res.json();
      expect(data.error).toContain('Invalid report_type');
    });
  }
});

// ============================================================================
// Completely unknown types must also be rejected
// ============================================================================

describe('Unknown report types are rejected', () => {
  it('rejects an arbitrary unknown type', async () => {
    const req = makeRequest({
      entity_id: 'test-entity-001',
      report_type: 'nonexistent_type',
      description: 'Should not be accepted',
    });
    const res = await POST(req);
    expect(res.status).toBe(400);
  });
});

// ============================================================================
// Exactly 5 canonical types — no more, no fewer
// ============================================================================

describe('Report type count matches DB schema', () => {
  it('has exactly 5 canonical report types', () => {
    expect(CANONICAL_REPORT_TYPES).toHaveLength(5);
  });

  it('does not include any stale types', () => {
    for (const stale of STALE_REPORT_TYPES) {
      expect(CANONICAL_REPORT_TYPES).not.toContain(stale);
    }
  });
});
