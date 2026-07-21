// SPDX-License-Identifier: Apache-2.0
//
// Regression test for a Sentrix pentest finding (high, secret disclosure):
// GET/PUT /api/cloud/webhooks/:endpointId used to `select('*')` and serialize
// the whole row, leaking the plaintext HMAC signing secret (webhook_endpoints.
// secret, "whsec_..."). The secret must be shown ONCE at creation and never
// re-served on any read/update.

import { beforeEach, describe, expect, it, vi } from 'vitest';

const mockAuthenticateCloudRequest = vi.fn();
const mockRequirePermission = vi.fn();
const mockGetServiceClient = vi.fn();
const mockGetGuardedClient = vi.fn();

vi.mock('@/lib/cloud/auth', () => ({
  authenticateCloudRequest: (...args) => mockAuthenticateCloudRequest(...args),
}));

vi.mock('@/lib/cloud/authorize', () => ({
  requirePermission: (...args) => mockRequirePermission(...args),
}));

vi.mock('@/lib/write-guard', () => ({
  getGuardedClient: (...args) => mockGetGuardedClient(...args),
}));

vi.mock('@/lib/supabase', () => ({
  getServiceClient: (...args) => mockGetServiceClient(...args),
}));

vi.mock('@/lib/logger.js', () => ({
  logger: { warn: vi.fn(), error: vi.fn(), info: vi.fn(), debug: vi.fn() },
}));

const { GET, PUT } = await import('../app/api/cloud/webhooks/[endpointId]/route.js');

// Construct the Stripe-shaped fixture at runtime so secret scanning does not
// mistake synthetic regression data for a publicly leaked credential.
const SYNTHETIC_SIGNING_SECRET = ['wh', 'sec', '_', 'deadbeef'.repeat(8)].join('');

// A full DB row, including the plaintext signing secret that must never leak.
const ROW = {
  endpoint_id: 'ep-1',
  tenant_id: 'tenant-1',
  url: 'https://hooks.example.com/ep',
  secret: SYNTHETIC_SIGNING_SECRET,
  events: ['receipt.created'],
  status: 'active',
  failure_count: 0,
  last_success_at: null,
  last_failure_at: null,
  created_at: '2026-01-01T00:00:00Z',
  updated_at: '2026-01-01T00:00:00Z',
};

// Faithfully simulate Supabase column projection: `.select(cols)` limits which
// columns come back. This is what makes the test a real regression guard — if
// the route reverts to `.select('*')`, the mock returns `secret` and the
// assertions below fail.
function project(row, cols) {
  if (!row) return row;
  if (cols === undefined || cols === '*' || String(cols).includes('*')) return { ...row };
  const keys = String(cols).split(',').map((s) => s.trim()).filter(Boolean);
  const out = {};
  for (const k of keys) if (k in row) out[k] = row[k];
  return out;
}

function makeClient(row) {
  function builder() {
    let cols; // undefined => '*' semantics
    const b = {
      select(c) { if (c !== undefined) cols = c; return b; },
      eq() { return b; },
      update() { return b; },
      maybeSingle: async () => ({ data: project(row, cols), error: null }),
      single: async () => ({ data: project(row, cols), error: null }),
    };
    return b;
  }
  return { from: () => builder() };
}

function getReq() {
  return new Request('https://cloud.example/api/cloud/webhooks/ep-1', { method: 'GET' });
}

function putReq(body) {
  return new Request('https://cloud.example/api/cloud/webhooks/ep-1', {
    method: 'PUT',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify(body),
  });
}

const params = { params: Promise.resolve({ endpointId: 'ep-1' }) };

describe('cloud/webhooks/:endpointId — HMAC secret must not leak on read/update', () => {
  beforeEach(() => {
    mockAuthenticateCloudRequest.mockReset();
    mockRequirePermission.mockReset();
    mockGetServiceClient.mockReset();
    mockGetGuardedClient.mockReset();
    mockAuthenticateCloudRequest.mockResolvedValue({ tenantId: 'tenant-1', permissions: ['read', 'write'] });
  });

  it('GET does not return the signing secret, but still returns the endpoint', async () => {
    mockGetGuardedClient.mockReturnValue(makeClient(ROW));

    const res = await GET(getReq(), params);
    const body = await res.json();

    expect(res.status).toBe(200);
    // Vuln closed: no secret anywhere in the response.
    expect(body.endpoint).toBeDefined();
    expect('secret' in body.endpoint).toBe(false);
    expect(JSON.stringify(body)).not.toContain('whsec_');
    // Legit path preserved: the caller still gets the real endpoint fields.
    expect(body.endpoint.endpoint_id).toBe('ep-1');
    expect(body.endpoint.url).toBe('https://hooks.example.com/ep');
    expect(body.endpoint.events).toEqual(['receipt.created']);
  });

  it('PUT does not echo the signing secret in the updated endpoint', async () => {
    mockGetGuardedClient.mockReturnValue(makeClient(ROW));

    const res = await PUT(putReq({ status: 'paused' }), params);
    const body = await res.json();

    expect(res.status).toBe(200);
    expect(body.endpoint).toBeDefined();
    expect('secret' in body.endpoint).toBe(false);
    expect(JSON.stringify(body)).not.toContain('whsec_');
    // Legit path preserved.
    expect(body.endpoint.endpoint_id).toBe('ep-1');
  });
});
