import { describe, it, expect, vi, beforeEach } from 'vitest';

// =============================================================================
// Audit endpoint authorization tests
//
// Verifies the P0 fix: /api/audit must require audit.view permission,
// not just any valid API key.
// =============================================================================

// Mock @supabase/supabase-js before anything imports it
vi.mock('@supabase/supabase-js', () => ({
  createClient: vi.fn(() => ({
    from: vi.fn(() => ({
      select: vi.fn(() => ({
        eq: vi.fn(() => ({
          is: vi.fn(() => ({
            single: vi.fn(),
          })),
          single: vi.fn(),
          order: vi.fn(),
        })),
        order: vi.fn(() => ({
          range: vi.fn(() => ({
            eq: vi.fn(),
          })),
        })),
      })),
      update: vi.fn(() => ({
        eq: vi.fn(),
      })),
    })),
  })),
}));

// Mock env config
vi.mock('@/lib/env', () => ({
  getSupabaseConfig: () => ({
    url: 'https://test.supabase.co',
    serviceRoleKey: 'test-service-key',
  }),
}));

// Mock ep-ix to avoid side effects
vi.mock('@/lib/ep-ix', () => ({
  emitAudit: vi.fn(),
}));

// We mock authenticateRequest at the module level so the route uses our version
const mockAuthenticateRequest = vi.fn();
const mockGetServiceClient = vi.fn();

vi.mock('@/lib/supabase', () => ({
  authenticateRequest: (...args) => mockAuthenticateRequest(...args),
  getServiceClient: (...args) => mockGetServiceClient(...args),
}));

import { GET } from '../app/api/audit/route.js';

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function makeRequest({ headers = {}, searchParams = {} } = {}) {
  const url = new URL('https://localhost/api/audit');
  for (const [k, v] of Object.entries(searchParams)) {
    url.searchParams.set(k, v);
  }
  return {
    url: url.toString(),
    headers: {
      get: (name) => headers[name.toLowerCase()] || null,
    },
  };
}

function mockSupabaseQuery(data = [], error = null) {
  const chainable = {
    eq: vi.fn().mockReturnThis(),
    order: vi.fn().mockReturnThis(),
    range: vi.fn().mockResolvedValue({ data, error }),
    select: vi.fn().mockReturnThis(),
  };
  // Make eq also return chainable so chaining works in any order
  chainable.eq.mockReturnValue(chainable);
  chainable.order.mockReturnValue(chainable);
  chainable.select.mockReturnValue(chainable);

  mockGetServiceClient.mockReturnValue({
    from: vi.fn(() => chainable),
  });
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

describe('GET /api/audit — authorization', () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  it('returns 401 for unauthenticated requests', async () => {
    mockAuthenticateRequest.mockResolvedValue({
      error: 'Missing or invalid API key',
    });

    const req = makeRequest();
    const res = await GET(req);
    const body = await res.json();

    expect(res.status).toBe(401);
    expect(body.status).toBe(401);
    expect(body.title).toMatch(/unauthorized/i);
  });

  it('returns 403 for authenticated entity WITHOUT audit.view permission', async () => {
    mockAuthenticateRequest.mockResolvedValue({
      entity: { id: 'entity-1', status: 'active' },
      permissions: ['report.file', 'appeal.file'], // reporter-level, no audit.view
    });

    const req = makeRequest();
    const res = await GET(req);
    const body = await res.json();

    expect(res.status).toBe(403);
    expect(body.status).toBe(403);
    expect(body.detail).toContain('audit.view');
  });

  it('returns 403 for authenticated entity with empty permissions', async () => {
    mockAuthenticateRequest.mockResolvedValue({
      entity: { id: 'entity-2', status: 'active' },
      permissions: [],
    });

    const req = makeRequest();
    const res = await GET(req);
    const body = await res.json();

    expect(res.status).toBe(403);
    expect(body.detail).toContain('audit.view');
  });

  it('returns 403 for authenticated entity with null permissions', async () => {
    mockAuthenticateRequest.mockResolvedValue({
      entity: { id: 'entity-3', status: 'active' },
      permissions: null,
    });

    const req = makeRequest();
    const res = await GET(req);
    const body = await res.json();

    expect(res.status).toBe(403);
  });

  it('returns 200 for operator with audit.view in API key permissions', async () => {
    mockAuthenticateRequest.mockResolvedValue({
      entity: { id: 'operator-1', status: 'active' },
      permissions: ['audit.view', 'entity.suspend'],
    });
    mockSupabaseQuery([
      { id: 'evt-1', event_type: 'operator.resolve', created_at: '2026-01-01T00:00:00Z' },
    ]);

    const req = makeRequest();
    const res = await GET(req);
    const body = await res.json();

    expect(res.status).toBe(200);
    expect(body.events).toHaveLength(1);
  });

  it('returns 200 for entity with operator role header', async () => {
    mockAuthenticateRequest.mockResolvedValue({
      entity: { id: 'entity-4', status: 'active' },
      permissions: ['audit.view'], // operator-level permission
    });
    mockSupabaseQuery([]);

    const req = makeRequest({
      headers: { 'x-ep-role': 'operator' },
    });
    const res = await GET(req);
    const body = await res.json();

    expect(res.status).toBe(200);
    expect(body.events).toEqual([]);
  });

  it('rejects invalid role header that lacks audit.view', async () => {
    mockAuthenticateRequest.mockResolvedValue({
      entity: { id: 'entity-5', status: 'active' },
      permissions: [],
    });

    const req = makeRequest({
      headers: { 'x-ep-role': 'reporter' }, // reporter does not have audit.view
    });
    const res = await GET(req);
    const body = await res.json();

    expect(res.status).toBe(403);
    expect(body.detail).toContain('audit.view');
  });

  it('rejects fabricated role header that does not exist in OPERATOR_ROLES', async () => {
    mockAuthenticateRequest.mockResolvedValue({
      entity: { id: 'entity-6', status: 'active' },
      permissions: [],
    });

    const req = makeRequest({
      headers: { 'x-ep-role': 'superadmin' }, // not a real role
    });
    const res = await GET(req);

    expect(res.status).toBe(403);
  });
});
