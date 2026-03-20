/**
 * EP Handshake — Route-to-Service Integration Tests (Audit Issue #7)
 *
 * Tests that route handler functions pass the correct arguments to service
 * functions. Imports route handlers directly and calls them with mock Request
 * objects. Mocks @/lib/supabase (authenticateRequest) and @/lib/handshake
 * so we can verify EXACTLY what the routes pass to the service layer.
 *
 * @license Apache-2.0
 */

import { describe, it, expect, vi, beforeEach } from 'vitest';

// ============================================================================
// Helpers
// ============================================================================

function createMockRequest(method, url, body = null) {
  return new Request(url, {
    method,
    headers: { 'Content-Type': 'application/json' },
    ...(body ? { body: JSON.stringify(body) } : {}),
  });
}

/** Parse JSON from a NextResponse */
async function responseJson(response) {
  return response.json();
}

// ============================================================================
// Mock: @/lib/supabase — authenticateRequest always succeeds
// ============================================================================

const mockAuthenticateRequest = vi.fn().mockResolvedValue({
  entity: 'test-entity-123',
});

vi.mock('@/lib/supabase', () => ({
  authenticateRequest: (...args) => mockAuthenticateRequest(...args),
  getServiceClient: vi.fn(),
}));

// ============================================================================
// Mock: @/lib/handshake — all service functions are vi.fn() stubs
// ============================================================================

const mockInitiateHandshake = vi.fn().mockResolvedValue({
  handshake_id: 'eph_test_123',
  mode: 'mutual',
  status: 'initiated',
});

const mockListHandshakes = vi.fn().mockResolvedValue({
  handshakes: [{ handshake_id: 'eph_test_123' }],
});

const mockGetHandshake = vi.fn().mockResolvedValue({
  handshake_id: 'eph_test_123',
  mode: 'mutual',
  status: 'initiated',
  parties: [],
  presentations: [],
});

const mockAddPresentation = vi.fn().mockResolvedValue({
  presentation_id: 'pres_test_456',
  party_role: 'initiator',
});

const mockVerifyHandshake = vi.fn().mockResolvedValue({
  handshake_id: 'eph_test_123',
  outcome: 'accepted',
  reason_codes: [],
});

const mockRevokeHandshake = vi.fn().mockResolvedValue({
  handshake_id: 'eph_test_123',
  status: 'revoked',
});

vi.mock('@/lib/handshake', () => ({
  initiateHandshake: (...args) => mockInitiateHandshake(...args),
  listHandshakes: (...args) => mockListHandshakes(...args),
  getHandshake: (...args) => mockGetHandshake(...args),
  addPresentation: (...args) => mockAddPresentation(...args),
  verifyHandshake: (...args) => mockVerifyHandshake(...args),
  revokeHandshake: (...args) => mockRevokeHandshake(...args),
}));

// ============================================================================
// Mock: @/lib/errors — use real implementations
// ============================================================================

// Let @/lib/errors resolve normally (it uses NextResponse which is available
// in the vitest environment via next/server).

// ============================================================================
// Import route handlers (after mocks are set up)
// ============================================================================

import { POST as createPost, GET as listGet } from '@/app/api/handshake/route';
import { POST as presentPost } from '@/app/api/handshake/[handshakeId]/present/route';
import { POST as verifyPost } from '@/app/api/handshake/[handshakeId]/verify/route';
import { POST as revokePost } from '@/app/api/handshake/[handshakeId]/revoke/route';
import { GET as detailGet } from '@/app/api/handshake/[handshakeId]/route';

// ============================================================================
// Reset mocks before each test
// ============================================================================

beforeEach(() => {
  vi.clearAllMocks();
  mockAuthenticateRequest.mockResolvedValue({ entity: 'test-entity-123' });
  mockInitiateHandshake.mockResolvedValue({
    handshake_id: 'eph_test_123',
    mode: 'mutual',
    status: 'initiated',
  });
  mockListHandshakes.mockResolvedValue({
    handshakes: [{ handshake_id: 'eph_test_123' }],
  });
  mockGetHandshake.mockResolvedValue({
    handshake_id: 'eph_test_123',
    mode: 'mutual',
    status: 'initiated',
    parties: [],
    presentations: [],
  });
  mockAddPresentation.mockResolvedValue({
    presentation_id: 'pres_test_456',
    party_role: 'initiator',
  });
  mockVerifyHandshake.mockResolvedValue({
    handshake_id: 'eph_test_123',
    outcome: 'accepted',
    reason_codes: [],
  });
  mockRevokeHandshake.mockResolvedValue({
    handshake_id: 'eph_test_123',
    status: 'revoked',
  });
});

// ============================================================================
// Tests
// ============================================================================

describe('POST /api/handshake (create)', () => {
  const validBody = {
    mode: 'mutual',
    policy_id: 'pol_abc',
    parties: [
      { role: 'initiator', entity_ref: 'ent_1' },
      { role: 'responder', entity_ref: 'ent_2' },
    ],
  };

  it('1. passes actor inside single object to initiateHandshake (not as second arg)', async () => {
    const req = createMockRequest('POST', 'http://localhost/api/handshake', validBody);
    await createPost(req);

    expect(mockInitiateHandshake).toHaveBeenCalledTimes(1);
    // Should be called with a single object argument containing actor
    const callArgs = mockInitiateHandshake.mock.calls[0];
    expect(callArgs).toHaveLength(1);
    expect(callArgs[0]).toHaveProperty('actor', 'test-entity-123');
    expect(callArgs[0]).toHaveProperty('mode', 'mutual');
    expect(callArgs[0]).toHaveProperty('policy_id', 'pol_abc');
    expect(callArgs[0]).toHaveProperty('parties', validBody.parties);
  });

  it('2. passes payload, binding_ttl_ms, idempotency_key when provided', async () => {
    const body = {
      ...validBody,
      payload: { tx: '0xabc' },
      binding_ttl_ms: 300000,
      idempotency_key: 'idem_123',
    };
    const req = createMockRequest('POST', 'http://localhost/api/handshake', body);
    await createPost(req);

    const arg = mockInitiateHandshake.mock.calls[0][0];
    expect(arg.payload).toEqual({ tx: '0xabc' });
    expect(arg.binding_ttl_ms).toBe(300000);
    expect(arg.idempotency_key).toBe('idem_123');
  });

  it('3. passes interaction_id correctly', async () => {
    const body = {
      ...validBody,
      interaction_id: 'int_xyz',
    };
    const req = createMockRequest('POST', 'http://localhost/api/handshake', body);
    await createPost(req);

    const arg = mockInitiateHandshake.mock.calls[0][0];
    expect(arg.interaction_id).toBe('int_xyz');
  });

  it('4. returns 400 when mode is missing', async () => {
    const body = { ...validBody };
    delete body.mode;
    const req = createMockRequest('POST', 'http://localhost/api/handshake', body);
    const res = await createPost(req);

    expect(res.status).toBe(400);
    const json = await responseJson(res);
    expect(json.detail).toContain('mode');
    expect(mockInitiateHandshake).not.toHaveBeenCalled();
  });

  it('5. returns 400 when policy_id is missing', async () => {
    const body = { ...validBody };
    delete body.policy_id;
    const req = createMockRequest('POST', 'http://localhost/api/handshake', body);
    const res = await createPost(req);

    expect(res.status).toBe(400);
    const json = await responseJson(res);
    expect(json.detail).toContain('policy_id');
    expect(mockInitiateHandshake).not.toHaveBeenCalled();
  });

  it('6. returns 400 when parties has fewer than 2 entries', async () => {
    const body = {
      ...validBody,
      parties: [{ role: 'initiator', entity_ref: 'ent_1' }],
    };
    const req = createMockRequest('POST', 'http://localhost/api/handshake', body);
    const res = await createPost(req);

    expect(res.status).toBe(400);
    const json = await responseJson(res);
    expect(json.detail).toContain('parties');
    expect(mockInitiateHandshake).not.toHaveBeenCalled();
  });

  it('7. returns 201 on success', async () => {
    const req = createMockRequest('POST', 'http://localhost/api/handshake', validBody);
    const res = await createPost(req);

    expect(res.status).toBe(201);
    const json = await responseJson(res);
    expect(json.handshake_id).toBe('eph_test_123');
  });
});

describe('POST /api/handshake/:id/present', () => {
  const handshakeId = 'eph_test_123';
  const mockParams = { params: Promise.resolve({ handshakeId }) };

  const validBody = {
    party_role: 'initiator',
    presentation_type: 'verifiable_credential',
    claims: { name: 'Alice', age: 30 },
    issuer_ref: 'iss_abc',
    disclosure_mode: 'selective',
  };

  it('8. passes party_role as second positional argument (not inside object)', async () => {
    const req = createMockRequest('POST', `http://localhost/api/handshake/${handshakeId}/present`, validBody);
    await presentPost(req, mockParams);

    expect(mockAddPresentation).toHaveBeenCalledTimes(1);
    const callArgs = mockAddPresentation.mock.calls[0];
    // addPresentation(handshakeId, partyRole, presentation, actor)
    expect(callArgs[0]).toBe(handshakeId);
    expect(callArgs[1]).toBe('initiator');
  });

  it('9. passes presentation as {type, data, issuer_ref, disclosure_mode} object', async () => {
    const req = createMockRequest('POST', `http://localhost/api/handshake/${handshakeId}/present`, validBody);
    await presentPost(req, mockParams);

    const callArgs = mockAddPresentation.mock.calls[0];
    const presentationArg = callArgs[2];
    expect(presentationArg).toEqual({
      type: 'verifiable_credential',
      data: { name: 'Alice', age: 30 },
      issuer_ref: 'iss_abc',
      disclosure_mode: 'selective',
    });
  });

  it('10. passes actor as fourth argument', async () => {
    const req = createMockRequest('POST', `http://localhost/api/handshake/${handshakeId}/present`, validBody);
    await presentPost(req, mockParams);

    const callArgs = mockAddPresentation.mock.calls[0];
    expect(callArgs[3]).toBe('test-entity-123');
  });

  it('11. returns 400 when party_role is missing', async () => {
    const body = { ...validBody };
    delete body.party_role;
    const req = createMockRequest('POST', `http://localhost/api/handshake/${handshakeId}/present`, body);
    const res = await presentPost(req, mockParams);

    expect(res.status).toBe(400);
    const json = await responseJson(res);
    expect(json.detail).toContain('party_role');
    expect(mockAddPresentation).not.toHaveBeenCalled();
  });

  it('12. returns 400 when presentation_type is missing', async () => {
    const body = { ...validBody };
    delete body.presentation_type;
    const req = createMockRequest('POST', `http://localhost/api/handshake/${handshakeId}/present`, body);
    const res = await presentPost(req, mockParams);

    expect(res.status).toBe(400);
    const json = await responseJson(res);
    expect(json.detail).toContain('presentation_type');
    expect(mockAddPresentation).not.toHaveBeenCalled();
  });
});

describe('POST /api/handshake/:id/verify', () => {
  const handshakeId = 'eph_test_123';
  const mockParams = { params: Promise.resolve({ handshakeId }) };

  it('13. passes options object {actor, payload_hash} as second argument', async () => {
    const body = { payload_hash: 'hash_abc123' };
    const req = createMockRequest('POST', `http://localhost/api/handshake/${handshakeId}/verify`, body);
    await verifyPost(req, mockParams);

    expect(mockVerifyHandshake).toHaveBeenCalledTimes(1);
    const callArgs = mockVerifyHandshake.mock.calls[0];
    expect(callArgs[0]).toBe(handshakeId);
    expect(callArgs[1]).toEqual({
      actor: 'test-entity-123',
      payload_hash: 'hash_abc123',
    });
  });

  it('14. handles missing body gracefully (defaults to empty object)', async () => {
    // Send a request with no body — the route uses .json().catch(() => ({}))
    const req = new Request(`http://localhost/api/handshake/${handshakeId}/verify`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
    });
    await verifyPost(req, mockParams);

    expect(mockVerifyHandshake).toHaveBeenCalledTimes(1);
    const callArgs = mockVerifyHandshake.mock.calls[0];
    expect(callArgs[0]).toBe(handshakeId);
    expect(callArgs[1]).toEqual({
      actor: 'test-entity-123',
      payload_hash: null,
    });
  });

  it('15. returns success with verification result', async () => {
    const body = {};
    const req = createMockRequest('POST', `http://localhost/api/handshake/${handshakeId}/verify`, body);
    const res = await verifyPost(req, mockParams);

    expect(res.status).toBe(200);
    const json = await responseJson(res);
    expect(json.outcome).toBe('accepted');
    expect(json.handshake_id).toBe('eph_test_123');
  });
});

describe('GET /api/handshake (list)', () => {
  it('16. calls listHandshakes (not getHandshake) with filters and actor', async () => {
    const req = createMockRequest('GET', 'http://localhost/api/handshake?status=initiated&mode=mutual&entity_ref=ent_1');
    await listGet(req);

    expect(mockListHandshakes).toHaveBeenCalledTimes(1);
    expect(mockGetHandshake).not.toHaveBeenCalled();

    const callArgs = mockListHandshakes.mock.calls[0];
    // listHandshakes(filters, actor)
    expect(callArgs[1]).toBe('test-entity-123');
  });

  it('17. passes filter params from query string correctly', async () => {
    const req = createMockRequest('GET', 'http://localhost/api/handshake?status=verified&mode=delegated&entity_ref=ent_xyz');
    await listGet(req);

    const filters = mockListHandshakes.mock.calls[0][0];
    expect(filters).toEqual({
      entity_ref: 'ent_xyz',
      status: 'verified',
      mode: 'delegated',
    });
  });
});

describe('GET /api/handshake/:id (detail)', () => {
  it('18. calls getHandshake with handshakeId as first argument', async () => {
    const handshakeId = 'eph_detail_789';
    const mockParams = { params: Promise.resolve({ handshakeId }) };
    const req = createMockRequest('GET', `http://localhost/api/handshake/${handshakeId}`);
    await detailGet(req, mockParams);

    expect(mockGetHandshake).toHaveBeenCalledTimes(1);
    const callArgs = mockGetHandshake.mock.calls[0];
    expect(callArgs[0]).toBe('eph_detail_789');
  });
});

describe('POST /api/handshake/:id/revoke', () => {
  it('19. passes handshakeId, reason, and actor correctly', async () => {
    const handshakeId = 'eph_revoke_321';
    const mockParams = { params: Promise.resolve({ handshakeId }) };
    const body = { reason: 'policy_violation' };
    const req = createMockRequest('POST', `http://localhost/api/handshake/${handshakeId}/revoke`, body);
    await revokePost(req, mockParams);

    expect(mockRevokeHandshake).toHaveBeenCalledTimes(1);
    const callArgs = mockRevokeHandshake.mock.calls[0];
    expect(callArgs[0]).toBe('eph_revoke_321');
    expect(callArgs[1]).toBe('policy_violation');
    expect(callArgs[2]).toBe('test-entity-123');
  });
});
