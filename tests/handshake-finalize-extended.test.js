/**
 * Extended tests for lib/handshake/finalize.js
 *
 * Targets uncovered lines:
 *   19  — revokeHandshake: MISSING_HANDSHAKE_ID when no handshakeId
 *   22  — revokeHandshake: MISSING_REASON when no reason
 *   51  — _handleRevokeHandshake: DB_ERROR when handshake fetch fails
 *   103 — _handleRevokeHandshake: DB_ERROR when update fails
 *
 * @license Apache-2.0
 */

import { describe, it, expect, vi, beforeEach } from 'vitest';

// ── Mocks ─────────────────────────────────────────────────────────────────────

const mockGetServiceClient = vi.fn();

vi.mock('../lib/supabase.js', () => ({
  getServiceClient: (...args) => mockGetServiceClient(...args),
}));

vi.mock('../lib/protocol-write.js', () => ({
  COMMAND_TYPES: {
    REVOKE_HANDSHAKE: 'revoke_handshake',
    INITIATE_HANDSHAKE: 'initiate_handshake',
    ADD_PRESENTATION: 'add_presentation',
    VERIFY_HANDSHAKE: 'verify_handshake',
  },
  protocolWrite: vi.fn(async (command) => {
    if (command.type === 'revoke_handshake') {
      const { _handleRevokeHandshake } = await import('../lib/handshake/finalize.js');
      const res = await _handleRevokeHandshake(command);
      return res?.result ?? res;
    }
    throw new Error(`Unhandled: ${command.type}`);
  }),
}));

// Mock the events module (dynamically imported inside _handleRevokeHandshake)
vi.mock('../lib/handshake/events.js', () => ({
  requireHandshakeEvent: vi.fn().mockResolvedValue(undefined),
}));

// Import after mocks
import { revokeHandshake, _handleRevokeHandshake } from '../lib/handshake/finalize.js';
import { HandshakeError } from '../lib/handshake/errors.js';

// ── DB mock builder ───────────────────────────────────────────────────────────

function makeChain(resolveValue) {
  return {
    select: vi.fn().mockReturnThis(),
    eq: vi.fn().mockReturnThis(),
    limit: vi.fn().mockReturnThis(),
    maybeSingle: vi.fn().mockResolvedValue(resolveValue),
    then: (resolve) => Promise.resolve(resolveValue).then(resolve),
  };
}

function buildSupabaseMock({
  handshake = null,
  handshakeError = null,
  memberCheck = null,
  updateError = null,
} = {}) {
  const hsChain = makeChain({ data: handshake, error: handshakeError });
  const memberChain = {
    select: vi.fn().mockReturnThis(),
    eq: vi.fn().mockReturnThis(),
    limit: vi.fn().mockResolvedValue({ data: memberCheck, error: null }),
  };
  const updateChain = {
    eq: vi.fn().mockReturnThis(),
    then: (resolve) => Promise.resolve({ data: null, error: updateError }).then(resolve),
  };

  return {
    from: vi.fn((table) => {
      if (table === 'handshakes') {
        // First call is the fetch, subsequent calls are the update
        let hsCallCount = 0;
        return {
          select: vi.fn().mockReturnThis(),
          eq: vi.fn().mockReturnThis(),
          maybeSingle: vi.fn().mockResolvedValue({ data: handshake, error: handshakeError }),
          update: vi.fn(() => updateChain),
        };
      }
      if (table === 'handshake_parties') return memberChain;
      return makeChain({ data: null, error: null });
    }),
  };
}

// ── revokeHandshake — public API (lines 19, 22) ───────────────────────────────

describe('revokeHandshake — MISSING_HANDSHAKE_ID (line 19)', () => {
  it('throws MISSING_HANDSHAKE_ID when handshakeId is empty string', async () => {
    await expect(revokeHandshake('', 'reason', 'system')).rejects.toMatchObject({
      code: 'MISSING_HANDSHAKE_ID',
      status: 400,
    });
  });

  it('throws MISSING_HANDSHAKE_ID when handshakeId is null', async () => {
    await expect(revokeHandshake(null, 'reason', 'system')).rejects.toMatchObject({
      code: 'MISSING_HANDSHAKE_ID',
      status: 400,
    });
  });

  it('throws MISSING_HANDSHAKE_ID when handshakeId is undefined', async () => {
    await expect(revokeHandshake(undefined, 'reason', 'system')).rejects.toMatchObject({
      code: 'MISSING_HANDSHAKE_ID',
    });
  });
});

describe('revokeHandshake — MISSING_REASON (line 22)', () => {
  it('throws MISSING_REASON when reason is empty string', async () => {
    await expect(revokeHandshake('hs-1', '', 'system')).rejects.toMatchObject({
      code: 'MISSING_REASON',
      status: 400,
    });
  });

  it('throws MISSING_REASON when reason is null', async () => {
    await expect(revokeHandshake('hs-1', null, 'system')).rejects.toMatchObject({
      code: 'MISSING_REASON',
    });
  });

  it('throws MISSING_REASON when reason is undefined', async () => {
    await expect(revokeHandshake('hs-1', undefined, 'system')).rejects.toMatchObject({
      code: 'MISSING_REASON',
    });
  });
});

// ── _handleRevokeHandshake — DB_ERROR on fetch (line 51) ─────────────────────

describe('_handleRevokeHandshake — DB_ERROR on handshake fetch (line 51)', () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  it('throws DB_ERROR when handshake fetch fails', async () => {
    const db = buildSupabaseMock({
      handshake: null,
      handshakeError: { message: 'connection refused' },
    });
    mockGetServiceClient.mockReturnValue(db);

    await expect(_handleRevokeHandshake({
      actor: 'system',
      input: { handshake_id: 'hs-test-1', reason: 'policy change' },
    })).rejects.toMatchObject({
      code: 'DB_ERROR',
      status: 500,
    });
  });

  it('throws NOT_FOUND when handshake does not exist', async () => {
    const db = buildSupabaseMock({
      handshake: null,
      handshakeError: null,
    });
    mockGetServiceClient.mockReturnValue(db);

    await expect(_handleRevokeHandshake({
      actor: 'system',
      input: { handshake_id: 'hs-nonexistent', reason: 'cleanup' },
    })).rejects.toMatchObject({
      code: 'NOT_FOUND',
      status: 404,
    });
  });
});

// ── _handleRevokeHandshake — INVALID_STATE ────────────────────────────────────

describe('_handleRevokeHandshake — INVALID_STATE for terminal statuses', () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  it('throws INVALID_STATE when handshake is already revoked', async () => {
    const db = buildSupabaseMock({
      handshake: { handshake_id: 'hs-revoked', status: 'revoked' },
    });
    mockGetServiceClient.mockReturnValue(db);

    await expect(_handleRevokeHandshake({
      actor: 'system',
      input: { handshake_id: 'hs-revoked', reason: 'duplicate' },
    })).rejects.toMatchObject({
      code: 'INVALID_STATE',
      status: 409,
    });
  });

  it('throws INVALID_STATE when handshake is expired', async () => {
    const db = buildSupabaseMock({
      handshake: { handshake_id: 'hs-expired', status: 'expired' },
    });
    mockGetServiceClient.mockReturnValue(db);

    await expect(_handleRevokeHandshake({
      actor: 'system',
      input: { handshake_id: 'hs-expired', reason: 'cleanup' },
    })).rejects.toMatchObject({
      code: 'INVALID_STATE',
    });
  });
});

// ── _handleRevokeHandshake — UNAUTHORIZED_REVOCATION ──────────────────────────

describe('_handleRevokeHandshake — UNAUTHORIZED_REVOCATION', () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  it('throws UNAUTHORIZED_REVOCATION when non-system actor is not a party member', async () => {
    const db = buildSupabaseMock({
      handshake: { handshake_id: 'hs-1', status: 'verified' },
      memberCheck: [], // empty — actor is not a member
    });
    mockGetServiceClient.mockReturnValue(db);

    await expect(_handleRevokeHandshake({
      actor: 'entity-stranger',
      input: { handshake_id: 'hs-1', reason: 'abuse' },
    })).rejects.toMatchObject({
      code: 'UNAUTHORIZED_REVOCATION',
      status: 403,
    });
  });

  it('allows non-system actor who is a party member', async () => {
    const { requireHandshakeEvent } = await import('../lib/handshake/events.js');

    const updateChain = {
      eq: vi.fn().mockReturnThis(),
      then: (resolve) => Promise.resolve({ data: null, error: null }).then(resolve),
    };
    const db = {
      from: vi.fn((table) => {
        if (table === 'handshakes') {
          return {
            select: vi.fn().mockReturnThis(),
            eq: vi.fn().mockReturnThis(),
            maybeSingle: vi.fn().mockResolvedValue({ data: { handshake_id: 'hs-1', status: 'verified' }, error: null }),
            update: vi.fn(() => updateChain),
          };
        }
        if (table === 'handshake_parties') {
          return {
            select: vi.fn().mockReturnThis(),
            eq: vi.fn().mockReturnThis(),
            limit: vi.fn().mockResolvedValue({ data: [{ id: 'p1' }], error: null }),
          };
        }
        return makeChain({ data: null, error: null });
      }),
    };
    mockGetServiceClient.mockReturnValue(db);

    const res = await _handleRevokeHandshake({
      actor: 'entity-member',
      input: { handshake_id: 'hs-1', reason: 'voluntary exit' },
    });
    expect(res.result.status).toBe('revoked');
    expect(res.result.handshake_id).toBe('hs-1');
  });
});

// ── _handleRevokeHandshake — DB_ERROR on update (line 103) ───────────────────

describe('_handleRevokeHandshake — DB_ERROR on update (line 103)', () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  it('throws DB_ERROR when update fails', async () => {
    const updateChain = {
      eq: vi.fn().mockReturnThis(),
      then: (resolve) => Promise.resolve({ data: null, error: { message: 'write failed' } }).then(resolve),
    };
    const db = {
      from: vi.fn((table) => {
        if (table === 'handshakes') {
          return {
            select: vi.fn().mockReturnThis(),
            eq: vi.fn().mockReturnThis(),
            maybeSingle: vi.fn().mockResolvedValue({ data: { handshake_id: 'hs-1', status: 'initiated' }, error: null }),
            update: vi.fn(() => updateChain),
          };
        }
        return makeChain({ data: null, error: null });
      }),
    };
    mockGetServiceClient.mockReturnValue(db);

    await expect(_handleRevokeHandshake({
      actor: 'system',
      input: { handshake_id: 'hs-1', reason: 'test' },
    })).rejects.toMatchObject({
      code: 'DB_ERROR',
      status: 500,
    });
  });

  it('succeeds and returns revoked status for valid active handshake', async () => {
    const updateChain = {
      eq: vi.fn().mockReturnThis(),
      then: (resolve) => Promise.resolve({ data: null, error: null }).then(resolve),
    };
    const db = {
      from: vi.fn((table) => {
        if (table === 'handshakes') {
          return {
            select: vi.fn().mockReturnThis(),
            eq: vi.fn().mockReturnThis(),
            maybeSingle: vi.fn().mockResolvedValue({ data: { handshake_id: 'hs-ok', status: 'initiated' }, error: null }),
            update: vi.fn(() => updateChain),
          };
        }
        return makeChain({ data: null, error: null });
      }),
    };
    mockGetServiceClient.mockReturnValue(db);

    const res = await _handleRevokeHandshake({
      actor: 'system',
      input: { handshake_id: 'hs-ok', reason: 'policy violation' },
    });
    expect(res.result.status).toBe('revoked');
    expect(res.result.reason).toBe('policy violation');
    expect(res.aggregateId).toBe('hs-ok');
  });

  it('extracts actor entity_id when actor is an object', async () => {
    const updateChain = {
      eq: vi.fn().mockReturnThis(),
      then: (resolve) => Promise.resolve({ data: null, error: null }).then(resolve),
    };
    const db = {
      from: vi.fn((table) => {
        if (table === 'handshakes') {
          return {
            select: vi.fn().mockReturnThis(),
            eq: vi.fn().mockReturnThis(),
            maybeSingle: vi.fn().mockResolvedValue({
              data: { handshake_id: 'hs-obj', status: 'verified' },
              error: null,
            }),
            update: vi.fn(() => updateChain),
          };
        }
        return makeChain({ data: null, error: null });
      }),
    };
    mockGetServiceClient.mockReturnValue(db);

    // actor as object with entity_id — system bypass
    const res = await _handleRevokeHandshake({
      actor: { entity_id: 'system', role: 'admin' },
      input: { handshake_id: 'hs-obj', reason: 'admin action' },
    });
    expect(res.result.status).toBe('revoked');
  });
});
