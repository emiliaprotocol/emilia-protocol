/**
 * lib/handshake/index.js — extended coverage.
 *
 * Targets uncovered lines:
 *   57   getHandshake: throws when handshakeId is missing
 *   69   getHandshake: throws on hsError from DB
 *   140  listHandshakes: throws on query error
 *   143  listHandshakes: returns empty when actor is null (fail closed)
 *   149  listHandshakes: filters by status and mode when provided
 */

import { describe, it, expect, vi, beforeEach } from 'vitest';

// ── Mocks ─────────────────────────────────────────────────────────────────────

const mockGetServiceClient = vi.fn();
const mockResolveActorRef = vi.fn((actor) => actor);

vi.mock('../lib/supabase.js', () => ({
  getServiceClient: (...args) => mockGetServiceClient(...args),
}));

vi.mock('../lib/actor.js', () => ({
  resolveActorRef: (...args) => mockResolveActorRef(...args),
}));

// Stub heavy sub-module imports to avoid transitive dependency chains
vi.mock('../lib/handshake/create.js', () => ({
  initiateHandshake: vi.fn(),
  _handleInitiateHandshake: vi.fn(),
}));
vi.mock('../lib/handshake/present.js', () => ({
  addPresentation: vi.fn(),
  _handleAddPresentation: vi.fn(),
}));
vi.mock('../lib/handshake/verify.js', () => ({
  verifyHandshake: vi.fn(),
  _handleVerifyHandshake: vi.fn(),
}));
vi.mock('../lib/handshake/finalize.js', () => ({
  revokeHandshake: vi.fn(),
  _handleRevokeHandshake: vi.fn(),
}));
vi.mock('../lib/handshake/consume.js', () => ({
  consumeHandshake: vi.fn(),
  isHandshakeConsumed: vi.fn(),
}));
vi.mock('../lib/handshake/binding.js', () => ({
  buildBindingMaterial: vi.fn(),
  canonicalizeBinding: vi.fn(),
  hashBinding: vi.fn(),
  validateBindingCompleteness: vi.fn(),
  computePartySetHash: vi.fn(),
  computeContextHash: vi.fn(),
  computePayloadHash: vi.fn(),
  computePolicyHash: vi.fn(),
}));
vi.mock('@/lib/crypto', () => ({
  sha256: vi.fn((s) => 'sha256:' + s),
}));

import { getHandshake, listHandshakes, HandshakeError } from '../lib/handshake/index.js';

// ── Helpers ───────────────────────────────────────────────────────────────────

function makeChain(resolved) {
  const chain = {
    select: vi.fn().mockReturnThis(),
    eq: vi.fn().mockReturnThis(),
    in: vi.fn().mockReturnThis(),
    order: vi.fn().mockReturnThis(),
    limit: vi.fn().mockReturnThis(),
    maybeSingle: vi.fn().mockResolvedValue(resolved),
    single: vi.fn().mockResolvedValue(resolved),
    then: (resolve, reject) => Promise.resolve(resolved).then(resolve, reject),
  };
  return chain;
}

let mockSupabase;

beforeEach(() => {
  vi.clearAllMocks();
  mockSupabase = { from: vi.fn() };
  mockGetServiceClient.mockReturnValue(mockSupabase);
});

// ── getHandshake ──────────────────────────────────────────────────────────────

describe('getHandshake — missing handshakeId (line 57)', () => {
  it('throws HandshakeError MISSING_HANDSHAKE_ID when handshakeId is not provided', async () => {
    await expect(getHandshake(null)).rejects.toMatchObject({
      code: 'MISSING_HANDSHAKE_ID',
      status: 400,
    });

    await expect(getHandshake(undefined)).rejects.toMatchObject({
      code: 'MISSING_HANDSHAKE_ID',
    });

    await expect(getHandshake('')).rejects.toMatchObject({
      code: 'MISSING_HANDSHAKE_ID',
    });
  });
});

describe('getHandshake — DB error on fetch (line 69)', () => {
  it('throws HandshakeError DB_ERROR when handshakes query fails', async () => {
    const errorChain = makeChain({ data: null, error: { message: 'connection timeout' } });
    mockSupabase.from.mockReturnValue(errorChain);

    await expect(getHandshake('hs-1')).rejects.toMatchObject({
      code: 'DB_ERROR',
      status: 500,
    });
  });
});

describe('getHandshake — returns null when not found', () => {
  it('returns null when handshake does not exist', async () => {
    const chain = makeChain({ data: null, error: null });
    mockSupabase.from.mockReturnValue(chain);

    const result = await getHandshake('hs-missing');
    expect(result).toBeNull();
  });
});

describe('getHandshake — returns handshake with related data when found', () => {
  it('returns merged handshake object with parties, presentations, binding, result', async () => {
    const hs = { handshake_id: 'hs-1', status: 'verified' };
    const chainHs = {
      select: vi.fn().mockReturnThis(),
      eq: vi.fn().mockReturnThis(),
      maybeSingle: vi.fn().mockResolvedValue({ data: hs, error: null }),
    };
    const chainEmpty = makeChain({ data: [], error: null });
    const chainNull = makeChain({ data: null, error: null });

    let callCount = 0;
    mockSupabase.from.mockImplementation(() => {
      callCount++;
      if (callCount === 1) return chainHs; // handshakes
      // parties, presentations, binding, result
      return callCount % 2 === 0 ? chainEmpty : chainNull;
    });

    const result = await getHandshake('hs-1');
    expect(result.handshake_id).toBe('hs-1');
    expect(Array.isArray(result.parties)).toBe(true);
    expect(Array.isArray(result.presentations)).toBe(true);
  });
});

// ── listHandshakes ────────────────────────────────────────────────────────────

describe('listHandshakes — null actor returns empty (line 143)', () => {
  it('returns empty handshakes array when actor is null (fail closed)', async () => {
    const result = await listHandshakes({}, null);
    expect(result).toEqual({ handshakes: [] });
    // Should not have called supabase at all
    expect(mockSupabase.from).not.toHaveBeenCalled();
  });
});

describe('listHandshakes — query error throws (line 140)', () => {
  it('throws HandshakeError DB_ERROR when query fails', async () => {
    // parties query
    const partiesChain = makeChain({ data: [{ handshake_id: 'hs-1' }], error: null });

    // Final query chain that errors
    const errorChain = {
      select: vi.fn().mockReturnThis(),
      order: vi.fn().mockReturnThis(),
      limit: vi.fn().mockReturnThis(),
      in: vi.fn().mockReturnThis(),
      eq: vi.fn().mockReturnThis(),
      then: (resolve) =>
        Promise.resolve({ data: null, error: { message: 'db error' } }).then(resolve),
    };

    let callCount = 0;
    mockSupabase.from.mockImplementation((table) => {
      callCount++;
      if (table === 'handshake_parties') return partiesChain;
      return errorChain;
    });

    await expect(listHandshakes({}, 'actor-1')).rejects.toMatchObject({
      code: 'DB_ERROR',
      status: 500,
    });
  });
});

describe('listHandshakes — returns empty when no party rows for actor', () => {
  it('returns empty when actor has no party memberships', async () => {
    const partiesChain = makeChain({ data: [], error: null });
    mockSupabase.from.mockReturnValue(partiesChain);

    const result = await listHandshakes({}, 'actor-no-parties');
    expect(result).toEqual({ handshakes: [] });
  });
});

describe('listHandshakes — filters by status and mode (line 149)', () => {
  it('applies status and mode filters when provided', async () => {
    const partiesChain = makeChain({ data: [{ handshake_id: 'hs-1' }], error: null });

    const eqMock = vi.fn().mockImplementation(function() { return this; });

    const queryChain = {
      select: vi.fn().mockReturnThis(),
      order: vi.fn().mockReturnThis(),
      limit: vi.fn().mockReturnThis(),
      in: vi.fn().mockReturnThis(),
      eq: eqMock,
      then: (resolve) =>
        Promise.resolve({ data: [{ handshake_id: 'hs-1', status: 'verified', mode: 'basic' }], error: null }).then(resolve),
    };

    mockSupabase.from.mockImplementation((table) => {
      if (table === 'handshake_parties') return partiesChain;
      return queryChain;
    });

    const result = await listHandshakes({ status: 'verified', mode: 'basic' }, 'actor-1');
    expect(eqMock).toHaveBeenCalledWith('status', 'verified');
    expect(eqMock).toHaveBeenCalledWith('mode', 'basic');
    expect(result.handshakes).toBeDefined();
  });
});
