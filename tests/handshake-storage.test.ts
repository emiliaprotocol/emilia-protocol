/**
 * Tests for lib/handshake/storage.js
 *
 * Covers all exported functions:
 *   fetchHandshake, fetchParties, fetchPresentations, fetchBinding,
 *   fetchResult, fetchPartyByRole, fetchAuthority,
 *   insertHandshake, insertParties, insertBinding, insertPresentation,
 *   insertResult, updateHandshakeStatus, updatePartyStatus
 *
 * @license Apache-2.0
 */

import { describe, it, expect, vi, beforeEach } from 'vitest';
import crypto from 'crypto';

// ── Mock: Supabase ────────────────────────────────────────────────────────────

const mockGetServiceClient = vi.fn();

vi.mock('../lib/supabase.js', () => ({
  getServiceClient: (...args) => mockGetServiceClient(...args),
}));

// ── Import under test (after mocks) ──────────────────────────────────────────

import {
  fetchHandshake,
  fetchParties,
  fetchPresentations,
  fetchBinding,
  fetchResult,
  fetchPartyByRole,
  fetchAuthority,
  insertHandshake,
  insertParties,
  insertBinding,
  insertPresentation,
  insertResult,
  updateHandshakeStatus,
  updatePartyStatus,
} from '../lib/handshake/storage.js';

import { HandshakeError } from '../lib/handshake/errors.js';

// ── Mock builder ──────────────────────────────────────────────────────────────

function buildSelectChain({ data = null, error = null } = {}) {
  const chain = {
    select: vi.fn().mockReturnThis(),
    eq: vi.fn().mockReturnThis(),
    maybeSingle: vi.fn().mockResolvedValue({ data, error }),
    single: vi.fn().mockResolvedValue({ data, error }),
  };
  // For array results (fetchParties, fetchPresentations)
  chain.then = (resolve, reject) =>
    Promise.resolve({ data: Array.isArray(data) ? data : (data ? [data] : []), error }).then(resolve, reject);
  return chain;
}

function buildInsertChain({ data = null, error = null } = {}) {
  const chain = {
    insert: vi.fn().mockReturnThis(),
    select: vi.fn().mockReturnThis(),
    single: vi.fn().mockResolvedValue({ data, error }),
    then: (resolve, reject) =>
      Promise.resolve({ data: null, error }).then(resolve, reject),
  };
  return chain;
}

function buildUpdateChain({ data = null, error = null } = {}) {
  const chain = {
    update: vi.fn().mockReturnThis(),
    eq: vi.fn().mockReturnThis(),
    then: (resolve, reject) =>
      Promise.resolve({ data, error }).then(resolve, reject),
  };
  return chain;
}

// ── Read operations ───────────────────────────────────────────────────────────

describe('fetchHandshake', () => {
  beforeEach(() => { vi.clearAllMocks(); });

  it('returns handshake data on success', async () => {
    const hs = { handshake_id: 'hs-1', status: 'verified' };
    const from = vi.fn().mockReturnValue({
      select: vi.fn().mockReturnValue({
        eq: vi.fn().mockReturnValue({
          maybeSingle: vi.fn().mockResolvedValue({ data: hs, error: null }),
        }),
      }),
    });
    mockGetServiceClient.mockReturnValue({ from });

    const result = await fetchHandshake('hs-1');
    expect(result).toEqual(hs);
  });

  it('returns null when handshake does not exist', async () => {
    const from = vi.fn().mockReturnValue({
      select: vi.fn().mockReturnValue({
        eq: vi.fn().mockReturnValue({
          maybeSingle: vi.fn().mockResolvedValue({ data: null, error: null }),
        }),
      }),
    });
    mockGetServiceClient.mockReturnValue({ from });

    const result = await fetchHandshake('hs-missing');
    expect(result).toBeNull();
  });

  it('throws HandshakeError DB_ERROR on fetch failure', async () => {
    const from = vi.fn().mockReturnValue({
      select: vi.fn().mockReturnValue({
        eq: vi.fn().mockReturnValue({
          maybeSingle: vi.fn().mockResolvedValue({ data: null, error: { message: 'timeout' } }),
        }),
      }),
    });
    mockGetServiceClient.mockReturnValue({ from });

    await expect(fetchHandshake('hs-1'))
      .rejects.toMatchObject({ code: 'DB_ERROR', status: 500 });
  });

  it('queries handshakes table with specific columns when columns param provided', async () => {
    const from = vi.fn().mockReturnValue({
      select: vi.fn().mockReturnValue({
        eq: vi.fn().mockReturnValue({
          maybeSingle: vi.fn().mockResolvedValue({ data: { handshake_id: 'hs-1' }, error: null }),
        }),
      }),
    });
    mockGetServiceClient.mockReturnValue({ from });

    await fetchHandshake('hs-1', 'handshake_id,status');
    expect(from).toHaveBeenCalledWith('handshakes');
  });
});

describe('fetchParties', () => {
  beforeEach(() => { vi.clearAllMocks(); });

  it('returns parties array on success', async () => {
    const parties = [{ id: 1, handshake_id: 'hs-1', party_role: 'initiator' }];
    const from = vi.fn().mockReturnValue({
      select: vi.fn().mockReturnValue({
        eq: vi.fn().mockResolvedValue({ data: parties, error: null }),
      }),
    });
    mockGetServiceClient.mockReturnValue({ from });

    const result = await fetchParties('hs-1');
    expect(result).toEqual(parties);
  });

  it('returns empty array when no parties found', async () => {
    const from = vi.fn().mockReturnValue({
      select: vi.fn().mockReturnValue({
        eq: vi.fn().mockResolvedValue({ data: null, error: null }),
      }),
    });
    mockGetServiceClient.mockReturnValue({ from });

    const result = await fetchParties('hs-none');
    expect(result).toEqual([]);
  });
});

describe('fetchBinding', () => {
  beforeEach(() => { vi.clearAllMocks(); });

  it('returns binding when found', async () => {
    const binding = { handshake_id: 'hs-1', binding_hash: 'sha256-abc' };
    const from = vi.fn().mockReturnValue({
      select: vi.fn().mockReturnValue({
        eq: vi.fn().mockReturnValue({
          maybeSingle: vi.fn().mockResolvedValue({ data: binding, error: null }),
        }),
      }),
    });
    mockGetServiceClient.mockReturnValue({ from });

    const result = await fetchBinding('hs-1');
    expect(result.binding_hash).toBe('sha256-abc');
  });

  it('returns null when binding not found', async () => {
    const from = vi.fn().mockReturnValue({
      select: vi.fn().mockReturnValue({
        eq: vi.fn().mockReturnValue({
          maybeSingle: vi.fn().mockResolvedValue({ data: null, error: null }),
        }),
      }),
    });
    mockGetServiceClient.mockReturnValue({ from });

    const result = await fetchBinding('hs-none');
    expect(result).toBeNull();
  });
});

describe('fetchPartyByRole', () => {
  beforeEach(() => { vi.clearAllMocks(); });

  it('returns party when found by role', async () => {
    const party = { id: 42, party_role: 'initiator' };
    const from = vi.fn().mockReturnValue({
      select: vi.fn().mockReturnValue({
        eq: vi.fn().mockReturnValue({
          eq: vi.fn().mockReturnValue({
            maybeSingle: vi.fn().mockResolvedValue({ data: party, error: null }),
          }),
        }),
      }),
    });
    mockGetServiceClient.mockReturnValue({ from });

    const result = await fetchPartyByRole('hs-1', 'initiator');
    expect(result.party_role).toBe('initiator');
  });

  it('throws HandshakeError on DB error', async () => {
    const from = vi.fn().mockReturnValue({
      select: vi.fn().mockReturnValue({
        eq: vi.fn().mockReturnValue({
          eq: vi.fn().mockReturnValue({
            maybeSingle: vi.fn().mockResolvedValue({ data: null, error: { message: 'db error' } }),
          }),
        }),
      }),
    });
    mockGetServiceClient.mockReturnValue({ from });

    await expect(fetchPartyByRole('hs-1', 'initiator'))
      .rejects.toMatchObject({ code: 'DB_ERROR' });
  });
});

describe('fetchAuthority', () => {
  beforeEach(() => { vi.clearAllMocks(); });

  it('returns data and error directly (no throw)', async () => {
    const authority = { authority_id: 'auth-1', status: 'active' };
    const from = vi.fn().mockReturnValue({
      select: vi.fn().mockReturnValue({
        eq: vi.fn().mockReturnValue({
          maybeSingle: vi.fn().mockResolvedValue({ data: authority, error: null }),
        }),
      }),
    });
    mockGetServiceClient.mockReturnValue({ from });

    const result = await fetchAuthority('key-ref-1');
    expect(result.data.authority_id).toBe('auth-1');
    expect(result.error).toBeNull();
  });
});

// ── Write operations ──────────────────────────────────────────────────────────

describe('insertHandshake', () => {
  beforeEach(() => { vi.clearAllMocks(); });

  it('returns inserted handshake on success', async () => {
    const record = { handshake_id: 'hs-new', status: 'pending' };
    const from = vi.fn().mockReturnValue({
      insert: vi.fn().mockReturnValue({
        select: vi.fn().mockReturnValue({
          single: vi.fn().mockResolvedValue({ data: record, error: null }),
        }),
      }),
    });
    mockGetServiceClient.mockReturnValue({ from });

    const result = await insertHandshake({ status: 'pending' });
    expect(result.handshake_id).toBe('hs-new');
  });

  it('throws HandshakeError on insert failure', async () => {
    const from = vi.fn().mockReturnValue({
      insert: vi.fn().mockReturnValue({
        select: vi.fn().mockReturnValue({
          single: vi.fn().mockResolvedValue({ data: null, error: { message: 'insert failed' } }),
        }),
      }),
    });
    mockGetServiceClient.mockReturnValue({ from });

    await expect(insertHandshake({}))
      .rejects.toMatchObject({ code: 'DB_ERROR', status: 500 });
  });
});

describe('insertParties', () => {
  beforeEach(() => { vi.clearAllMocks(); });

  it('succeeds with valid party records', async () => {
    const from = vi.fn().mockReturnValue({
      insert: vi.fn().mockResolvedValue({ data: null, error: null }),
    });
    mockGetServiceClient.mockReturnValue({ from });

    await expect(insertParties([{ handshake_id: 'hs-1', party_role: 'initiator' }]))
      .resolves.not.toThrow();
  });

  it('throws HandshakeError on insert failure', async () => {
    const from = vi.fn().mockReturnValue({
      insert: vi.fn().mockResolvedValue({ data: null, error: { message: 'constraint violation' } }),
    });
    mockGetServiceClient.mockReturnValue({ from });

    await expect(insertParties([{}]))
      .rejects.toMatchObject({ code: 'DB_ERROR' });
  });
});

describe('insertBinding', () => {
  beforeEach(() => { vi.clearAllMocks(); });

  it('succeeds with a valid binding record', async () => {
    const from = vi.fn().mockReturnValue({
      insert: vi.fn().mockResolvedValue({ data: null, error: null }),
    });
    mockGetServiceClient.mockReturnValue({ from });

    await expect(insertBinding({ handshake_id: 'hs-1', binding_hash: 'sha256-abc' }))
      .resolves.not.toThrow();
  });

  it('throws HandshakeError on insert failure', async () => {
    const from = vi.fn().mockReturnValue({
      insert: vi.fn().mockResolvedValue({ data: null, error: { message: 'duplicate key' } }),
    });
    mockGetServiceClient.mockReturnValue({ from });

    await expect(insertBinding({}))
      .rejects.toMatchObject({ code: 'DB_ERROR' });
  });
});

describe('insertPresentation', () => {
  beforeEach(() => { vi.clearAllMocks(); });

  it('returns inserted presentation record on success', async () => {
    const pres = { id: 'pres-1', handshake_id: 'hs-1' };
    const from = vi.fn().mockReturnValue({
      insert: vi.fn().mockReturnValue({
        select: vi.fn().mockReturnValue({
          single: vi.fn().mockResolvedValue({ data: pres, error: null }),
        }),
      }),
    });
    mockGetServiceClient.mockReturnValue({ from });

    const result = await insertPresentation({ handshake_id: 'hs-1' });
    expect(result.id).toBe('pres-1');
  });

  it('throws HandshakeError on insert failure', async () => {
    const from = vi.fn().mockReturnValue({
      insert: vi.fn().mockReturnValue({
        select: vi.fn().mockReturnValue({
          single: vi.fn().mockResolvedValue({ data: null, error: { message: 'error' } }),
        }),
      }),
    });
    mockGetServiceClient.mockReturnValue({ from });

    await expect(insertPresentation({}))
      .rejects.toMatchObject({ code: 'DB_ERROR' });
  });
});

describe('updateHandshakeStatus', () => {
  beforeEach(() => { vi.clearAllMocks(); });

  it('succeeds with valid update', async () => {
    const from = vi.fn().mockReturnValue({
      update: vi.fn().mockReturnValue({
        eq: vi.fn().mockResolvedValue({ data: null, error: null }),
      }),
    });
    mockGetServiceClient.mockReturnValue({ from });

    await expect(updateHandshakeStatus('hs-1', { status: 'verified' }))
      .resolves.not.toThrow();
  });

  it('applies optional statusFilter when provided', async () => {
    const eqFn = vi.fn().mockImplementation(() => {
      // Allow chaining: each eq call returns an object with eq and then
      return {
        eq: eqFn,
        then: (resolve, reject) => Promise.resolve({ data: null, error: null }).then(resolve, reject),
      };
    });
    const updateFn = vi.fn().mockReturnValue({ eq: eqFn });
    const from = vi.fn().mockReturnValue({ update: updateFn });
    mockGetServiceClient.mockReturnValue({ from });

    await updateHandshakeStatus('hs-1', { status: 'verified' }, 'pending');
    // Two eq calls: one for handshake_id, one for status filter
    expect(eqFn).toHaveBeenCalledWith('status', 'pending');
  });

  it('throws HandshakeError on update failure', async () => {
    const from = vi.fn().mockReturnValue({
      update: vi.fn().mockReturnValue({
        eq: vi.fn().mockResolvedValue({ data: null, error: { message: 'write error' } }),
      }),
    });
    mockGetServiceClient.mockReturnValue({ from });

    await expect(updateHandshakeStatus('hs-1', { status: 'verified' }))
      .rejects.toMatchObject({ code: 'DB_ERROR' });
  });
});

describe('updatePartyStatus', () => {
  beforeEach(() => { vi.clearAllMocks(); });

  it('calls update on handshake_parties with correct party id', async () => {
    const from = vi.fn().mockReturnValue({
      update: vi.fn().mockReturnValue({
        eq: vi.fn().mockResolvedValue({ data: null, error: null }),
      }),
    });
    mockGetServiceClient.mockReturnValue({ from });

    await updatePartyStatus(99, { status: 'verified' });
    expect(from).toHaveBeenCalledWith('handshake_parties');
  });
});

describe('fetchResult', () => {
  beforeEach(() => { vi.clearAllMocks(); });

  it('returns result when found', async () => {
    const resultRow = { handshake_id: 'hs-1', outcome: 'verified' };
    const from = vi.fn().mockReturnValue({
      select: vi.fn().mockReturnValue({
        eq: vi.fn().mockReturnValue({
          maybeSingle: vi.fn().mockResolvedValue({ data: resultRow, error: null }),
        }),
      }),
    });
    mockGetServiceClient.mockReturnValue({ from });

    const result = await fetchResult('hs-1');
    expect(result.outcome).toBe('verified');
  });

  it('returns null when result not found', async () => {
    const from = vi.fn().mockReturnValue({
      select: vi.fn().mockReturnValue({
        eq: vi.fn().mockReturnValue({
          maybeSingle: vi.fn().mockResolvedValue({ data: null, error: null }),
        }),
      }),
    });
    mockGetServiceClient.mockReturnValue({ from });

    const result = await fetchResult('hs-none');
    expect(result).toBeNull();
  });
});
