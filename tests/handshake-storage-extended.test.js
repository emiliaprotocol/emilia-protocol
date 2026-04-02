/**
 * lib/handshake/storage.js — extended coverage.
 *
 * Targets uncovered lines:
 *   35-37  fetchPresentations — returns empty array on null data
 *   131-137 insertResult — error path throws HandshakeError
 */

import { describe, it, expect, vi, beforeEach } from 'vitest';

const mockGetServiceClient = vi.fn();

vi.mock('../lib/supabase.js', () => ({
  getServiceClient: (...args) => mockGetServiceClient(...args),
}));

import {
  fetchPresentations,
  insertResult,
  updateHandshakeStatus,
} from '../lib/handshake/storage.js';

// ── fetchPresentations ────────────────────────────────────────────────────────

describe('fetchPresentations', () => {
  beforeEach(() => { vi.clearAllMocks(); });

  it('returns presentations array on success', async () => {
    const presentations = [{ id: 'pres-1', handshake_id: 'hs-1' }];
    const from = vi.fn().mockReturnValue({
      select: vi.fn().mockReturnValue({
        eq: vi.fn().mockResolvedValue({ data: presentations, error: null }),
      }),
    });
    mockGetServiceClient.mockReturnValue({ from });

    const result = await fetchPresentations('hs-1');
    expect(result).toEqual(presentations);
  });

  it('returns empty array when no presentations found (null data)', async () => {
    // Lines 35-37: the `res.data || []` fallback
    const from = vi.fn().mockReturnValue({
      select: vi.fn().mockReturnValue({
        eq: vi.fn().mockResolvedValue({ data: null, error: null }),
      }),
    });
    mockGetServiceClient.mockReturnValue({ from });

    const result = await fetchPresentations('hs-none');
    expect(result).toEqual([]);
  });

  it('returns empty array when data is empty array', async () => {
    const from = vi.fn().mockReturnValue({
      select: vi.fn().mockReturnValue({
        eq: vi.fn().mockResolvedValue({ data: [], error: null }),
      }),
    });
    mockGetServiceClient.mockReturnValue({ from });

    const result = await fetchPresentations('hs-empty');
    expect(result).toEqual([]);
  });
});

// ── insertResult ──────────────────────────────────────────────────────────────

describe('insertResult', () => {
  beforeEach(() => { vi.clearAllMocks(); });

  it('succeeds with a valid result record', async () => {
    const from = vi.fn().mockReturnValue({
      insert: vi.fn().mockResolvedValue({ data: null, error: null }),
    });
    mockGetServiceClient.mockReturnValue({ from });

    await expect(
      insertResult({ handshake_id: 'hs-1', outcome: 'accepted' })
    ).resolves.not.toThrow();
  });

  it('throws HandshakeError on insert failure — lines 131-137', async () => {
    // Lines 131-137: error path in insertResult
    const from = vi.fn().mockReturnValue({
      insert: vi.fn().mockResolvedValue({
        data: null,
        error: { message: 'unique constraint violation' },
      }),
    });
    mockGetServiceClient.mockReturnValue({ from });

    await expect(insertResult({ handshake_id: 'hs-1' })).rejects.toMatchObject({
      code: 'DB_ERROR',
      status: 500,
    });
  });
});

// ── updateHandshakeStatus with no statusFilter — extra branch ─────────────────

describe('updateHandshakeStatus — without statusFilter', () => {
  beforeEach(() => { vi.clearAllMocks(); });

  it('does not apply eq(status) when statusFilter is null', async () => {
    const eqMock = vi.fn().mockResolvedValue({ data: null, error: null });
    const from = vi.fn().mockReturnValue({
      update: vi.fn().mockReturnValue({ eq: eqMock }),
    });
    mockGetServiceClient.mockReturnValue({ from });

    await updateHandshakeStatus('hs-1', { status: 'verified' }, null);
    // Only one eq call for handshake_id — NOT for status
    expect(eqMock).toHaveBeenCalledWith('handshake_id', 'hs-1');
    expect(eqMock).not.toHaveBeenCalledWith('status', expect.anything());
  });
});
