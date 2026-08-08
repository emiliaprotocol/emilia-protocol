// SPDX-License-Identifier: Apache-2.0

import { beforeEach, describe, expect, it, vi } from 'vitest';

const mockAuthenticateOperator = vi.fn();
const mockGetGuardedClient = vi.fn();
const mockProtocolWrite = vi.fn();

vi.mock('@/lib/operator-auth', () => ({
  authenticateOperator: (...args: unknown[]) => mockAuthenticateOperator(...args),
}));

vi.mock('@/lib/write-guard', () => ({
  getGuardedClient: (...args: unknown[]) => mockGetGuardedClient(...args),
}));

vi.mock('@/lib/protocol-write', () => ({
  COMMAND_TYPES: {
    EXPIRE_RECEIPTS: 'expire_receipts',
    ESCALATE_DISPUTES: 'escalate_disputes',
    EXPIRE_CONTINUITY_CLAIMS: 'expire_continuity_claims',
  },
  protocolWrite: (...args: unknown[]) => mockProtocolWrite(...args),
}));

import { GET } from '../app/api/cron/expire/route.js';

function selectedRows(rows: unknown[]) {
  return {
    select: vi.fn().mockReturnThis(),
    eq: vi.fn().mockReturnThis(),
    in: vi.fn().mockReturnThis(),
    lt: vi.fn().mockReturnThis(),
    is: vi.fn().mockReturnThis(),
    then: (resolve: (value: unknown) => unknown) => Promise.resolve({ data: rows, error: null }).then(resolve),
  };
}

beforeEach(() => {
  vi.clearAllMocks();
  mockAuthenticateOperator.mockResolvedValue({ valid: true, operator_id: '_legacy_cron' });
});

describe('cron expiry route commit-time accounting', () => {
  it('reports committed transitions rather than stale pre-selection counts', async () => {
    const tables: Record<string, ReturnType<typeof selectedRows>> = {
      receipts: selectedRows([{ receipt_id: 'r-raced' }]),
      disputes: selectedRows([{ dispute_id: 'd-raced' }]),
      continuity_claims: selectedRows([{ continuity_id: 'c-raced' }]),
    };
    mockGetGuardedClient.mockReturnValue({
      from: vi.fn((table: string) => tables[table]),
      rpc: vi.fn().mockResolvedValue({ data: 0, error: null }),
    });
    mockProtocolWrite
      .mockResolvedValueOnce({ expired: 0, receipt_ids: [] })
      .mockResolvedValueOnce({ escalated: 0, dispute_ids: [] })
      .mockResolvedValueOnce({ expired: 0, continuity_ids: [] });

    const response = await GET(new Request('https://example.test/api/cron/expire') as any);
    expect(response.status).toBe(200);
    await expect(response.json()).resolves.toMatchObject({
      bilateral_expired: 0,
      disputes_escalated: 0,
      continuity_expired: 0,
    });
    expect(mockProtocolWrite).toHaveBeenCalledTimes(3);
  });
});
