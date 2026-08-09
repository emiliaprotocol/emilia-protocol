// SPDX-License-Identifier: Apache-2.0

import { beforeEach, describe, expect, it, vi } from 'vitest';

const mocks = vi.hoisted(() => ({
  authenticateOperator: vi.fn(),
  authenticateRequest: vi.fn(),
  getGuardedClient: vi.fn(),
  adjudicateDispute: vi.fn(),
}));

vi.mock('@/lib/operator-auth', () => ({ authenticateOperator: mocks.authenticateOperator }));
vi.mock('@/lib/supabase', () => ({ authenticateRequest: mocks.authenticateRequest }));
vi.mock('@/lib/write-guard', () => ({ getGuardedClient: mocks.getGuardedClient }));
vi.mock('@/lib/dispute-adjudication', () => ({ adjudicateDispute: mocks.adjudicateDispute }));
vi.mock('@/lib/logger.js', () => ({
  logger: { info: vi.fn(), warn: vi.fn(), error: vi.fn(), debug: vi.fn() },
}));

const { POST } = await import('../app/api/disputes/[disputeId]/adjudicate/route.js');

beforeEach(() => {
  vi.clearAllMocks();
  mocks.getGuardedClient.mockReturnValue({ from: vi.fn() });
});

describe('dispute adjudication operator authority', () => {
  it('does not treat every named operator as authorized to adjudicate', async () => {
    mocks.authenticateOperator.mockResolvedValue({
      valid: true,
      operator_id: 'host-verifier-1',
      role: 'host_verifier',
    });

    const response = await POST(
      new Request('https://www.emiliaprotocol.ai/api/disputes/d-1/adjudicate', {
        method: 'POST',
        headers: { authorization: 'Bearer request-bound-token' },
      }) as any,
      { params: Promise.resolve({ disputeId: 'd-1' }) },
    );

    expect(response.status).toBe(403);
    expect(mocks.authenticateRequest).not.toHaveBeenCalled();
    expect(mocks.adjudicateDispute).not.toHaveBeenCalled();
  });
});
