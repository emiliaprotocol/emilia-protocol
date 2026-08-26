// SPDX-License-Identifier: Apache-2.0

import { beforeEach, describe, expect, it, vi } from 'vitest';

const mocks = vi.hoisted(() => ({
  afterCallbacks: [] as Array<() => Promise<void>>,
  putEngagement: vi.fn(),
  runPipeline: vi.fn(),
}));

vi.mock('next/server', async () => {
  const actual = await vi.importActual<typeof import('next/server')>('next/server');
  return {
    ...actual,
    after: (callback: () => Promise<void>) => {
      mocks.afterCallbacks.push(callback);
    },
  };
});

vi.mock('@/lib/trust-desk/ids', () => ({
  newEngagementId: () => 'td_test_public_budget',
  deriveSlug: () => 'acme-td-test',
}));

vi.mock('@/lib/trust-desk/store', () => ({
  putEngagement: (...args: unknown[]) => mocks.putEngagement(...args),
  STATUS: {
    INTAKE_RECEIVED: 'intake_received',
  },
}));

vi.mock('@/lib/trust-desk/pipeline', () => ({
  runPipeline: (...args: unknown[]) => mocks.runPipeline(...args),
}));

const { POST } = await import('../app/api/trust-desk/intake/route.ts');

describe('Trust Desk public intake resource profile', () => {
  beforeEach(() => {
    mocks.afterCallbacks.length = 0;
    mocks.putEngagement.mockReset().mockResolvedValue(undefined);
    mocks.runPipeline.mockReset().mockResolvedValue({ outcome: 'awaiting_review' });
  });

  it('passes the narrow anonymous LLM budget into deferred pipeline work', async () => {
    const request = new Request('https://www.emiliaprotocol.ai/api/trust-desk/intake', {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({
        company: 'Acme AI',
        contact_email: 'security@acme.example',
        selling_into: 'financial_services',
        questionnaire_text: 'Do you govern consequential AI actions?',
      }),
    });

    const response = await POST(request as any);
    expect(response.status).toBe(200);
    expect(mocks.afterCallbacks).toHaveLength(1);

    await mocks.afterCallbacks[0]();

    expect(mocks.runPipeline).toHaveBeenCalledOnce();
    expect(mocks.runPipeline.mock.calls[0][0]).toMatchObject({
      engagement: {
        engagement_id: 'td_test_public_budget',
        questionnaire_content: 'Do you govern consequential AI actions?',
      },
      llmBudgetOptions: {
        maxCalls: 6,
        maxEstimatedTokens: 12_000,
        maxWallClockMs: 20_000,
      },
    });
  });
});
