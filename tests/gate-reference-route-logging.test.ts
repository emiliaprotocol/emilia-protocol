// SPDX-License-Identifier: Apache-2.0

import { beforeEach, describe, expect, it, vi } from 'vitest';

const mocks = vi.hoisted(() => ({
  runGateReferenceLab: vi.fn(),
  loggerError: vi.fn(),
}));

vi.mock('@/lib/gate/reference-lab.js', () => ({
  GATE_REFERENCE_PROFILES: { treasury: {} },
  runGateReferenceLab: mocks.runGateReferenceLab,
}));

vi.mock('@/lib/rate-limit.js', () => ({
  checkRateLimit: async () => ({ allowed: true, remaining: 10, reset: 60 }),
  getClientIP: () => '203.0.113.9',
}));

vi.mock('@/lib/logger.js', () => ({
  logger: { error: mocks.loggerError },
}));

beforeEach(() => {
  vi.clearAllMocks();
});

describe('GET /api/v1/gate/reference-scenario failure handling', () => {
  it('keeps the public response opaque while logging the operator diagnostic', async () => {
    mocks.runGateReferenceLab.mockRejectedValue(new Error('key generation failed'));
    const { GET } = await import('../app/api/v1/gate/reference-scenario/route.js');

    const response = await GET(new Request('https://ep.test/api/v1/gate/reference-scenario?profile=treasury'));

    expect(response.status).toBe(503);
    await expect(response.json()).resolves.toEqual({ ok: false, error: 'gate_reference_scenario_failed' });
    expect(mocks.loggerError).toHaveBeenCalledWith('gate reference scenario failed', {
      profile: 'treasury',
      error: 'key generation failed',
    });
  });
});
