// SPDX-License-Identifier: Apache-2.0

import { beforeEach, describe, expect, it, vi } from 'vitest';

const mocks = vi.hoisted(() => ({
  readiness: vi.fn(),
}));

vi.mock('@/lib/agent-record/runtime-readiness', () => ({
  getAgentRecordRuntimeReadiness: mocks.readiness,
}));

const Health = await import('../app/api/health/route');
const Live = await import('../app/api/live/route');

describe('application liveness and readiness HTTP contract', () => {
  beforeEach(() => {
    mocks.readiness.mockReset();
  });

  it('returns an exact non-disclosing 200 only when runtime dependencies are ready', async () => {
    mocks.readiness.mockResolvedValue({
      ready: true,
      checks: {
        signing_key: true,
        durable_rate_limiting: true,
        database_configuration: true,
        database_creation_authorization: true,
        database_rpcs: true,
      },
    });

    const response = await Health.GET();

    expect(response.status).toBe(200);
    expect(await response.json()).toEqual({ status: 'ready' });
    expect(response.headers.get('cache-control')).toBe('no-store, no-cache, must-revalidate');
  });

  it('fails closed with an exact non-disclosing 503 on false or thrown readiness', async () => {
    for (const result of [
      { kind: 'result', value: { ready: false, unavailable: ['database_rpcs'] } },
      { kind: 'error', value: new Error('database detail must not escape') },
    ] as const) {
      if (result.kind === 'result') mocks.readiness.mockResolvedValueOnce(result.value);
      else mocks.readiness.mockRejectedValueOnce(result.value);

      const response = await Health.GET();

      expect(response.status).toBe(503);
      expect(await response.json()).toEqual({ status: 'not_ready' });
      expect(response.headers.get('cache-control')).toBe('no-store, no-cache, must-revalidate');
    }
  });

  it('keeps process liveness independent from database readiness', async () => {
    mocks.readiness.mockRejectedValue(new Error('database offline'));

    const response = await Live.GET();

    expect(response.status).toBe(200);
    expect(await response.json()).toEqual({ status: 'live' });
    expect(response.headers.get('cache-control')).toBe('no-store, no-cache, must-revalidate');
    expect(mocks.readiness).not.toHaveBeenCalled();
  });
});
