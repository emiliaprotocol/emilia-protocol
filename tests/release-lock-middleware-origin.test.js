// SPDX-License-Identifier: Apache-2.0

import { beforeEach, describe, expect, it, vi } from 'vitest';

const checkRateLimit = vi.hoisted(() => vi.fn());

vi.mock('@/lib/rate-limit', () => ({
  checkRateLimit: (...args) => checkRateLimit(...args),
  getClientIP: () => '203.0.113.10',
  RATE_LIMITS: {
    mobile_pairing: { max: 20, window: 60 },
    mobile_runtime_ip: { max: 60, window: 60 },
    read: { max: 120, window: 60 },
  },
}));

vi.mock('@/lib/siem', () => ({
  siemEvent: vi.fn(),
}));

const { middleware } = await import('../middleware.js');

function request(path, { origin, fetchSite } = {}) {
  const url = `https://www.emiliaprotocol.ai${path}`;
  const headers = new Headers();
  if (origin !== undefined) headers.set('origin', origin);
  if (fetchSite !== undefined) headers.set('sec-fetch-site', fetchSite);
  return {
    method: 'POST',
    nextUrl: new URL(url),
    headers,
    body: null,
  };
}

describe('Release Lock middleware origin boundary', () => {
  beforeEach(() => {
    checkRateLimit.mockReset();
    checkRateLimit.mockResolvedValue({ allowed: true, remaining: 19, reset: 60 });
  });

  it('refuses sibling-origin challenge and pairing mutations before rate limiting', async () => {
    for (const path of [
      `/api/v1/release-locks/rlk_${'a'.repeat(32)}/registration/options`,
      `/api/v1/release-locks/rlk_${'a'.repeat(32)}/rounds/co-accepted/pairings`,
      '/api/v1/release-locks/pairings/exchange',
    ]) {
      const response = await middleware(request(path, {
        origin: 'https://attacker.emiliaprotocol.ai',
        fetchSite: 'same-site',
      }));
      expect(response.status).toBe(403);
      expect(await response.json()).toMatchObject({
        code: 'release_lock_origin_denied',
      });
    }
    expect(checkRateLimit).not.toHaveBeenCalled();
  });

  it('requires an Origin header and allows the exact application origin', async () => {
    const missing = await middleware(request(
      '/api/v1/release-locks/invitations/exchange',
    ));
    expect(missing.status).toBe(403);

    const allowed = await middleware(request(
      '/api/v1/release-locks/invitations/exchange',
      {
        origin: 'https://www.emiliaprotocol.ai',
        fetchSite: 'same-origin',
      },
    ));
    expect(allowed.status).not.toBe(403);
    expect(checkRateLimit).toHaveBeenCalledOnce();
  });
});
