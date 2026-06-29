// SPDX-License-Identifier: Apache-2.0

import { describe, it, expect, vi, beforeEach } from 'vitest';

const mockCheckRateLimit = vi.fn();

vi.mock('@/lib/rate-limit', () => ({
  checkRateLimit: (...args) => mockCheckRateLimit(...args),
  getClientIP: () => '203.0.113.9',
  RATE_LIMITS: {
    submit: { max: 60, window: 60 },
    read: { max: 120, window: 60 },
    register: { max: 10, window: 60 },
  },
}));

vi.mock('@/lib/siem', () => ({
  siemEvent: vi.fn(),
}));

const { middleware } = await import('../middleware.js');

function req(path, { method = 'POST', headers = {} } = {}) {
  const url = `https://www.emiliaprotocol.ai${path}`;
  return {
    method,
    nextUrl: new URL(url),
    headers: new Headers(headers),
  };
}

describe('middleware API body-size tripwire', () => {
  beforeEach(() => {
    mockCheckRateLimit.mockReset();
    mockCheckRateLimit.mockResolvedValue({ allowed: true, remaining: 59, reset: 60 });
  });

  it('rejects declared oversized JSON API bodies before rate limiting', async () => {
    const res = await middleware(req('/api/receipt', {
      headers: {
        'content-type': 'application/json',
        'content-length': String(1024 * 1024 + 1),
      },
    }));

    expect(res.status).toBe(413);
    expect(mockCheckRateLimit).not.toHaveBeenCalled();
    expect(await res.json()).toMatchObject({ code: 'payload_too_large', max_bytes: 1024 * 1024 });
  });

  it('keeps multipart upload envelope separate from JSON/API body cap', async () => {
    const allowed = await middleware(req('/api/trust-desk/intake', {
      headers: {
        'content-type': 'multipart/form-data; boundary=x',
        'content-length': String(2 * 1024 * 1024),
      },
    }));
    expect(allowed.status).not.toBe(413);
    expect(mockCheckRateLimit).toHaveBeenCalledOnce();

    mockCheckRateLimit.mockClear();
    const denied = await middleware(req('/api/trust-desk/intake', {
      headers: {
        'content-type': 'multipart/form-data; boundary=x',
        'content-length': String(26 * 1024 * 1024 + 1),
      },
    }));

    expect(denied.status).toBe(413);
    expect(mockCheckRateLimit).not.toHaveBeenCalled();
  });
});
