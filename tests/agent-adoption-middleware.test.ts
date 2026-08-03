// SPDX-License-Identifier: Apache-2.0

import { beforeEach, describe, expect, it, vi } from 'vitest';

const mocks = vi.hoisted(() => ({
  checkRateLimit: vi.fn(),
  siemEvent: vi.fn(),
}));

vi.mock('@/lib/rate-limit', () => ({
  checkRateLimit: (...args: unknown[]) => mocks.checkRateLimit(...args),
  getClientIP: () => '203.0.113.44',
  RATE_LIMITS: {
    register: { max: 10, window: 3600 },
    submit: { max: 30, window: 60 },
    pilot_request: { max: 5, window: 3600 },
    public_verify: { max: 60, window: 60 },
    read: { max: 120, window: 60 },
  },
}));

vi.mock('@/lib/siem', () => ({
  siemEvent: (...args: unknown[]) => mocks.siemEvent(...args),
}));

const { middleware } = await import('../middleware.ts');

function request(
  path: string,
  {
    method = 'GET',
    headers = {},
    onClone = () => {},
  }: {
    method?: string;
    headers?: Record<string, string>;
    onClone?: () => void;
  } = {},
) {
  const url = new URL(`https://www.emiliaprotocol.ai${path}`);
  return {
    method,
    nextUrl: url,
    headers: new Headers(headers),
    body: method === 'GET' ? null : new ReadableStream(),
    clone() {
      onClone();
      throw new Error('middleware must not clone this authenticated body');
    },
  };
}

describe('Agent Adoption middleware security boundaries', () => {
  beforeEach(() => {
    vi.clearAllMocks();
    mocks.checkRateLimit.mockResolvedValue({ allowed: true, remaining: 17, reset: 60 });
  });

  it('rate-limits a protected session mutation without reading its streamed body', async () => {
    const onClone = vi.fn();

    const response = await middleware(request(
      `/api/adopt/sessions/${'1'.repeat(32)}/attempts`,
      {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        onClone,
      },
    ) as never);

    expect(onClone).not.toHaveBeenCalled();
    expect(mocks.checkRateLimit).toHaveBeenCalledOnce();
    expect(mocks.checkRateLimit).toHaveBeenCalledWith('203.0.113.44', 'submit');
    expect(response.headers.get('x-ratelimit-limit')).toBe('30');
    expect(response.headers.get('x-ratelimit-remaining')).toBe('17');
  });

  it('refuses a rate-limited session mutation before reading its streamed body', async () => {
    const onClone = vi.fn();
    mocks.checkRateLimit.mockResolvedValue({ allowed: false, remaining: 0, reset: 23 });

    const response = await middleware(request(
      `/api/adopt/sessions/${'2'.repeat(32)}/passkey/assert/verify`,
      {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        onClone,
      },
    ) as never);

    expect(response.status).toBe(429);
    expect(response.headers.get('retry-after')).toBe('23');
    expect(onClone).not.toHaveBeenCalled();
  });

  it('rate-limits anonymous session creation before consuming a slow body', async () => {
    const onClone = vi.fn();
    mocks.checkRateLimit.mockResolvedValue({ allowed: false, remaining: 0, reset: 31 });

    const response = await middleware(request('/api/adopt/sessions', {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      onClone,
    }) as never);

    expect(response.status).toBe(429);
    expect(mocks.checkRateLimit).toHaveBeenCalledWith('203.0.113.44', 'register');
    expect(onClone).not.toHaveBeenCalled();
  });

  it('still rejects an oversized declared body without touching the stream', async () => {
    const onClone = vi.fn();

    const response = await middleware(request(
      `/api/adopt/sessions/${'3'.repeat(32)}/share`,
      {
        method: 'POST',
        headers: {
          'content-type': 'application/json',
          'content-length': String(1024 * 1024 + 1),
        },
        onClone,
      },
    ) as never);

    expect(response.status).toBe(413);
    expect(onClone).not.toHaveBeenCalled();
  });

  it('meters the public Operating Bond page before the non-API response path', async () => {
    const response = await middleware(request(`/adopt/r/agent_share_${'4'.repeat(40)}`) as never);

    expect(mocks.checkRateLimit).toHaveBeenCalledOnce();
    expect(mocks.checkRateLimit).toHaveBeenCalledWith('203.0.113.44', 'public_verify');
    expect(response.headers.get('x-ratelimit-limit')).toBe('60');
    expect(response.headers.get('x-ratelimit-remaining')).toBe('17');
    expect(response.headers.get('content-security-policy')).toContain("default-src 'self'");
  });

  it('fails the public Operating Bond page closed when its limiter is unavailable', async () => {
    mocks.checkRateLimit.mockResolvedValue({
      allowed: false,
      remaining: 0,
      reset: 60,
      error: 'rate_limit_unavailable',
    });

    const response = await middleware(request(`/adopt/r/agent_share_${'5'.repeat(40)}`) as never);

    expect(response.status).toBe(503);
    expect(await response.json()).toMatchObject({ error: expect.stringContaining('temporarily unavailable') });
  });

  it('fails the page closed on the public_verify fail-open outage sentinel', async () => {
    mocks.checkRateLimit.mockResolvedValue({ allowed: true, remaining: -1, reset: 60 });

    const response = await middleware(request(`/adopt/r/agent_share_${'7'.repeat(40)}`) as never);

    expect(response.status).toBe(503);
    expect(response.headers.get('retry-after')).toBe('60');
  });

  it('returns public verifier rate headers when the page allowance is exhausted', async () => {
    mocks.checkRateLimit.mockResolvedValue({ allowed: false, remaining: 0, reset: 29 });

    const response = await middleware(request(`/adopt/r/agent_share_${'8'.repeat(40)}`) as never);

    expect(response.status).toBe(429);
    expect(response.headers.get('x-ratelimit-limit')).toBe('60');
    expect(response.headers.get('x-ratelimit-remaining')).toBe('0');
    expect(response.headers.get('x-ratelimit-reset')).toBe('29');
    expect(response.headers.get('retry-after')).toBe('29');
  });

  it('keeps the public adoption share API on the public verifier tier', async () => {
    const response = await middleware(request(`/api/adopt/shares/agent_share_${'6'.repeat(40)}`) as never);

    expect(mocks.checkRateLimit).toHaveBeenCalledOnce();
    expect(mocks.checkRateLimit).toHaveBeenCalledWith('203.0.113.44', 'public_verify');
    expect(response.headers.get('x-ratelimit-limit')).toBe('60');
  });

  it('classifies Agent Record creation and revocation as fail-closed submit mutations', async () => {
    const sessionId = '00000000-0000-4000-8000-000000000001';
    const recordId = `agent_record_${'9'.repeat(40)}`;

    for (const path of [
      `/api/adopt/sessions/${sessionId}/records`,
      `/api/agent-records/${recordId}/revoke`,
    ]) {
      mocks.checkRateLimit.mockClear();
      const response = await middleware(request(path, { method: 'POST' }) as never);
      expect(mocks.checkRateLimit).toHaveBeenCalledWith('203.0.113.44', 'submit');
      expect(response.headers.get('x-ratelimit-limit')).toBe('30');
    }
  });

  it('meters exact Agent Record API and page reads as public verification', async () => {
    const recordId = `agent_record_${'a'.repeat(40)}`;
    for (const path of [
      `/api/agent-records/${recordId}`,
      `/agent-record/r/${recordId}`,
    ]) {
      mocks.checkRateLimit.mockClear();
      const response = await middleware(request(path) as never);
      expect(mocks.checkRateLimit).toHaveBeenCalledWith(
        '203.0.113.44',
        'public_verify',
        { requireDurable: true },
      );
      expect(response.headers.get('x-ratelimit-limit')).toBe('60');
    }
  });

  it('fails Agent Record API and page reads closed without a durable production decision', async () => {
    const recordId = `agent_record_${'b'.repeat(40)}`;
    for (const result of [
      { allowed: false, remaining: 0, reset: 60, error: 'durable_rate_limit_required' },
      { allowed: true, remaining: -1, reset: 60 },
    ]) {
      for (const path of [
        `/api/agent-records/${recordId}`,
        `/agent-record/r/${recordId}`,
      ]) {
        mocks.checkRateLimit.mockResolvedValueOnce(result);
        const response = await middleware(request(path) as never);
        expect(response.status).toBe(503);
        expect(response.headers.get('retry-after')).toBe('60');
      }
    }
  });
});
