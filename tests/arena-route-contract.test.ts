// SPDX-License-Identifier: Apache-2.0
import { beforeEach, describe, expect, it, vi } from 'vitest';

const mocks = vi.hoisted(() => ({
  provision: vi.fn(),
  submit: vi.fn(),
  publish: vi.fn(),
  load: vi.fn(),
}));

vi.mock('@/lib/arena/service', () => ({
  ArenaServiceError: class ArenaServiceError extends Error {
    constructor(public status: number, public code: string, message = code) { super(message); }
  },
  provisionArenaSession: mocks.provision,
  submitArenaAttempt: mocks.submit,
  publishArenaRefusal: mocks.publish,
  loadPublicArenaRefusal: mocks.load,
}));

vi.mock('@/lib/logger.js', () => ({
  logger: { error: vi.fn(), warn: vi.fn(), info: vi.fn() },
}));

const Sessions = await import('../app/api/arena/sessions/route');
const Attempts = await import('../app/api/arena/sessions/[sessionId]/attempts/route');
const Publish = await import('../app/api/arena/sessions/[sessionId]/attempts/[attemptId]/publish/route');
const PublicRefusal = await import('../app/api/arena/refusals/[shareId]/route');

function jsonRequest(url: string, body: unknown, headers: Record<string, string> = {}) {
  return new Request(url, {
    method: 'POST',
    headers: { 'content-type': 'application/json', ...headers },
    body: JSON.stringify(body),
  }) as any;
}

function expectCurrentStatusCacheHeaders(response: Response) {
  const cacheControl = response.headers.get('cache-control');
  expect(cacheControl).toBe('no-store, max-age=0');
  expect(cacheControl).not.toMatch(/(?:^|[,\s])public(?:$|[,\s])|s-maxage|stale-while-revalidate/i);
  expect(response.headers.get('pragma')).toBe('no-cache');
  expect(response.headers.get('expires')).toBe('0');
}

describe('Arena route contract', () => {
  beforeEach(() => vi.resetAllMocks());

  it('rejects extra session fields and blank names before provisioning', async () => {
    for (const body of [
      { agent_name: 'Night Shift', decision: 'allow' },
      { agent_name: '   ' },
      { agent_name: 'a'.repeat(65) },
    ]) {
      const response = await Sessions.POST(jsonRequest('https://example.test/api/arena/sessions', body));
      expect(response.status).toBe(400);
    }
    expect(mocks.provision).not.toHaveBeenCalled();
  });

  it('returns the dedicated session response once with no-store headers', async () => {
    mocks.provision.mockResolvedValue({ session_id: 'arena_session_1', token: 'ep_arena_secret' });
    const response = await Sessions.POST(jsonRequest('https://example.test/api/arena/sessions', { agent_name: 'Night Shift' }));
    expect(response.status).toBe(201);
    expect(response.headers.get('cache-control')).toContain('no-store');
    expect(response.headers.get('referrer-policy')).toBe('no-referrer');
    expect(await response.json()).toMatchObject({ token: 'ep_arena_secret' });
  });

  it('passes only parsed attempt input to the service and never fabricates a result', async () => {
    const expected = { attempt_id: 'arena_attempt_1', decision: 'refuse' };
    mocks.submit.mockResolvedValue(expected);
    const body = { operation_id: 'op-1', target: 'vendor.demo', amount: 900, purpose: 'synthetic-oversized-transfer' };
    const request = jsonRequest('https://example.test/api/arena/sessions/s/attempts', body, { authorization: 'Bearer ep_arena_x' });
    const response = await Attempts.POST(request, { params: { sessionId: 'arena_session_1' } });
    expect(response.status).toBe(201);
    expect(mocks.submit).toHaveBeenCalledWith(expect.objectContaining({
      request, sessionId: 'arena_session_1', input: body,
    }));
    expect(await response.json()).toEqual(expected);
  });

  it('requires a separate authenticated publication endpoint', async () => {
    mocks.publish.mockResolvedValue({ share_id: 'arena_share_1', share_url: '/arena/r/arena_share_1' });
    const request = new Request('https://example.test/publish', {
      method: 'POST', headers: { authorization: 'Bearer ep_arena_x' },
    }) as any;
    const response = await Publish.POST(request, {
      params: { sessionId: 'arena_session_1', attemptId: 'arena_attempt_1' },
    });
    expect(response.status).toBe(201);
    expect(mocks.publish).toHaveBeenCalledWith(expect.objectContaining({
      request, sessionId: 'arena_session_1', attemptId: 'arena_attempt_1',
    }));
  });

  it('keeps unpublished or unknown public refusals indistinguishable', async () => {
    mocks.load.mockResolvedValue(null);
    const shareIds = [`arena_share_${'0'.repeat(40)}`, 'private_arena_share_database_id'];
    const bodies = [];

    for (const shareId of shareIds) {
      const response = await PublicRefusal.GET(new Request('https://example.test/refusal'), {
        params: { shareId },
      });
      expect(response.status).toBe(404);
      expectCurrentStatusCacheHeaders(response);
      const body = await response.json();
      expect(JSON.stringify(body)).not.toContain(shareId);
      bodies.push(body);
    }

    expect(bodies[0]).toEqual(bodies[1]);
  });

  it('serves published refusals as current status with no public or stale caching', async () => {
    mocks.load.mockResolvedValue({
      share_id: `arena_share_${'1'.repeat(40)}`,
      verification: { integrity_verified: true, accepted: null },
    });
    const response = await PublicRefusal.GET(new Request('https://example.test/refusal'), {
      params: { shareId: `arena_share_${'1'.repeat(40)}` },
    });
    expect(response.status).toBe(200);
    expectCurrentStatusCacheHeaders(response);
    expect(response.headers.get('content-security-policy')).toContain("default-src 'none'");
    expect((await response.json()).verification.accepted).toBeNull();
  });

  it('prevents caching on service and unexpected public refusal errors', async () => {
    const { ArenaServiceError } = await import('@/lib/arena/service');
    const errors = [
      new ArenaServiceError(503, 'arena_store_unavailable', 'arena_store_unavailable'),
      new Error('database details must remain private'),
    ];

    for (const error of errors) {
      mocks.load.mockRejectedValueOnce(error);
      const response = await PublicRefusal.GET(new Request('https://example.test/refusal'), {
        params: { shareId: `arena_share_${'2'.repeat(40)}` },
      });
      expect(response.status).toBe(503);
      expectCurrentStatusCacheHeaders(response);
      expect(await response.text()).not.toContain('database details must remain private');
    }
  });
});
