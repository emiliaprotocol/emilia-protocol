// SPDX-License-Identifier: Apache-2.0

import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

type LimiterMode = 'unconfigured' | 'outage' | 'exhausted' | 'healthy';
type ReadinessMode = 'ready' | 'missing';

const RECORD_ID = `agent_record_${'d'.repeat(40)}`;
const AGENT_RECORD_PATHS = [
  `/api/agent-records/${RECORD_ID}`,
  `/agent-record/r/${RECORD_ID}`,
] as const;

async function loadRealMiddleware(mode: LimiterMode, readiness: ReadinessMode = 'ready') {
  vi.resetModules();
  vi.stubEnv('NODE_ENV', 'production');

  vi.doMock('@/lib/env', () => ({
    getRateLimitConfig: () => ({ durableRequired: true }),
    getUpstashConfig: () => mode === 'unconfigured'
      ? null
      : { url: 'https://rate-limit.example', token: 'test-token' },
  }));
  vi.doMock('@/lib/logger.js', () => ({
    logger: { error: vi.fn() },
  }));
  vi.doMock('@/lib/siem', () => ({ siemEvent: vi.fn() }));
  vi.doMock('@/lib/agent-record/readiness', () => ({
    getAgentRecordConfigurationReadiness: () => ({
      enforced: true,
      ready: readiness === 'ready',
      checks: {
        signing_key: readiness === 'ready',
        durable_rate_limiting: readiness === 'ready',
        database_configuration: readiness === 'ready',
        database_creation_authorization: readiness === 'ready',
      },
      unavailable: readiness === 'ready' ? [] : ['signing_key'],
    }),
  }));

  const fetchMock = vi.fn();
  if (mode === 'outage') {
    fetchMock.mockResolvedValue({
      json: async () => ({ error: 'upstream unavailable' }),
    });
  } else if (mode === 'exhausted') {
    fetchMock.mockResolvedValue({
      json: async () => ({ result: [0, 0, 29] }),
    });
  } else if (mode === 'healthy') {
    fetchMock.mockResolvedValue({
      json: async () => ({ result: [1, 41, 60] }),
    });
  }
  vi.stubGlobal('fetch', fetchMock);

  const [{ middleware }, { NextRequest }] = await Promise.all([
    import('../middleware.ts'),
    import('next/server'),
  ]);
  return { middleware, NextRequest, fetchMock };
}

describe('Agent Record durable rate limiting through real middleware', () => {
  beforeEach(() => {
    vi.unstubAllGlobals();
    vi.clearAllMocks();
  });

  afterEach(() => {
    vi.unstubAllEnvs();
    vi.unstubAllGlobals();
    vi.resetModules();
    vi.doUnmock('@/lib/env');
    vi.doUnmock('@/lib/logger.js');
    vi.doUnmock('@/lib/siem');
    vi.doUnmock('@/lib/agent-record/readiness');
  });

  it('fails every Agent Record entry point closed on missing production configuration only', async () => {
    const { middleware, NextRequest, fetchMock } = await loadRealMiddleware('healthy', 'missing');

    for (const [method, path] of [
      ['GET', `/agent-record/r/${RECORD_ID}`],
      ['GET', `/api/agent-records/${RECORD_ID}`],
      ['POST', `/api/agent-records/${RECORD_ID}/revoke`],
      ['POST', `/api/adopt/sessions/${'a'.repeat(32)}/records`],
    ] as const) {
      const response = await middleware(new NextRequest(`https://ep.test${path}`, { method }) as never);
      expect(response.status, `${method} ${path}`).toBe(503);
      expect(response.headers.get('retry-after'), `${method} ${path}`).toBe('60');
      expect(response.headers.get('cache-control'), `${method} ${path}`).toBe(
        'no-store, no-cache, must-revalidate',
      );
      const body = await response.json();
      expect(body).toEqual({
        error: 'Agent Record is temporarily unavailable.',
        code: 'agent_record_unavailable',
        retry_after: 60,
      });
    }

    const adopt = await middleware(new NextRequest('https://ep.test/adopt') as never);
    expect(adopt.status).toBe(200);
    const verifier = await middleware(new NextRequest('https://ep.test/api/verify/tr_public') as never);
    expect(verifier.status).toBe(200);
    expect(fetchMock).toHaveBeenCalledOnce();
  });

  it('fails the public GET and page closed in production when Upstash is unconfigured', async () => {
    const { middleware, NextRequest, fetchMock } = await loadRealMiddleware('unconfigured');

    for (const path of AGENT_RECORD_PATHS) {
      const response = await middleware(new NextRequest(`https://ep.test${path}`) as never);
      expect(response.status, path).toBe(503);
      expect(response.headers.get('retry-after'), path).toBe('60');
      expect(response.headers.get('cache-control'), path).toBe(
        'no-store, no-cache, must-revalidate',
      );
    }
    expect(fetchMock).not.toHaveBeenCalled();
  });

  it('fails Agent Record closed on a configured Upstash outage but keeps public evidence fail-open', async () => {
    const { middleware, NextRequest, fetchMock } = await loadRealMiddleware('outage');

    for (const path of AGENT_RECORD_PATHS) {
      const response = await middleware(new NextRequest(`https://ep.test${path}`) as never);
      expect(response.status, path).toBe(503);
      expect(response.headers.get('cache-control'), path).toBe(
        'no-store, no-cache, must-revalidate',
      );
    }

    for (const path of ['/api/verify/tr_public', '/api/badge/agent-public']) {
      const response = await middleware(new NextRequest(`https://ep.test${path}`) as never);
      expect(response.status, path).toBe(200);
    }
    expect(fetchMock).toHaveBeenCalledTimes(4);
  });

  it('marks a page-level 429 as non-cacheable in production', async () => {
    const { middleware, NextRequest, fetchMock } = await loadRealMiddleware('exhausted');
    const response = await middleware(
      new NextRequest(`https://ep.test/agent-record/r/${RECORD_ID}`) as never,
    );

    expect(response.status).toBe(429);
    expect(response.headers.get('retry-after')).toBe('29');
    expect(response.headers.get('cache-control')).toBe(
      'no-store, no-cache, must-revalidate',
    );
    expect(fetchMock).toHaveBeenCalledOnce();
  });

  it('allows the public GET and page when Upstash returns a durable allowance', async () => {
    const { middleware, NextRequest, fetchMock } = await loadRealMiddleware('healthy');

    for (const path of AGENT_RECORD_PATHS) {
      const response = await middleware(new NextRequest(`https://ep.test${path}`) as never);
      expect(response.status, path).toBe(200);
      expect(response.headers.get('x-ratelimit-limit'), path).toBe('60');
      expect(response.headers.get('x-ratelimit-remaining'), path).toBe('41');
    }
    expect(fetchMock).toHaveBeenCalledTimes(2);
  });
});
