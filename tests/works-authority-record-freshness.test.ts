// SPDX-License-Identifier: Apache-2.0

import { describe, expect, it, vi } from 'vitest';

import { resolveAuthorityRecordGitHubRef } from '../lib/works/authority-record-freshness.ts';

const REVISION = 'a'.repeat(40);

describe('Authority Record live GitHub ref resolver', () => {
  it('resolves the pinned watched branch through the commit API', async () => {
    const fetchImpl = vi.fn(async () => new Response(JSON.stringify({ sha: REVISION }), {
      status: 200, headers: { 'content-type': 'application/json' },
    }));
    const result = await resolveAuthorityRecordGitHubRef({
      repositoryUrl: 'https://github.com/acme/agent',
      watchedRef: 'refs/heads/main',
      fetchImpl: fetchImpl as any,
    });
    expect(result).toEqual({ kind: 'resolved', revision: REVISION });
    expect(fetchImpl).toHaveBeenCalledWith(
      'https://api.github.com/repos/acme/agent/commits/heads%2Fmain',
      expect.objectContaining({ redirect: 'manual' }),
    );
  });

  it('reports rate limiting and upstream failure as unavailable, never stale', async () => {
    for (const response of [
      new Response('{}', { status: 403, headers: { 'x-ratelimit-remaining': '0' } }),
      new Response('{}', { status: 503 }),
      new Response('{}', { status: 404 }),
    ]) {
      const result = await resolveAuthorityRecordGitHubRef({
        repositoryUrl: 'https://github.com/acme/agent', watchedRef: 'refs/heads/main',
        fetchImpl: vi.fn(async () => response) as any,
      });
      expect(result.kind).toBe('unavailable');
    }
  });

  it('returns indeterminate for malformed success data or redirects', async () => {
    for (const response of [
      new Response(JSON.stringify({ sha: 'moving-main' }), { status: 200 }),
      new Response('', { status: 302, headers: { location: 'https://evil.example' } }),
    ]) {
      const result = await resolveAuthorityRecordGitHubRef({
        repositoryUrl: 'https://github.com/acme/agent', watchedRef: 'refs/tags/v1.0.0',
        fetchImpl: vi.fn(async () => response) as any,
      });
      expect(result.kind).toBe('indeterminate');
    }
  });

  it('refuses non-GitHub subjects and malformed refs without fetching', async () => {
    const fetchImpl = vi.fn();
    const result = await resolveAuthorityRecordGitHubRef({
      repositoryUrl: 'https://evil.example/acme/agent', watchedRef: 'main', fetchImpl,
    });
    expect(result).toEqual({ kind: 'indeterminate', reason: 'watched_subject_invalid' });
    expect(fetchImpl).not.toHaveBeenCalled();
  });
});
