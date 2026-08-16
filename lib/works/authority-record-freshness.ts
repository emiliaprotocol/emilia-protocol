// SPDX-License-Identifier: Apache-2.0

import { normalizeGitHubRepositoryUrl, type RefResolution } from './authority-record.js';

const WATCHED_REF = /^refs\/(heads|tags)\/(?!\/)(?!.*\.\.)(?!.*(?:^|\/)\.)(?!.*\.lock(?:\/|$))[A-Za-z0-9._/-]{1,240}$/;
const REVISION = /^(?:[0-9a-f]{40}|[0-9a-f]{64})$/;

export async function resolveAuthorityRecordGitHubRef({
  repositoryUrl,
  watchedRef,
  fetchImpl = fetch,
  githubToken = process.env.GITHUB_TOKEN || process.env.GH_TOKEN || '',
}: {
  repositoryUrl: string;
  watchedRef: string;
  fetchImpl?: typeof fetch;
  githubToken?: string;
}): Promise<RefResolution> {
  const normalized = normalizeGitHubRepositoryUrl(repositoryUrl);
  const match = WATCHED_REF.exec(watchedRef);
  if (!normalized || !match) {
    return Object.freeze({ kind: 'indeterminate', reason: 'watched_subject_invalid' });
  }
  const path = new URL(normalized).pathname.slice(1);
  const refName = watchedRef.slice('refs/'.length);
  const headers: Record<string, string> = {
    accept: 'application/vnd.github+json',
    'x-github-api-version': '2022-11-28',
  };
  if (githubToken) headers.authorization = `Bearer ${githubToken}`;

  let response: Response;
  try {
    response = await fetchImpl(
      `https://api.github.com/repos/${path}/commits/${encodeURIComponent(refName)}`,
      { method: 'GET', headers, redirect: 'manual', signal: AbortSignal.timeout(8_000) },
    );
  } catch {
    return Object.freeze({ kind: 'unavailable', reason: 'github_lookup_unavailable' });
  }
  if (response.status >= 300 && response.status < 400) {
    return Object.freeze({ kind: 'indeterminate', reason: 'github_redirect_refused' });
  }
  if (response.status === 403 && response.headers.get('x-ratelimit-remaining') === '0') {
    return Object.freeze({ kind: 'unavailable', reason: 'github_rate_limited' });
  }
  if (response.status === 404) {
    return Object.freeze({ kind: 'unavailable', reason: 'watched_ref_not_found' });
  }
  if (!response.ok) {
    return Object.freeze({ kind: 'unavailable', reason: 'github_lookup_unavailable' });
  }
  let data: unknown;
  try {
    data = await response.json();
  } catch {
    return Object.freeze({ kind: 'indeterminate', reason: 'github_response_invalid' });
  }
  const revision = data && typeof data === 'object' && !Array.isArray(data)
    ? (data as Record<string, unknown>).sha : null;
  if (typeof revision !== 'string' || !REVISION.test(revision)) {
    return Object.freeze({ kind: 'indeterminate', reason: 'github_response_invalid' });
  }
  return Object.freeze({ kind: 'resolved', revision });
}
