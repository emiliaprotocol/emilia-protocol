// SPDX-License-Identifier: Apache-2.0
import { createElement } from 'react';
import { renderToStaticMarkup } from 'react-dom/server';
import { readFileSync } from 'node:fs';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import ProposalLookup, { ProposalResults } from '../app/works/submissions/ProposalLookup';
import { createProposalRequestFence, loadProposal, projectProposal } from '../app/works/submissions/proposal-client';
import ProposalPage from '../app/works/submissions/[id]/page';
import ProposalFinderPage from '../app/works/submissions/page';

vi.mock('next/navigation', () => ({
  notFound: () => { throw new Error('WORKS_NOT_FOUND'); },
  useRouter: () => ({ push: vi.fn() }),
}));
const record = (changes = {}) => ({
  submission_id: 'submission-first', opportunity_id: 'refund-job', builder_id: 'real-builder',
  listing_id: 'real-agent', proposal: 'A private approach to this job.', team: ['Alex'],
  example: false, visibility: 'private', created_at: '2026-09-07T12:00:00Z', ...changes,
});
const response = (changes = {}) => ({ collection: 'submissions', record: record(changes) });

beforeEach(() => { vi.stubEnv('WORKS_V0', '1'); });
afterEach(() => { vi.unstubAllEnvs(); vi.unstubAllGlobals(); });

describe('bookmarkable proposal lookup', () => {
  it('gives a confirmed proposal a return link instead of leaving its ID in transient state only', () => {
    const source = readFileSync(new URL('../app/works/SubmissionForm.tsx', import.meta.url), 'utf8');
    expect(source).toContain('href={`/works/submissions/${confirmedId}`}');
    expect(source).toContain('Open your recorded proposal');
  });

  it('lets an unresolved attempt be bookmarked without asserting that it was recorded', () => {
    const source = readFileSync(new URL('../app/works/SubmissionForm.tsx', import.meta.url), 'utf8');
    expect(source).toContain('href={`/works/submissions/${attempt.submission_id}`}');
    expect(source).toContain('Check this proposal ID');
  });

  it('uses a browser-valid Unicode Sets pattern for proposal IDs', () => {
    const html = renderToStaticMarkup(ProposalFinderPage());
    const pattern = html.match(/pattern="([^"]+)"/)?.[1];
    expect(pattern).toBeDefined();
    const constraint = new RegExp(`^(?:${pattern})$`, 'v');
    expect(constraint.test('submission-first')).toBe(true);
    expect(constraint.test('../proposal')).toBe(false);
    expect(constraint.test('x'.repeat(65))).toBe(false);
  });

  it('renders an ID-only finder and an authentication page without fetching any proposal during SSR', async () => {
    const fetcher = vi.fn();
    vi.stubGlobal('fetch', fetcher);
    const finder = renderToStaticMarkup(ProposalFinderPage());
    expect(finder).toContain('Find a proposal');
    expect(finder).toContain('Proposal ID');
    expect(finder).not.toContain('type="password"');
    const html = renderToStaticMarkup(await ProposalPage({ params: Promise.resolve({ id: 'submission-first' }) }));
    expect(fetcher).not.toHaveBeenCalled();
    expect(html).toContain('submission-first');
    expect(html).toContain('type="password"');
    expect(html).toContain('method="post"');
    expect(html).toContain('<fieldset disabled=""');
    expect(html).not.toContain('A private approach');
  });

  it('refuses disabled lookup and malformed bookmark IDs without probing records', async () => {
    vi.stubEnv('WORKS_V0', '0');
    expect(() => ProposalFinderPage()).toThrow('WORKS_NOT_FOUND');
    await expect(ProposalPage({ params: Promise.resolve({ id: 'submission-first' }) })).rejects.toThrow('WORKS_NOT_FOUND');
    vi.stubEnv('WORKS_V0', '1');
    await expect(ProposalPage({ params: Promise.resolve({ id: '../private' }) })).rejects.toThrow('WORKS_NOT_FOUND');
  });
});

describe('proposal lookup response boundary', () => {
  it('projects an exact, schema-valid record and excludes backend fields', () => {
    expect(projectProposal(response({ owner_entity_id: 'owner-secret', api_key: 'key-secret' }), 'submission-first')).toEqual(record());
    expect(projectProposal(response({ visibility: 'public', listing_id: null, team: [] }), 'submission-first').visibility).toBe('public');
  });

  it.each([null, {}, { collection: 'builders', record: record() },
    response({ submission_id: 'other-proposal' }), response({ builder_id: '../builder' }),
    response({ visibility: 'unknown' }), response({ visibility: undefined }), response({ example: true }),
    response({ proposal: 'x'.repeat(8001) }), response({ team: 'not-an-array' })])('refuses malformed or mismatched responses: %j', (body) => {
    expect(() => projectProposal(body, 'submission-first')).toThrow('proposal_response_invalid');
  });

  it('uses only the authenticated single-record API with private request options', async () => {
    const fetcher = vi.fn().mockResolvedValue(new Response(JSON.stringify(response())));
    vi.stubGlobal('fetch', fetcher);
    const controller = new AbortController();
    expect(await loadProposal('submission-first', 'ep_live_private-test', controller.signal)).toEqual(record());
    expect(fetcher).toHaveBeenCalledExactlyOnceWith('/api/works/submissions/submission-first', {
      method: 'GET', headers: { authorization: 'Bearer ep_live_private-test' },
      cache: 'no-store', credentials: 'omit', redirect: 'error', referrerPolicy: 'no-referrer', signal: controller.signal,
    });
  });

  it.each([401, 403, 404, 429, 503])('refuses HTTP %i without echoing backend detail or claiming a missing proposal', async (status) => {
    vi.stubGlobal('fetch', vi.fn().mockResolvedValue(new Response('{"detail":"private backend or token"}', { status })));
    await expect(loadProposal('submission-first', 'ep_live_private-test', new AbortController().signal)).rejects.toThrow(/^proposal_(?:access_refused|unavailable|rate_limited)$/);
  });

  it('refuses invalid input before fetching and malformed 2xx JSON before rendering', async () => {
    const fetcher = vi.fn().mockResolvedValue(new Response('not JSON'));
    vi.stubGlobal('fetch', fetcher);
    await expect(loadProposal('../private', 'ep_live_private-test', new AbortController().signal)).rejects.toThrow('proposal_input_invalid');
    await expect(loadProposal('submission-first', 'bad\nkey', new AbortController().signal)).rejects.toThrow('proposal_input_invalid');
    expect(fetcher).not.toHaveBeenCalled();
    await expect(loadProposal('submission-first', 'ep_live_private-test', new AbortController().signal)).rejects.toThrow();
  });

  it('discards a late private response after clear even when fetch ignores abort', async () => {
    let resolve!: (value: Response) => void;
    const fetcher = vi.fn().mockImplementation(() => new Promise<Response>((done) => { resolve = done; }));
    vi.stubGlobal('fetch', fetcher);
    const fence = createProposalRequestFence();
    const first = fence.begin();
    const result = first.load('submission-first', 'ep_live_private-test');
    fence.cancel();
    resolve(new Response(JSON.stringify(response())));
    expect(await result).toBeNull();
    expect(first.signal.aborted).toBe(true);
    expect(first.isCurrent()).toBe(false);
  });

  it('discards stale errors after a newer lookup and still loads the current response', async () => {
    let reject!: (reason: Error) => void;
    vi.stubGlobal('fetch', vi.fn()
      .mockImplementationOnce(() => new Promise<Response>((_resolve, fail) => { reject = fail; }))
      .mockResolvedValueOnce(new Response(JSON.stringify(response()))));
    const fence = createProposalRequestFence();
    const first = fence.begin();
    const oldResult = first.load('submission-first', 'ep_live_old-key');
    const current = fence.begin();
    reject(new Error('old private failure'));
    expect(await oldResult).toBeNull();
    expect(await current.load('submission-first', 'ep_live_current-key')).toEqual(record());
    expect(current.isCurrent()).toBe(true);
    fence.cancel();
  });
});

describe('proposal lookup privacy and copy', () => {
  it('keeps private content out of the initial render and explains who can read it', () => {
    const html = renderToStaticMarkup(createElement(ProposalLookup, { submissionId: 'submission-first' }));
    expect(html).toContain('proposal author, the job owner or an authorized administrator');
    expect(html).toContain('Clear private view');
    const source = readFileSync(new URL('../app/works/submissions/ProposalLookup.tsx', import.meta.url), 'utf8');
    expect(source).not.toMatch(/localStorage|sessionStorage|console\.|useSearchParams/);
    expect(source).toContain("document.visibilityState === 'hidden'");
    expect(source).toContain("window.addEventListener('pagehide', leave)");
    expect(source).toContain('if (!request.isCurrent() || !loaded) return');
  });

  it('renders escaped proposal text with useful links without implying acceptance', () => {
    const html = renderToStaticMarkup(createElement(ProposalResults, {
      record: projectProposal(response({ proposal: '<script>private text</script>' }), 'submission-first'),
      checkedAt: '2026-09-07T12:00:00Z',
    }));
    expect(html).toContain('&lt;script&gt;private text&lt;/script&gt;');
    expect(html).toContain('href="/works/opportunities/refund-job"');
    expect(html).toContain('href="/works/builders/real-builder"');
    expect(html).toContain('href="/works/listings/real-agent"');
    expect(html).toContain('does not mean the job owner has read or accepted it');
    expect(html).toContain('Recorded proposal');
    expect(html).not.toContain('Your recorded response');
    expect(html).not.toContain('<script>private text');
  });
});
