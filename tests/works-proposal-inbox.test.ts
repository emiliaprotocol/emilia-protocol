// SPDX-License-Identifier: Apache-2.0
import { createElement } from 'react';
import { renderToStaticMarkup } from 'react-dom/server';
import { readFileSync } from 'node:fs';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import ProposalInbox, { ProposalInboxResults } from '../app/works/opportunities/[id]/inbox/ProposalInbox';
import { createInboxRequestFence, loadOpportunityInbox, projectInboxRecords } from '../app/works/opportunities/[id]/inbox/inbox-client';
import InboxPage from '../app/works/opportunities/[id]/inbox/page';

const store = vi.hoisted(() => ({ get: vi.fn() }));
vi.mock('@/lib/works/store', () => ({ getWorksRecord: store.get }));
vi.mock('next/navigation', () => ({ notFound: () => { throw new Error('WORKS_NOT_FOUND'); } }));

const record = (changes = {}) => ({
  submission_id: 'proposal-first', opportunity_id: 'refund-job', builder_id: 'real-builder',
  listing_id: 'real-agent', proposal: 'A private proposal for the named job.', team: ['Alex'],
  example: false, visibility: 'private', created_at: '2026-09-06T07:00:00Z', ...changes,
});
const response = (records = [record()]) => ({ collection: 'submissions', opportunity_id: 'refund-job', access: 'owner' as const, offset: 0, limit: 50 as const, has_more: false, records });

beforeEach(() => {
  vi.stubEnv('WORKS_V0', '1');
  store.get.mockReset();
  store.get.mockResolvedValue({ ok: true, record: { opportunity_id: 'refund-job', title: 'Refunds job', example: false } });
});
afterEach(() => { vi.unstubAllEnvs(); vi.unstubAllGlobals(); });

describe('proposal inbox projection', () => {
  it('projects only eligible fields for the exact job and refuses mismatched scopes or examples', () => {
    const rows = projectInboxRecords(response([
      record({ owner_entity_id: 'private-owner', api_key: 'private-key', notes: 'private backend note' }),
    ]), 'refund-job');
    expect(rows).toEqual([record()]);
    expect(JSON.stringify(rows)).not.toMatch(/private-owner|private-key|private backend note|Another private job/);
    for (const changes of [{ opportunity_id: 'other-job' }, { example: true }]) expect(() => projectInboxRecords(response([record(changes)]), 'refund-job')).toThrow('inbox_response_invalid');
    for (const changes of [{ access: 'submitter' }, { opportunity_id: 'another-job' }, { limit: 100 }, { offset: 1 }, { has_more: 'false' }]) expect(() => projectInboxRecords({ ...response(), ...changes }, 'refund-job')).toThrow('inbox_response_invalid');
  });

  it.each([null, {}, { collection: 'builders', records: [] }, response([record({ visibility: 'unknown' })]),
    response([record({ builder_id: '../private' })]), response([record({ proposal: 'x'.repeat(8001) })])])('refuses malformed projections instead of claiming there are no responses: %j', (value) => {
    expect(() => projectInboxRecords(value, 'refund-job')).toThrow('inbox_response_invalid');
  });

  it('shows an owner-authorized empty page with a useful next step', () => {
    expect(projectInboxRecords(response([]), 'refund-job')).toEqual([]);
    const html = renderToStaticMarkup(createElement(ProposalInboxResults, { ...response([]), checkedAt: '2026-09-06T07:00:00Z' }));
    expect(html).toContain('Opportunity owner access confirmed');
    expect(html).toContain('No proposals on this page yet');
    expect(html).toContain('Share the opportunity link with builders');
  });
});

describe('proposal inbox private request boundary', () => {
  it('uses the existing authenticated API without putting a key in the URL or response projection', async () => {
    const fetcher = vi.fn().mockResolvedValue(new Response(JSON.stringify(response()), { status: 200 }));
    vi.stubGlobal('fetch', fetcher);
    const controller = new AbortController();
    expect(await loadOpportunityInbox('refund-job', 'ep_live_private-test', controller.signal)).toEqual({ records: [record()], access: 'owner', offset: 0, limit: 50, has_more: false });
    expect(fetcher).toHaveBeenCalledWith('/api/works/opportunities/refund-job/inbox?offset=0', {
      method: 'GET', headers: { authorization: 'Bearer ep_live_private-test' },
      cache: 'no-store', credentials: 'omit', redirect: 'error', referrerPolicy: 'no-referrer', signal: controller.signal,
    });
  });

  it.each([401, 403, 404, 429, 503])('clears results on HTTP %i without echoing server detail', async (status) => {
    vi.stubGlobal('fetch', vi.fn().mockResolvedValue(new Response('{"detail":"private backend or token"}', { status })));
    await expect(loadOpportunityInbox('refund-job', 'ep_live_private-test', new AbortController().signal)).rejects.toThrow(/^inbox_(?:access_refused|unavailable|rate_limited)$/);
  });

  it('refuses invalid key or job ID before any request', async () => {
    const fetcher = vi.fn();
    vi.stubGlobal('fetch', fetcher);
    await expect(loadOpportunityInbox('../other-job', 'ep_live_key', new AbortController().signal)).rejects.toThrow('inbox_input_invalid');
    await expect(loadOpportunityInbox('refund-job', 'bad\nkey', new AbortController().signal)).rejects.toThrow('inbox_input_invalid');
    expect(fetcher).not.toHaveBeenCalled();
  });

  it('invalidates earlier requests on a newer request, edit or clear, even if transport ignores abort', async () => {
    const fence = createInboxRequestFence();
    const first = fence.begin();
    const second = fence.begin();
    expect(first.signal.aborted).toBe(true);
    expect(first.isCurrent()).toBe(false);
    expect(second.isCurrent()).toBe(true);
    fence.cancel();
    expect(second.signal.aborted).toBe(true);
    expect(second.isCurrent()).toBe(false);
    const third = fence.begin();
    expect(first.isCurrent()).toBe(false);
    expect(third.isCurrent()).toBe(true);
    fence.cancel();
  });
});

describe('proposal inbox page and copy', () => {
  it('loads only the public opportunity during SSR, never private submissions or credentials', async () => {
    const html = renderToStaticMarkup(await InboxPage({ params: Promise.resolve({ id: 'refund-job' }) }));
    expect(store.get).toHaveBeenCalledExactlyOnceWith('opportunities', 'refund-job');
    expect(html).toContain('Open your private proposal inbox');
    expect(html).toContain('type="password"');
    expect(html).toContain('method="post"');
    expect(html).toContain('<fieldset disabled=""');
    expect(html).not.toContain('A private proposal for the named job');
  });

  it('keeps disabled, missing and example opportunities outside the inbox', async () => {
    vi.stubEnv('WORKS_V0', '0');
    await expect(InboxPage({ params: Promise.resolve({ id: 'refund-job' }) })).rejects.toThrow('WORKS_NOT_FOUND');
    expect(store.get).not.toHaveBeenCalled();
    vi.stubEnv('WORKS_V0', '1');
    store.get.mockResolvedValue({ ok: true, record: { example: true } });
    await expect(InboxPage({ params: Promise.resolve({ id: 'example-job' }) })).rejects.toThrow('WORKS_NOT_FOUND');
    store.get.mockResolvedValue({ ok: false, code: 'not_found' });
    await expect(InboxPage({ params: Promise.resolve({ id: 'missing-job' }) })).rejects.toThrow('WORKS_NOT_FOUND');
  });

  it('shows access limits and clears private state on edits, clear and backgrounding', () => {
    const html = renderToStaticMarkup(createElement(ProposalInbox, { opportunityId: 'refund-job' }));
    expect(html).toContain('server checks that the key belongs to the opportunity owner');
    expect(html).toContain('does not send email notifications');
    const source = readFileSync(new URL('../app/works/opportunities/[id]/inbox/ProposalInbox.tsx', import.meta.url), 'utf8');
    expect(source).not.toMatch(/localStorage|sessionStorage|console\.|searchParams|useSearchParams/);
    expect(source).toContain('if (!request.isCurrent()) return');
    expect(source).toContain('if (!ready) return');
    expect(source).toContain('onChange={(event) => { clear(false); setApiKey(event.target.value); }}');
    expect(source).toContain("document.visibilityState === 'hidden'");
  });
});
