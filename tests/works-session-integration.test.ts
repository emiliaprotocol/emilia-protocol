// SPDX-License-Identifier: Apache-2.0
import { afterEach, describe, expect, it, vi } from 'vitest';
import { worksRequestAuth } from '../app/works/session-request';
import { publishOpportunityWithRecovery } from '../app/works/opportunity-publication';
import { prepareOpportunityDraft } from '../app/works/opportunity-publication';

afterEach(() => vi.unstubAllGlobals());

describe('Works browser credentials stay scoped to one authentication mode', () => {
  it('uses the HttpOnly session without manufacturing an authorization header', () => {
    expect(worksRequestAuth(null)).toEqual({ headers: {}, credentials: 'same-origin' });
  });
  it('keeps explicit legacy keys isolated from ambient session cookies', () => {
    expect(worksRequestAuth('SYNTHETIC_SECRET_KEY')).toEqual({
      headers: { authorization: 'Bearer SYNTHETIC_SECRET_KEY' }, credentials: 'omit',
    });
  });
  it.each(['', ' ', 'bad\nkey', 'x'.repeat(513)])('rejects malformed explicit credentials', key => {
    expect(() => worksRequestAuth(key)).toThrow();
  });
  it('publishes and recovers an exact job through a session, without a bearer in its body or URL', async () => {
    const draft = prepareOpportunityDraft({ opportunityId: 'session-job', kind: 'problem', title: 'Review invoices',
      description: 'Prepare a review queue, without making payments.', postedBy: '', contactRoute: 'mailto:buyer@example.com',
      funding: { status: 'UNKNOWN', statement: 'Not specified', scope: 'Job funding', limitations: '' },
      authority: { status: 'UNKNOWN', statement: 'Not specified', scope: 'Job authority', limitations: '' }, eligibility: null });
    const fetcher = vi.fn().mockRejectedValueOnce(new Error('lost response')).mockResolvedValueOnce(new Response(JSON.stringify({
      collection: 'opportunities', owned: true, record: { ...draft, posted_by: 'Verified account' },
    })));
    vi.stubGlobal('fetch', fetcher);
    await expect(publishOpportunityWithRecovery(null, draft, new AbortController().signal)).resolves.toMatchObject({ opportunity_id: 'session-job' });
    expect(fetcher).toHaveBeenCalledTimes(2);
    for (const [, options] of fetcher.mock.calls) {
      expect(options.credentials).toBe('same-origin');
      expect(options.headers.authorization).toBeUndefined();
    }
  });
});
