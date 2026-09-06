// SPDX-License-Identifier: Apache-2.0
import { createElement } from 'react';
import { renderToStaticMarkup } from 'react-dom/server';
import { readFileSync } from 'node:fs';
import { afterEach, describe, expect, it, vi } from 'vitest';
import SubmissionForm, { createSubmissionAttemptTracker, matchesSubmissionAttempt, sendOrCheckSubmission } from '../app/works/SubmissionForm';

vi.mock('next/navigation', () => ({ useRouter: () => ({ refresh: vi.fn() }) }));
const input = () => ({
  opportunityId: 'refund-job', builderId: 'real-builder', listingId: 'real-agent',
  proposal: 'A bounded proposal.', team: 'Alex, Sam', visibility: 'private' as const,
});
afterEach(() => vi.unstubAllGlobals());

describe('stable submission identity after response loss', () => {
  it('reuses one frozen payload and ID on retries without retaining the API key', () => {
    const tracker = createSubmissionAttemptTracker();
    const id = vi.fn().mockReturnValueOnce('first-proposal').mockReturnValueOnce('second-proposal');
    const value = input();
    const first = tracker.prepare(value, id);
    const second = tracker.prepare(input(), id);
    expect(second).toBe(first);
    expect(id).toHaveBeenCalledOnce();
    expect(Object.isFrozen(first)).toBe(true);
    expect(Object.isFrozen(first.team)).toBe(true);
    value.proposal = 'Changed after admission';
    expect(first.proposal).toBe('A bounded proposal.');
    expect(Object.keys(first)).not.toContain('apiKey');
    tracker.clear();
    expect(tracker.prepare(input(), id).submission_id).toBe('second-proposal');
  });

  it.each(['proposal', 'builderId', 'opportunityId', 'listingId', 'team', 'visibility'])('refuses changed %s until explicit start-over', (key) => {
    const tracker = createSubmissionAttemptTracker();
    const first = tracker.prepare(input(), () => 'first-proposal');
    const changed = { ...input(), [key]: key === 'visibility' ? 'public' : 'changed-value' };
    expect(() => tracker.prepare(changed as ReturnType<typeof input>, () => 'second-proposal')).toThrow('submission_attempt_changed');
    expect(tracker.prepare(input(), () => 'third-proposal')).toBe(first);
  });

  it('confirms only an exact returned proposal, including its private/public choice', () => {
    const tracker = createSubmissionAttemptTracker();
    const expected = tracker.prepare(input(), () => 'first-proposal');
    expect(matchesSubmissionAttempt({ ...expected, created_at: '2026-09-06T00:00:00Z' }, expected)).toBe(true);
    expect(matchesSubmissionAttempt({ ...expected, visibility: 'public' }, expected)).toBe(false);
    expect(matchesSubmissionAttempt({ ...expected, submission_id: 'second-proposal' }, expected)).toBe(false);
    expect(matchesSubmissionAttempt({ ...expected, proposal: 'Something else' }, expected)).toBe(false);
    expect(matchesSubmissionAttempt({ ...expected, team: ['Different'] }, expected)).toBe(false);
    expect(matchesSubmissionAttempt({ saved: true }, expected)).toBe(false);
    expect(matchesSubmissionAttempt(null, expected)).toBe(false);
  });

  it('checks the exact saved proposal without posting or sending a key in its URL', async () => {
    const payload = createSubmissionAttemptTracker().prepare(input(), () => 'first-proposal');
    const fetcher = vi.fn().mockResolvedValue(new Response(JSON.stringify({ collection: 'submissions', record: payload })));
    vi.stubGlobal('fetch', fetcher);
    await sendOrCheckSubmission(payload, 'ep_live_private-test', true);
    expect(fetcher).toHaveBeenCalledExactlyOnceWith('/api/works/submissions/first-proposal', expect.objectContaining({ method: 'GET', cache: 'no-store', credentials: 'omit', redirect: 'error' }));
    expect(fetcher.mock.calls[0][1].headers.authorization).toBe('Bearer ep_live_private-test');
    expect(fetcher.mock.calls[0][1].body).toBeUndefined();
  });

  it('resolves duplicate-ID responses by reading the same saved proposal, not posting a new ID', async () => {
    const payload = createSubmissionAttemptTracker().prepare(input(), () => 'first-proposal');
    const fetcher = vi.fn().mockResolvedValueOnce(new Response('{}', { status: 409 }))
      .mockResolvedValueOnce(new Response(JSON.stringify({ collection: 'submissions', record: payload })));
    vi.stubGlobal('fetch', fetcher);
    await sendOrCheckSubmission(payload, 'ep_live_private-test');
    expect(fetcher.mock.calls.map(call => call[1].method)).toEqual(['POST', 'GET']);
    expect(JSON.parse(fetcher.mock.calls[0][1].body).submission_id).toBe('first-proposal');
    expect(fetcher.mock.calls[1][0]).toBe('/api/works/submissions/first-proposal');
  });

  it('does not accept a mismatched recovery record or echo backend secrets', async () => {
    const payload = createSubmissionAttemptTracker().prepare(input(), () => 'first-proposal');
    const fetcher = vi.fn().mockResolvedValueOnce(new Response(JSON.stringify({ collection: 'submissions', record: { ...payload, visibility: 'public' } })))
      .mockResolvedValueOnce(new Response('{"detail":"private-token"}', { status: 401 }));
    vi.stubGlobal('fetch', fetcher);
    await expect(sendOrCheckSubmission(payload, 'ep_live_private-test', true)).rejects.toThrow('submission_confirmation_missing');
    await expect(sendOrCheckSubmission(payload, 'ep_live_private-test', true)).rejects.toThrow('submission_access_refused');
    await expect(sendOrCheckSubmission(payload, 'bad\nkey', true)).rejects.toThrow('submission_key_required');
    expect(fetcher).toHaveBeenCalledTimes(2);
  });

  it('explains access accurately and provides an explicit way to resolve an uncertain attempt', () => {
    const html = renderToStaticMarkup(createElement(SubmissionForm, {
      opportunityId: 'refund-job', sponsorName: 'Sponsor', sponsorContactRoute: 'mailto:sponsor@example.com',
    }));
    expect(html).toContain('Private responses can be read by you, the opportunity owner and authorized administrators');
    expect(html).not.toContain('shared only with the opportunity owner');
    const source = readFileSync(new URL('../app/works/SubmissionForm.tsx', import.meta.url), 'utf8');
    expect(source).toContain('Start a separate response');
    expect(source).toContain('already have been recorded');
    expect(source).toContain('matchesSubmissionAttempt(body.record, payload)');
    expect(source).toContain('if (inFlight.current) return');
    expect(source).not.toMatch(/localStorage|sessionStorage/);
  });
});
