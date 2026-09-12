// SPDX-License-Identifier: Apache-2.0
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { createElement } from 'react';
import { renderToStaticMarkup } from 'react-dom/server';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import OpportunityForm from '../app/works/OpportunityForm';
import { createWorksRecord, getOwnedWorksRecord } from '../lib/works/store';
import { prepareOpportunityDraft, publishOpportunityWithRecovery, sameOpportunityPublication } from '../app/works/opportunity-publication';
import type { OpportunityFormInput } from '../app/works/form-payloads';
import type { OpportunityRecord } from '../lib/works/model';

vi.mock('../lib/supabase.js', () => ({ getServiceClient: vi.fn() }));

const OWNER = '11111111-1111-4111-8111-111111111111';
const OTHER = '22222222-2222-4222-8222-222222222222';
const job = {
  opportunity_id: 'refund-review', kind: 'problem', title: 'Review refund requests',
  description: 'Prepare a review queue. Do not issue refunds.', posted_by: 'Finance team',
  contact_route: 'mailto:finance@example.com', claims: [],
};
const signal = () => new AbortController().signal;
const created = (record: unknown = job) => new Response(JSON.stringify({ collection: 'opportunities', record }), { status: 201 });
const owned = (record: unknown = job) => new Response(JSON.stringify({ collection: 'opportunities', owned: true, record }));
let directory: string;
beforeEach(() => {
  directory = fs.mkdtempSync(path.join(os.tmpdir(), 'works-opportunity-publish-'));
  vi.stubEnv('WORKS_DATA_DIR', directory);
});
afterEach(() => {
  vi.unstubAllEnvs(); vi.unstubAllGlobals();
  fs.rmSync(directory, { recursive: true, force: true });
});

describe('job publication recovery ownership', () => {
  it('lets the exact owner recover a job without treating public existence as ownership', async () => {
    expect((await createWorksRecord('opportunities', job, { ownerEntityId: OWNER })).ok).toBe(true);
    const owned = await getOwnedWorksRecord('opportunities', job.opportunity_id, { ownerEntityId: OWNER });
    expect(owned).toMatchObject({ ok: true, record: job });
    expect(JSON.stringify(owned)).not.toContain(OWNER);
    expect(await getOwnedWorksRecord('opportunities', job.opportunity_id, { ownerEntityId: OTHER }))
      .toMatchObject({ ok: false, code: 'not_found' });
  });
  it('keeps examples, unknown collections, invalid IDs and invalid owners outside recovery', async () => {
    for (const [collection, id, ownerEntityId, code] of [
      ['opportunities', 'ex-reproduce-conformance', OWNER, 'not_found'],
      ['opportunities', 'missing-job', OWNER, 'not_found'],
      ['submissions', 'refund-review', OWNER, 'invalid_collection'],
      ['opportunities', '../other-job', OWNER, 'invalid_id'],
      ['opportunities', 'refund-review', 'public-slug', 'owner_required'],
    ]) expect(await getOwnedWorksRecord(collection, id, { ownerEntityId })).toMatchObject({ ok: false, code });
  });
});

describe('job description before credentials', () => {
  it('starts with a disabled-until-hydrated local draft, not an API key', () => {
    const html = renderToStaticMarkup(createElement(OpportunityForm));
    expect(html).toContain('Preview my job');
    expect(html).toContain('Nothing is sent or published when you preview');
    expect(html).toContain('method="post"');
    expect(html).toContain('<fieldset disabled=""');
    expect(html).not.toContain('type="password"');
  });
});

describe('exact job publication confirmation', () => {
  it('does not call an empty successful response a published job', async () => {
    vi.stubGlobal('fetch', vi.fn().mockResolvedValueOnce(new Response('{}', { status: 201 }))
      .mockResolvedValueOnce(new Response('{}', { status: 404 })));
    await expect(publishOpportunityWithRecovery('ep_private_key', job as OpportunityRecord, signal())).rejects.toThrow('could not be confirmed');
  });
  it('rejects a success body or owned recovery with different job contents', async () => {
    vi.stubGlobal('fetch', vi.fn().mockResolvedValueOnce(created({ ...job, description: 'Different work' }))
      .mockResolvedValueOnce(owned({ ...job, description: 'Different work' })));
    await expect(publishOpportunityWithRecovery('ep_private_key', job as OpportunityRecord, signal())).rejects.toThrow('different');
  });
  it('accepts the exact created job with the server-bound account name, and projects away backend fields', async () => {
    const fetcher = vi.fn().mockResolvedValueOnce(created({ ...job, posted_by: 'Authenticated Company', owner_entity_id: OWNER, api_key: 'private-backend-key' }));
    vi.stubGlobal('fetch', fetcher);
    const result = await publishOpportunityWithRecovery('ep_private_key', job as OpportunityRecord, signal());
    expect(result).toMatchObject({ ...job, posted_by: 'Authenticated Company' });
    expect(JSON.stringify(result)).not.toMatch(/private-backend-key|owner_entity_id/);
    expect(fetcher).toHaveBeenCalledTimes(1);
  });
  it.each([409, 500, 503])('recovers HTTP %i only from identical owner-authenticated content', async (status) => {
    const controller = new AbortController();
    const fetcher = vi.fn().mockResolvedValueOnce(new Response('{}', { status })).mockResolvedValueOnce(owned());
    vi.stubGlobal('fetch', fetcher);
    expect(await publishOpportunityWithRecovery('ep_private_key', job as OpportunityRecord, controller.signal)).toMatchObject(job);
    expect(fetcher).toHaveBeenNthCalledWith(2, '/api/works/opportunities/refund-review/owned', {
      method: 'GET', headers: { authorization: 'Bearer ep_private_key' }, signal: controller.signal,
      cache: 'no-store', credentials: 'omit', redirect: 'error', referrerPolicy: 'no-referrer',
    });
  });
  it('recovers a lost response without changing the preview, ID or claim timestamps across retries', async () => {
    const claim = { statement: 'Not established.', status: 'UNKNOWN' as const, scope: 'This job only.', limitations: '' };
    const input: OpportunityFormInput = {
      opportunityId: job.opportunity_id, kind: 'problem', title: job.title, description: job.description,
      postedBy: 'A name typed by a caller', contactRoute: job.contact_route, funding: claim, authority: claim, eligibility: null,
    };
    const draft = prepareOpportunityDraft(input, '2026-09-07T10:00:00.000Z');
    const original = JSON.stringify(draft);
    const fetcher = vi.fn().mockRejectedValueOnce(new TypeError('Network failed'))
      .mockResolvedValueOnce(new Response('{}', { status: 503 }))
      .mockResolvedValueOnce(new Response('{}', { status: 409 }))
      .mockResolvedValueOnce(owned({ ...draft, posted_by: 'Authenticated Company' }));
    vi.stubGlobal('fetch', fetcher);
    await expect(publishOpportunityWithRecovery('ep_private_key', draft, signal())).rejects.toThrow('could not be confirmed');
    expect(await publishOpportunityWithRecovery('ep_private_key', draft, signal())).toMatchObject({ opportunity_id: job.opportunity_id });
    expect(fetcher.mock.calls[0][1].body).toBe(original);
    expect(fetcher.mock.calls[2][1].body).toBe(original);
    expect(draft.claims.map(c => c.observed_at)).toEqual(['2026-09-07T10:00:00.000Z', '2026-09-07T10:00:00.000Z']);
    expect(Object.isFrozen(draft)).toBe(true);
    expect(Object.isFrozen(draft.claims[0])).toBe(true);
    expect(JSON.stringify(draft)).toBe(original);
  });
  it.each([
    { collection: 'opportunities', record: job },
    { collection: 'opportunities', owned: false, record: job },
    { collection: 'listings', owned: true, record: job },
    { collection: 'opportunities', owned: true, record: { ...job, opportunity_id: 'other-job' } },
    { collection: 'opportunities', owned: true, record: { ...job, example: true } },
    { collection: 'opportunities', owned: true, record: { ...job, posted_by: '' } },
  ])('refuses public-only or malformed recovery envelopes: %j', async body => {
    vi.stubGlobal('fetch', vi.fn().mockResolvedValueOnce(new Response('{}', { status: 409 }))
      .mockResolvedValueOnce(new Response(JSON.stringify(body))));
    await expect(publishOpportunityWithRecovery('ep_private_key', job as OpportunityRecord, signal())).rejects.toThrow('could not be confirmed');
  });
  it.each([401, 403, 404, 429, 503])('does not confirm publication when owner recovery returns HTTP %i', async status => {
    vi.stubGlobal('fetch', vi.fn().mockRejectedValueOnce(new Error('Lost response'))
      .mockResolvedValueOnce(new Response('{"detail":"secret backend detail"}', { status })));
    await expect(publishOpportunityWithRecovery('ep_private_key', job as OpportunityRecord, signal())).rejects.toThrow('could not be confirmed');
  });
  it.each([400, 401, 403, 404, 422, 429])('does not retry or leak server errors after HTTP %i refuses a write', async status => {
    const fetcher = vi.fn().mockResolvedValueOnce(new Response('{"detail":"secret backend detail"}', { status }));
    vi.stubGlobal('fetch', fetcher);
    await expect(publishOpportunityWithRecovery('ep_private_key', job as OpportunityRecord, signal())).rejects.toThrow(/key|accept|Too many/);
    expect(fetcher).toHaveBeenCalledTimes(1);
  });
  it('compares every client-owned field, allowing only the server-bound poster name to differ', () => {
    expect(sameOpportunityPublication(job, { ...job, posted_by: 'Authenticated Company' })).toBe(true);
    for (const change of [{ title: 'Changed title' }, { kind: 'challenge' }, { description: 'Changed work' }, { contact_route: 'mailto:other@example.com' }, { opportunity_id: 'changed-id' }, { example: true }, { claims: [{ statement: 'Funding', status: 'UNKNOWN', scope: 'This job only', observed_at: '2026-09-07T10:00:00Z', source: null }] }]) {
      expect(sameOpportunityPublication(job, { ...job, ...change })).toBe(false);
    }
    expect(sameOpportunityPublication(null, job)).toBe(false);
  });
  it('refuses malformed keys and invalid input before a request', async () => {
    const fetcher = vi.fn(); vi.stubGlobal('fetch', fetcher);
    for (const key of ['', 'key\nvalue', 'key value', 'x'.repeat(257)]) {
      await expect(publishOpportunityWithRecovery(key, job as OpportunityRecord, signal())).rejects.toThrow('valid EMILIA key');
    }
    await expect(publishOpportunityWithRecovery('ep_private_key', { ...job, example: true } as OpportunityRecord, signal())).rejects.toThrow('valid EMILIA key');
    expect(fetcher).not.toHaveBeenCalled();
  });
  it('rejects an aborted response even when the transport ignores the abort', async () => {
    const controller = new AbortController();
    const fetcher = vi.fn().mockImplementationOnce(async () => { controller.abort(); return created(); });
    vi.stubGlobal('fetch', fetcher);
    await expect(publishOpportunityWithRecovery('ep_private_key', job as OpportunityRecord, controller.signal)).rejects.toThrow();
    expect(fetcher).toHaveBeenCalledTimes(1);
  });
  it.each(['post', 'owned'])('rejects an abort while the %s response body is being decoded', async stage => {
    const controller = new AbortController();
    const response = stage === 'post' ? created() : owned();
    vi.spyOn(response, 'json').mockImplementationOnce(async () => {
      controller.abort();
      return { collection: 'opportunities', owned: true, record: job };
    });
    const fetcher = vi.fn();
    if (stage === 'owned') fetcher.mockResolvedValueOnce(new Response('{}', { status: 409 }));
    fetcher.mockResolvedValueOnce(response);
    vi.stubGlobal('fetch', fetcher);
    await expect(publishOpportunityWithRecovery('ep_private_key', job as OpportunityRecord, controller.signal)).rejects.toThrow();
    expect(fetcher).toHaveBeenCalledTimes(stage === 'post' ? 1 : 2);
  });
});
