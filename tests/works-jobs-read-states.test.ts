// SPDX-License-Identifier: Apache-2.0
import { createElement } from 'react';
import { renderToStaticMarkup } from 'react-dom/server';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import OpportunitiesPage from '@/app/works/opportunities/page';
import OpportunityPage from '@/app/works/opportunities/[id]/page';
import { getWorksRecord, listWorksRecords } from '@/lib/works/store';
import type { OpportunityRecord, SubmissionRecord } from '@/lib/works/model';

vi.mock('@/lib/works/store', () => ({ getWorksRecord: vi.fn(), listWorksRecords: vi.fn() }));
vi.mock('next/navigation', () => ({ notFound: () => { throw new Error('WORKS_NOT_FOUND'); } }));
vi.mock('@/app/works/SubmissionForm', () => ({
  default: ({ opportunityId }: { opportunityId: string }) => createElement('div', { 'data-proposal-form': opportunityId }),
}));

type VisibleSubmission = SubmissionRecord & { visibility?: 'private' | 'public' };
const job = (id: string, example = false): OpportunityRecord => ({
  opportunity_id: id, kind: 'problem', title: `Job ${id}`, description: 'Prepare a refunds review for the finance owner.',
  posted_by: 'Finance owner', contact_route: 'mailto:owner@example.com', claims: [], example,
});
const proposal = (id: string, overrides: Partial<VisibleSubmission> = {}): VisibleSubmission => ({
  submission_id: id, opportunity_id: 'refund-job', builder_id: 'builder-one', listing_id: 'worker-one',
  proposal: `Proposal ${id}`, visibility: 'public', example: false, ...overrides,
});
const unavailable = { ok: false as const, code: 'store_unavailable', detail: 'private database connection details' };
const section = (html: string, id: string) => html.match(new RegExp(`<section[^>]*id="${id}"[\\s\\S]*?<\\/section>`))?.[0] || '';
let jobs: OpportunityRecord[];
let proposals: VisibleSubmission[];
let failedCollections: string[];
const board = async () => renderToStaticMarkup(await OpportunitiesPage());
const detail = async (id = 'refund-job') => renderToStaticMarkup(await OpportunityPage({ params: Promise.resolve({ id }) }));

beforeEach(() => {
  vi.clearAllMocks();
  vi.stubEnv('WORKS_V0', '1');
  jobs = [job('refund-job')];
  proposals = [];
  failedCollections = [];
  vi.mocked(listWorksRecords).mockImplementation(async (collection) => failedCollections.includes(collection)
    ? unavailable
    : { ok: true, records: collection === 'opportunities' ? jobs : collection === 'submissions' ? proposals : [] });
  vi.mocked(getWorksRecord).mockImplementation(async (_collection, id) => {
    const record = jobs.find(item => item.opportunity_id === id);
    return record ? { ok: true, record } : { ok: false, code: 'not_found', detail: 'Not found' };
  });
});
afterEach(() => vi.unstubAllEnvs());

describe('public marketplace job read states', () => {
  it('checks the feature gate before reading the board or a job', async () => {
    vi.stubEnv('WORKS_V0', '0');
    await expect(board()).rejects.toThrow('WORKS_NOT_FOUND');
    await expect(detail()).rejects.toThrow('WORKS_NOT_FOUND');
    expect(listWorksRecords).not.toHaveBeenCalled();
    expect(getWorksRecord).not.toHaveBeenCalled();
  });

  it('shows a retryable board outage without claiming that no jobs exist', async () => {
    failedCollections = ['opportunities'];
    const html = await board();
    expect(html).toContain('The jobs board is unavailable right now.');
    expect(html).toContain('Reload jobs');
    expect(html).toContain('id="main-content"');
    expect(html).not.toMatch(/No (opportunities|jobs) posted|0 jobs/);
    expect(html).not.toContain(unavailable.detail);
  });

  it('keeps read-only examples out of posted jobs and their response links', async () => {
    jobs = [job('example-job', true), job('refund-job')];
    const html = await board();
    const posted = section(html, 'posted-jobs');
    const examples = section(html, 'example-jobs');
    expect(posted).toContain('Job refund-job');
    expect(posted).not.toContain('Job example-job');
    expect(examples).toContain('Job example-job');
    expect(examples).toContain('Read-only examples');
    expect(examples).toContain('View example');
    expect(examples).not.toMatch(/View and respond|View job and respond/);
    expect(examples).not.toContain('public proposal');
  });

  it('shows an honest empty jobs board even when examples exist', async () => {
    jobs = [job('example-job', true)];
    const html = await board();
    expect(section(html, 'posted-jobs')).toContain('No jobs posted yet.');
    expect(section(html, 'posted-jobs')).toContain('Describe your job');
    expect(section(html, 'example-jobs')).toContain('Job example-job');
  });

  it('labels public proposal counts and excludes private or example proposals', async () => {
    proposals = [proposal('public-one'), proposal('private-one', { visibility: 'private' }), proposal('unknown-one', { visibility: undefined }), proposal('example-one', { example: true })];
    const html = await board();
    expect(section(html, 'posted-jobs')).toContain('1 public proposal');
    expect(html).not.toContain('4 submissions');
    expect(html).toContain('Private proposals are not counted here.');
    expect(listWorksRecords).toHaveBeenCalledWith('submissions');
  });

  it('retains posted jobs when proposal counts cannot be loaded', async () => {
    failedCollections = ['submissions'];
    const html = await board();
    expect(section(html, 'posted-jobs')).toContain('Job refund-job');
    expect(html).toContain('Public proposal counts are unavailable.');
    expect(html).not.toContain('0 public proposals');
    expect(html).not.toContain(unavailable.detail);
  });

  it('keeps a good brief, response form and owner inbox when public proposals are unavailable', async () => {
    failedCollections = ['submissions'];
    const html = await detail();
    expect(html).toContain('Job refund-job');
    expect(html).toContain('data-proposal-form="refund-job"');
    expect(html).toContain('href="/works/opportunities/refund-job/inbox"');
    expect(html).toContain('Public proposals are unavailable right now.');
    expect(html).toContain('Reload proposals');
    expect(html).toMatch(/<a href="\/works\/opportunities\/refund-job"[^>]*>Reload proposals<\/a>/);
    expect(html).not.toMatch(/No public (submissions|proposals) yet/);
    expect(html).not.toContain(unavailable.detail);
  });

  it('does not turn an unavailable brief into a not-found result', async () => {
    vi.mocked(getWorksRecord).mockResolvedValue(unavailable);
    const html = await detail();
    expect(html).toContain('This job could not be loaded right now.');
    expect(html).toContain('Reload job');
    expect(html).toContain('id="main-content"');
    expect(html).not.toContain(unavailable.detail);
    expect(listWorksRecords).not.toHaveBeenCalled();
  });

  it('still returns not-found for a genuinely missing job', async () => {
    await expect(detail('missing-job')).rejects.toThrow('WORKS_NOT_FOUND');
    expect(listWorksRecords).not.toHaveBeenCalled();
  });

  it('retains public proposal text and stable IDs if builder and listing lookups fail', async () => {
    proposals = [proposal('public-one')];
    failedCollections = ['builders', 'listings'];
    const html = await detail();
    expect(html).toContain('Proposal public-one');
    expect(html).toContain('builder-one');
    expect(html).toContain('worker-one');
    expect(html).toContain('Some builder or agent details could not be loaded.');
    expect(html).not.toContain(unavailable.detail);
  });

  it('never renders private or example proposal bodies as live responses', async () => {
    proposals = [proposal('private-secret', { visibility: 'private' }), proposal('unspecified-secret', { visibility: undefined }), proposal('example-secret', { example: true })];
    const html = await detail();
    expect(html).toContain('No public proposals yet.');
    expect(html).toContain('Private proposals do not appear on this page.');
    for (const id of ['private-secret', 'unspecified-secret', 'example-secret']) expect(html).not.toContain(`Proposal ${id}`);
  });

  it('keeps example briefs read-only and labels their example responses', async () => {
    jobs = [job('example-job', true)];
    proposals = [proposal('example-one', { opportunity_id: 'example-job', example: true, visibility: undefined })];
    const html = await detail('example-job');
    expect(html).toContain('This is a read-only example opportunity.');
    expect(html).toContain('Example proposals');
    expect(html).toContain('Proposal example-one');
    expect(html).not.toContain('data-proposal-form');
    expect(html).not.toContain('/example-job/inbox');
  });
});
