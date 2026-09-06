// SPDX-License-Identifier: Apache-2.0
import { createElement } from 'react';
import { renderToStaticMarkup } from 'react-dom/server';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import WorksDirectory from '@/app/works/page';
import ListingPage from '@/app/works/listings/[id]/page';
import { listWorksRecords, getWorksRecord } from '@/lib/works/store';
import { listPublicAuthorityRecords } from '@/lib/works/authority-record-service';
import { createSupabaseAuthorityRecordStore } from '@/lib/works/authority-record-store';
import type { ActivityRecord, BuilderRecord, CapabilityCardRecord, ListingRecord } from '@/lib/works/model';
import { ClaimBadge } from '@/app/works/ui';

vi.mock('@/lib/works/store', () => ({ listWorksRecords: vi.fn(), getWorksRecord: vi.fn() }));
vi.mock('@/lib/works/authority-record-store', () => ({ createSupabaseAuthorityRecordStore: vi.fn(() => ({})) }));
vi.mock('@/lib/works/authority-record-service', () => ({ listPublicAuthorityRecords: vi.fn() }));
vi.mock('next/navigation', () => ({ notFound: () => { throw new Error('WORKS_NOT_FOUND'); } }));

const builder: BuilderRecord = {
  builder_id: 'acme-builder', kind: 'legal_entity', name: 'Acme Builder',
  contact_route: 'mailto:builder@acme.example', affiliations: [], example: false,
};
const listing = (id: string, overrides: Partial<ListingRecord> = {}): ListingRecord => ({
  listing_id: id, builder_id: builder.builder_id, kind: 'agent', name: id,
  summary: 'Research assistant with declared tools.', supported_tasks: ['research'],
  interfaces: ['MCP'], operating_constraints: ['No payment execution'],
  license: 'Apache-2.0', status: 'active', example: false,
  repository_url: 'https://example.com/acme/agent?private-payload=do-not-propagate',
  ...overrides,
});

let listings: ListingRecord[];
let cards: CapabilityCardRecord[];
let activity: ActivityRecord[];

const directory = async (params: Record<string, string | string[]> = {}) => renderToStaticMarkup(
  await WorksDirectory({ searchParams: Promise.resolve(params) }),
);
const listingDetail = async (id = 'real-agent') => renderToStaticMarkup(
  await ListingPage({ params: Promise.resolve({ id }) }),
);
const section = (html: string, id: string): string => html.match(new RegExp(`<section[^>]*id="${id}"[\\s\\S]*?<\\/section>`))?.[0] || '';

beforeEach(() => {
  vi.clearAllMocks();
  vi.stubEnv('WORKS_V0', '1');
  listings = [];
  cards = [];
  activity = [];
  vi.mocked(listWorksRecords).mockImplementation(async collection => ({
    ok: true,
    records: collection === 'listings' ? listings : collection === 'builders' ? [builder] : collection === 'cards' ? cards : collection === 'activity' ? activity : [],
  }));
  vi.mocked(getWorksRecord).mockImplementation(async (collection, id) => {
    const record = collection === 'builders' ? builder : listings.find(item => item.listing_id === id);
    return record ? { ok: true, record } : { ok: false, code: 'not_found', detail: 'Not found' };
  });
  vi.mocked(listPublicAuthorityRecords).mockResolvedValue([]);
});
afterEach(() => vi.unstubAllEnvs());

describe('marketplace storefront entry', () => {
  it('keeps directory and detail feature-gated before reading records', async () => {
    vi.stubEnv('WORKS_V0', '0');
    await expect(directory()).rejects.toThrow('WORKS_NOT_FOUND');
    await expect(listingDetail()).rejects.toThrow('WORKS_NOT_FOUND');
    expect(listWorksRecords).not.toHaveBeenCalled();
    expect(getWorksRecord).not.toHaveBeenCalled();
    expect(listPublicAuthorityRecords).not.toHaveBeenCalled();
  });

  it('leads with free scan and counts only explicitly non-example active agents', async () => {
    listings = [
      listing('real-agent'), listing('example-agent', { example: true }),
      listing('example-app', { kind: 'app', example: true }),
      listing('real-app', { kind: 'app' }), listing('real-project', { kind: 'project' }),
      listing('paused-agent', { status: 'paused' }), listing('archived-agent', { status: 'archived' }),
      listing('unmarked-agent', { example: undefined }),
    ];
    const html = await directory();
    expect(html).toContain('Discover the agent.<br/><span>Inspect its tools.</span>');
    expect(html).toContain('marketplace-tool-inspection-v1.webp');
    expect(html).toContain('Looking to manage your agents? Explore Workforce');
    expect(html).not.toContain('FIELD NOTE');
    expect(html).toContain('href="/works/scan"');
    expect(html.indexOf('Start a free scan')).toBeLessThan(html.indexOf('Browse agent listings'));
    const agents = section(html, 'works-listings');
    expect(agents).toContain('1 of 1 active agent listings · examples excluded');
    expect(agents).toContain('href="/works/listings/real-agent"');
    for (const id of ['example-agent', 'example-app', 'real-app', 'real-project', 'paused-agent', 'archived-agent', 'unmarked-agent']) {
      expect(agents).not.toContain(`href="/works/listings/${id}"`);
      expect(html).toContain(`href="/works/listings/${id}"`);
    }
    expect(section(html, 'example-listings')).toContain('href="/works/listings/example-agent"');
    expect(section(html, 'example-listings')).not.toContain('href="/works/listings/real-agent"');
    expect(html).toContain('example status unspecified');
  });

  it('shows an honest empty marketplace without treating seed examples as supply', async () => {
    listings = [listing('seed-worker', { example: true })];
    const html = await directory();
    expect(html).toContain('0 of 0 active agent listings · examples excluded');
    expect(html).toContain('No active agent listings yet.');
    expect(html).toContain('href="/works/join"');
    expect(html).toContain('href="/works/opportunities/new"');
    expect(html).toContain('Read-only examples · not marketplace supply');
    expect(section(html, 'example-listings')).toContain('seed-worker');
    expect(html).toContain('not available workers, customer deployments or proof of marketplace adoption');
  });

  it('retains the server-side search, task, interface, license and activity filters', async () => {
    listings = [listing('research-agent'), listing('finance-agent', {
      supported_tasks: ['refunds'], interfaces: ['HTTP'], license: 'MIT', summary: 'Finance assistant',
    })];
    activity = [{
      activity_id: 'release-agent', listing_id: 'research-agent', builder_id: builder.builder_id,
      type: 'release', title: 'Research release', occurred_at: '2026-09-01T00:00:00Z',
      source_url: 'https://example.com/release', scope: 'research-agent v1',
    }];
    for (const params of [{ q: 'research-agent' }, { task: 'research' }, { interface: 'MCP' }, { license: 'Apache-2.0' }, { activity: 'release' }, { q: ['research-agent', 'finance-agent'] }]) {
      const html = await directory(params);
      expect(html).toMatch(/<form(?=[^>]*method="get")(?=[^>]*action="\/works")[^>]*>/);
      expect(section(html, 'works-listings')).toContain('1 of 2 active agent listings');
      expect(section(html, 'works-listings')).toContain('href="/works/listings/research-agent"');
      expect(section(html, 'works-listings')).not.toContain('href="/works/listings/finance-agent"');
    }
    const noMatch = await directory({ q: 'no-matching-agent' });
    expect(noMatch).toContain('No active agents match these filters.');
    expect(noMatch).toContain('Reset filters');
  });

  it('does not convert a storage outage into a zero-supply or positive-evidence claim', async () => {
    vi.mocked(listWorksRecords).mockResolvedValue({ ok: false, code: 'store_unavailable', detail: 'Unavailable' });
    const html = await directory();
    expect(html).toContain('The listing directory is unavailable right now.');
    expect(html).toContain('We cannot confirm the number of agents.');
    expect(html).not.toContain('0 of 0 active agent listings');
    expect(html).not.toContain('No active agent listings yet.');
    expect(html).toContain('Missing evidence is unknown, not a favorable result.');
  });

  it('keeps scan access and available inventory when the Authority Record store cannot be constructed', async () => {
    listings = [listing('available-agent'), listing('seed-example', { example: true })];
    vi.mocked(createSupabaseAuthorityRecordStore).mockImplementationOnce(() => { throw new Error('private missing Supabase configuration'); });
    const html = await directory();
    expect(html).toContain('href="/works/scan"');
    expect(section(html, 'works-listings')).toContain('1 of 1 active agent listings');
    expect(section(html, 'works-listings')).toContain('href="/works/listings/available-agent"');
    expect(section(html, 'example-listings')).toContain('seed-example');
    const records = section(html, 'authority-records');
    expect(records).toContain('Authority Records are unavailable right now.');
    expect(records).toContain('We cannot confirm which public records are available.');
    expect(records).toContain('role="status"');
    expect(records).not.toContain('No owner-approved Authority Records');
    expect(html).not.toContain('private missing Supabase configuration');
    expect(listPublicAuthorityRecords).not.toHaveBeenCalled();
  });

  it('shows unavailable instead of no matching Authority Records when the public-record load rejects', async () => {
    listings = [listing('available-agent')];
    vi.mocked(listPublicAuthorityRecords).mockRejectedValueOnce(new Error('private backend endpoint error'));
    const html = await directory({ q: 'available-agent' });
    expect(html).toContain('href="/works/scan"');
    expect(section(html, 'works-listings')).toContain('href="/works/listings/available-agent"');
    const records = section(html, 'authority-records');
    expect(records).toContain('Authority Records are unavailable right now.');
    expect(records).not.toContain('No owner-approved Authority Records');
    expect(html).not.toContain('private backend endpoint error');
    expect(listPublicAuthorityRecords).toHaveBeenCalledTimes(1);
  });

  it('distinguishes a successful empty Authority Record response from an outage', async () => {
    const records = section(await directory(), 'authority-records');
    expect(records).toContain('No owner-approved Authority Records are public yet.');
    expect(records).not.toContain('unavailable');
  });

  it('keeps the open Gate free and scopes paid setup and support separately', async () => {
    const html = await directory();
    expect(html).toContain('The open Gate stays free. Paid setup and support are quoted separately.');
    expect(html).not.toContain('Gate is a separately scoped paid deployment');
    expect(html).not.toContain('discuss a paid Gate deployment');
  });

  it('uses only the public Authority Record projection and never counts it as agent supply', async () => {
    const records = [{ record_id: 'authority-approved', projection: {
      subject: { name: 'Owner-approved record', builder_name: 'Approved builder', repository_url: 'https://example.com/approved' },
      provenance: { observed_at: '2026-09-01T00:00:00Z', resolved_revision: 'a'.repeat(40) },
    } }] as Awaited<ReturnType<typeof listPublicAuthorityRecords>>;
    vi.mocked(listPublicAuthorityRecords).mockResolvedValue(records);
    const html = await directory();
    expect(listPublicAuthorityRecords).toHaveBeenCalledTimes(1);
    expect(html).toContain('href="/works/records/authority-approved"');
    expect(html).toContain('0 of 0 active agent listings');
    expect(html).toContain('its owner approves the exact current bytes');
    expect(html).toContain('never a favorable result');
    expect(section(await directory({ q: 'different record' }), 'authority-records')).not.toContain('Owner-approved record');
  });

  it('keeps VERIFIED attached to its claim scope and makes expired evidence UNKNOWN', async () => {
    listings = [listing('real-agent')];
    cards = [{ card_id: 'bounded-claim', listing_id: 'real-agent', builder_id: builder.builder_id, claim: {
      statement: 'Reproduced the named workflow.', status: 'VERIFIED', scope: 'Only the synthetic v1 workflow',
      source: { kind: 'content_addressed_artifact', reference: 'https://example.com/evidence.json', sha256: 'a'.repeat(64) },
      observed_at: '2025-01-01T00:00:00Z', expires_at: '2025-02-01T00:00:00Z', limitations: 'No production assessment.',
    } }];
    const html = await directory();
    const agentSection = section(html, 'works-listings');
    expect(agentSection).toContain('UNKNOWN');
    expect(agentSection).toContain('EXPIRED');
    expect(agentSection).toContain('Only the synthetic v1 workflow');
    expect(agentSection).toContain('https://example.com/evidence.json');
    expect(agentSection).toContain('No production assessment.');
    const badge = renderToStaticMarkup(createElement(ClaimBadge, { claim: cards[0].claim }));
    expect(badge).not.toContain('VERIFIED');
  });

  it('gives listings fixed scan, paid Gate and qualification routes without hiring or forwarding payloads', async () => {
    listings = [listing('real-agent')];
    const html = await listingDetail();
    for (const route of ['/works/scan', '/works/gate', '/works/qualification']) {
      expect(html).toContain(`href="${route}"`);
      expect(html).not.toContain(`href="${route}?`);
    }
    expect(html).toContain('not permission to act or certification of safety');
    expect(html).toContain('Gate deployment and commercial terms need a separate agreement.');
    expect(html).not.toMatch(/Hire now|Authorize now|<form/);
    expect(html).toContain('not to the agent as a whole');
    expect(html).toContain('No payment execution');
    listings = [listing('example-agent', { example: true })];
    expect(await listingDetail('example-agent')).toContain('not an agent available for hire or a customer deployment');
  });
});
