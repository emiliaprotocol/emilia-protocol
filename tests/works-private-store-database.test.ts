// SPDX-License-Identifier: Apache-2.0
// Exercise the production database adapter, not the deterministic file backend.
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

const database = vi.hoisted(() => ({ getServiceClient: vi.fn() }));
vi.mock('../lib/supabase.js', () => ({ getServiceClient: database.getServiceClient }));

import { getOwnedWorksRecord, listOpportunityInbox } from '../lib/works/store.ts';

const OWNER = '11111111-1111-4111-8111-111111111111';
const OTHER = '22222222-2222-4222-8222-222222222222';
const JOB = 'refund-job';
const options = { viewerEntityId: OWNER };
const opportunity = (overrides = {}) => ({
  record: { opportunity_id: JOB, example: false },
  owner_entity_id: OWNER,
  visibility: 'public',
  ...overrides,
});
const submission = (id = 'proposal-first', overrides = {}) => ({
  record: {
    submission_id: id, opportunity_id: JOB, builder_id: 'real-builder',
    listing_id: 'real-worker', proposal: 'A private proposal.', team: ['Alex'],
    created_at: '2026-09-06T07:00:00Z', ...overrides,
  },
  owner_entity_id: OTHER,
  visibility: 'private',
});

function databaseQuery() {
  return {
    select: vi.fn().mockReturnThis(), eq: vi.fn().mockReturnThis(),
    order: vi.fn().mockReturnThis(), range: vi.fn(), maybeSingle: vi.fn(),
  };
}

function installDatabase(rows: unknown = [submission()], ownedRow: unknown = opportunity()) {
  const ownerQuery = databaseQuery();
  ownerQuery.maybeSingle.mockResolvedValue({ data: ownedRow, error: null });
  const inboxQuery = databaseQuery();
  inboxQuery.range.mockResolvedValue({ data: rows, error: null });
  const from = vi.fn().mockReturnValueOnce(ownerQuery).mockReturnValueOnce(inboxQuery);
  database.getServiceClient.mockReturnValue({ from });
  return { from, ownerQuery, inboxQuery };
}

beforeEach(() => {
  // An empty override selects the production DB path without relying on the
  // caller's shell environment or a repository filesystem fixture.
  vi.stubEnv('WORKS_DATA_DIR', '');
  database.getServiceClient.mockReset();
});
afterEach(() => { vi.unstubAllEnvs(); });

describe('private proposal inbox through the database adapter', () => {
  it('checks the stored owner before issuing an exact-job, stable, bounded query', async () => {
    const { from, ownerQuery, inboxQuery } = installDatabase();
    const result = await listOpportunityInbox(JOB, options);
    expect(result).toMatchObject({ ok: true, opportunity_id: JOB, access: 'owner', offset: 0, limit: 50, has_more: false });
    expect(from.mock.calls).toEqual([['works_records'], ['works_records']]);
    expect(ownerQuery.eq.mock.calls).toEqual([['collection', 'opportunities'], ['record_id', JOB]]);
    expect(ownerQuery.maybeSingle).toHaveBeenCalledOnce();
    expect(inboxQuery.eq.mock.calls).toEqual([['collection', 'submissions'], ['record->>opportunity_id', JOB]]);
    expect(inboxQuery.order.mock.calls).toEqual([['created_at', { ascending: false }], ['record_id', { ascending: false }]]);
    // Supabase range is inclusive. The extra row supplies has_more.
    expect(inboxQuery.range).toHaveBeenCalledExactlyOnceWith(0, 50);
    expect(ownerQuery.maybeSingle.mock.invocationCallOrder[0]).toBeLessThan(inboxQuery.select.mock.invocationCallOrder[0]);
  });

  it('projects approved proposal fields and visibility without custody metadata', async () => {
    installDatabase([submission('proposal-first', { owner_entity_id: OWNER, api_key: 'PRIVATE_KEY', notes: 'PRIVATE_NOTE' })]);
    const result = await listOpportunityInbox(JOB, options);
    expect(result.ok).toBe(true);
    if (!result.ok) throw new Error(result.code);
    expect(result.records).toEqual([{
      submission_id: 'proposal-first', opportunity_id: JOB, builder_id: 'real-builder',
      listing_id: 'real-worker', proposal: 'A private proposal.', team: ['Alex'],
      example: false, visibility: 'private', created_at: '2026-09-06T07:00:00Z',
    }]);
    expect(JSON.stringify(result)).not.toMatch(/owner_entity_id|PRIVATE_KEY|PRIVATE_NOTE/);
    expect(JSON.stringify(result)).not.toContain(OTHER);
  });

  it('keeps the lookahead private and asks the database for the requested page only', async () => {
    const rows = Array.from({ length: 51 }, (_, index) => submission(`proposal-${index}`));
    const { inboxQuery } = installDatabase(rows);
    const result = await listOpportunityInbox(JOB, { ...options, offset: 50 });
    expect(result.ok).toBe(true);
    if (!result.ok) throw new Error(result.code);
    expect(inboxQuery.range).toHaveBeenCalledExactlyOnceWith(50, 100);
    expect(result.records).toHaveLength(50);
    expect(result.records.at(-1)?.submission_id).toBe('proposal-49');
    expect(result).toMatchObject({ offset: 50, limit: 50, has_more: true });
  });

  it('distinguishes an authorized empty result from a database failure', async () => {
    installDatabase([]);
    await expect(listOpportunityInbox(JOB, options)).resolves.toEqual({
      ok: true, opportunity_id: JOB, access: 'owner', records: [], offset: 0, limit: 50, has_more: false,
    });
  });

  it.each([
    ['foreign owner', opportunity({ owner_entity_id: OTHER })],
    ['missing job', null],
    ['missing owner', opportunity({ owner_entity_id: null })],
    ['non-UUID owner', opportunity({ owner_entity_id: 'owner-slug' })],
    ['example job', opportunity({ record: { opportunity_id: JOB, example: true } })],
  ])('never queries proposals for a %s', async (_label, ownedRow) => {
    const { from, inboxQuery } = installDatabase([submission()], ownedRow);
    await expect(listOpportunityInbox(JOB, options)).resolves.toMatchObject({ ok: false, code: 'not_found' });
    expect(from).toHaveBeenCalledOnce();
    expect(inboxQuery.select).not.toHaveBeenCalled();
  });

  it('labels administrator access but still queries only the exact job', async () => {
    const { inboxQuery } = installDatabase([submission()], opportunity({ owner_entity_id: OTHER }));
    await expect(listOpportunityInbox(JOB, { ...options, isAdmin: true })).resolves.toMatchObject({ ok: true, access: 'administrator' });
    expect(inboxQuery.eq).toHaveBeenCalledWith('record->>opportunity_id', JOB);
  });

  it('stops after ownership storage fails and does not expose the database error', async () => {
    const { from, ownerQuery } = installDatabase();
    ownerQuery.maybeSingle.mockResolvedValue({ data: null, error: { message: 'PRIVATE_DATABASE_ERROR' } });
    const result = await listOpportunityInbox(JOB, options);
    expect(result).toMatchObject({ ok: false, code: 'store_unavailable' });
    expect(JSON.stringify(result)).not.toContain('PRIVATE_DATABASE_ERROR');
    expect(from).toHaveBeenCalledOnce();
  });

  it.each([
    ['query error', { data: [], error: { message: 'PRIVATE_DATABASE_ERROR' } }],
    ['missing data', { data: null, error: null }],
    ['non-array data', { data: {}, error: null }],
    ['oversized page', { data: Array.from({ length: 52 }, (_, index) => submission(`proposal-${index}`)), error: null }],
    ['malformed row', { data: [null], error: null }],
    ['malformed record', { data: [{ record: 'PRIVATE_DATABASE_ERROR' }], error: null }],
  ])('fails closed on %s instead of returning an empty inbox', async (_label, response) => {
    const { inboxQuery } = installDatabase();
    inboxQuery.range.mockResolvedValue(response);
    const result = await listOpportunityInbox(JOB, options);
    expect(result).toEqual({ ok: false, code: 'store_unavailable', detail: 'Inbox storage could not be read.' });
    expect(result).not.toHaveProperty('records');
  });

  it('handles a rejected proposal query without leaking the exception', async () => {
    const { inboxQuery } = installDatabase();
    inboxQuery.range.mockRejectedValue(new Error('PRIVATE_DATABASE_ERROR'));
    await expect(listOpportunityInbox(JOB, options)).resolves.toEqual({
      ok: false, code: 'store_unavailable', detail: 'Inbox storage could not be read.',
    });
  });

  it.each([
    ['another job', [submission('proposal-first', { opportunity_id: 'another-job' })]],
    ['invalid submission', [submission('proposal-first', { proposal: '' })]],
    ['example submission', [submission('proposal-first', { example: true })]],
    ['duplicate submission IDs', [submission(), submission()]],
    ['invalid lookahead', [...Array.from({ length: 50 }, (_, index) => submission(`proposal-${index}`)), submission('proposal-bad', { opportunity_id: 'another-job' })]],
  ])('refuses the entire page when returned rows contain %s', async (_label, rows) => {
    installDatabase(rows);
    await expect(listOpportunityInbox(JOB, options)).resolves.toMatchObject({ ok: false, code: 'store_unavailable' });
  });

  it.each([undefined, 'invalid-date', 'x'.repeat(41)])('omits an invalid optional timestamp: %s', async created_at => {
    installDatabase([submission('proposal-first', { created_at })]);
    const result = await listOpportunityInbox(JOB, options);
    expect(result.ok).toBe(true);
    if (!result.ok) throw new Error(result.code);
    expect(result.records[0]).not.toHaveProperty('created_at');
  });

  it.each([-1, 1, 50.5, 100_050, NaN, Infinity])('refuses invalid page offset %s before any database read', async offset => {
    await expect(listOpportunityInbox(JOB, { ...options, offset })).resolves.toMatchObject({ ok: false, code: 'invalid_offset' });
    expect(database.getServiceClient).not.toHaveBeenCalled();
  });
});

describe('owner-only recovery through the database adapter', () => {
  it('does not accept a valid but differently identified database record as the requested profile', async () => {
    installDatabase([], { owner_entity_id: OWNER, record: {
      builder_id: 'different-builder', kind: 'person', name: 'A different builder',
      contact_route: 'mailto:builder@example.com',
    } });
    await expect(getOwnedWorksRecord('builders', 'real-builder', { ownerEntityId: OWNER }))
      .resolves.toMatchObject({ ok: false, code: 'store_unavailable' });
  });

  it('refuses a malformed owner record rather than confirming publication recovery', async () => {
    installDatabase([], { owner_entity_id: OWNER, record: { builder_id: 'real-builder' } });
    await expect(getOwnedWorksRecord('builders', 'real-builder', { ownerEntityId: OWNER }))
      .resolves.toMatchObject({ ok: false, code: 'store_unavailable' });
  });
});
