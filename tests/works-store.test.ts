// SPDX-License-Identifier: Apache-2.0
//
// EMILIA Works store regressions. WORKS_DATA_DIR deliberately selects the
// deterministic file backend; an absent override must select Supabase.

import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

const supabaseMocks = vi.hoisted(() => ({
  getServiceClient: vi.fn(),
}));

vi.mock('../lib/supabase.js', () => ({
  getServiceClient: supabaseMocks.getServiceClient,
}));

import {
  createWorksRecord,
  getWorksRecord,
  listWorksRecords,
  updateWorksRecord,
  WORKS_COLLECTIONS,
  WORKS_ID_FIELD,
} from '../lib/works/store.ts';
import { SEED } from '../lib/works/seed.ts';
import {
  validateActivity,
  validateBuilder,
  validateCapabilityCard,
  validateListing,
  validateOpportunity,
  validateSubmission,
} from '../lib/works/model.ts';

let dir: string;

beforeEach(() => {
  dir = fs.mkdtempSync(path.join(os.tmpdir(), 'works-store-'));
  process.env.WORKS_DATA_DIR = dir;
  supabaseMocks.getServiceClient.mockReset();
});

afterEach(() => {
  delete process.env.WORKS_DATA_DIR;
  fs.rmSync(dir, { recursive: true, force: true });
});

const OWNER_A = '11111111-1111-4111-8111-111111111111';
const OWNER_B = '22222222-2222-4222-8222-222222222222';

function newBuilder(id = 'acme-builder') {
  return {
    builder_id: id,
    kind: 'legal_entity',
    name: 'Acme Autonomy LLC',
    affiliations: [{ name: 'Acme Holdings', relation: 'parent company' }],
    contact_route: 'mailto:works@acme.example',
  };
}

function newListing(id = 'acme-listing', builderId = 'acme-builder') {
  return {
    listing_id: id,
    builder_id: builderId,
    kind: 'agent',
    name: 'Acme Agent',
    summary: 'A bounded test listing.',
    supported_tasks: ['test'],
    interfaces: ['https'],
    operating_constraints: ['test only'],
    status: 'active',
  };
}

function newOpportunity(id = 'acme-opportunity') {
  return {
    opportunity_id: id,
    kind: 'challenge',
    title: 'Bounded challenge',
    description: 'Submit a bounded proposal.',
    posted_by: 'Authenticated Entity',
    contact_route: 'mailto:buyer@example.com',
    claims: [],
  };
}

function newSubmission(id: string, overrides: Record<string, unknown> = {}) {
  return {
    submission_id: id,
    opportunity_id: 'acme-opportunity',
    builder_id: 'acme-builder',
    listing_id: 'acme-listing',
    proposal: 'A bounded proposal.',
    ...overrides,
  };
}

async function createOwnedBuilderAndListing(ownerEntityId = OWNER_A, suffix = '') {
  const builderId = `acme-builder${suffix}`;
  const listingId = `acme-listing${suffix}`;
  expect((await createWorksRecord('builders', newBuilder(builderId), { ownerEntityId })).ok).toBe(true);
  expect((await createWorksRecord('listings', newListing(listingId, builderId), { ownerEntityId })).ok).toBe(true);
  return { builderId, listingId };
}

describe('seed integrity', () => {
  it('keeps every example seed valid and public-readable', async () => {
    const validators = {
      builders: validateBuilder,
      listings: validateListing,
      cards: validateCapabilityCard,
      activity: validateActivity,
      opportunities: validateOpportunity,
      submissions: validateSubmission,
    } as const;
    for (const collection of WORKS_COLLECTIONS) {
      for (const record of SEED[collection]) {
        const result = validators[collection](record);
        expect(result.ok, `${collection}: ${JSON.stringify((result as any).code)}`).toBe(true);
        expect((record as any).example).toBe(true);
      }
    }

    const listed = await listWorksRecords('listings');
    expect(listed.ok).toBe(true);
    const got = await getWorksRecord('listings', 'ep-conformance-catalog');
    expect(got.ok).toBe(true);
  });
});

describe('create / read / list', () => {
  it('keeps the stable entity DB owner out of the record payload', async () => {
    const created = await createWorksRecord('builders', newBuilder(), { ownerEntityId: OWNER_A });
    expect(created.ok).toBe(true);
    if (created.ok) {
      expect((created.record as any).owner_entity_id).toBeUndefined();
      expect((created.record as any).owner_tenant_id).toBeUndefined();
      expect((created.record as any).created_at).toBeTruthy();
      expect((created.record as any).example).toBe(false);
    }
    expect((await getWorksRecord('builders', 'acme-builder')).ok).toBe(true);
    const listed = await listWorksRecords('builders');
    expect(listed.ok).toBe(true);
    if (listed.ok) {
      expect(listed.records.some((record: any) => record.builder_id === 'acme-builder')).toBe(true);
    }
  });

  it('refuses duplicate ids, malformed ownership, collections, ids, and records', async () => {
    await createWorksRecord('builders', newBuilder(), { ownerEntityId: OWNER_A });
    const duplicate = await createWorksRecord('builders', newBuilder(), { ownerEntityId: OWNER_A });
    expect(duplicate.ok).toBe(false);
    if (!duplicate.ok) expect(duplicate.code).toBe('already_exists');

    const owner = await createWorksRecord('builders', newBuilder('other-builder'), {
      ownerEntityId: 'entity-public-slug',
    });
    expect(owner.ok).toBe(false);
    if (!owner.ok) expect(owner.code).toBe('owner_required');

    const collection = await listWorksRecords('leaderboards');
    expect(collection.ok).toBe(false);
    if (!collection.ok) expect(collection.code).toBe('invalid_collection');

    const traversal = await getWorksRecord('builders', '../../etc/passwd');
    expect(traversal.ok).toBe(false);
    if (!traversal.ok) expect(traversal.code).toBe('invalid_id');

    const malformed = await createWorksRecord('builders', {
      builder_id: 'bad-contact', kind: 'person', name: 'X',
      contact_route: 'javascript:alert(1)',
    }, { ownerEntityId: OWNER_A });
    expect(malformed.ok).toBe(false);
    if (!malformed.ok) expect(malformed.code).toBe('invalid_contact_route');
  });

  it('rejects any self-service write containing VERIFIED, even with a URL and hash', async () => {
    await createWorksRecord('builders', newBuilder(), { ownerEntityId: OWNER_A });
    const result = await createWorksRecord('cards', {
      card_id: 'acme-card',
      builder_id: 'acme-builder',
      claim: {
        statement: 'Operated workflow W under profile P.',
        status: 'VERIFIED',
        scope: 'workflow W at rev abc',
        source: {
          kind: 'content_addressed_artifact',
          reference: 'https://example.com/artifact.json',
          sha256: 'e011fb3538f973cfcea6d02df79500af1d7ab74ee85667b46790633063294058',
        },
        observed_at: '2026-08-08T00:00:00Z',
      },
    }, { ownerEntityId: OWNER_A });
    expect(result.ok).toBe(false);
    if (!result.ok) expect(result.code).toBe('verified_claim_forbidden');
  });

  it('rejects user-created example records and example promotion on PATCH', async () => {
    const created = await createWorksRecord('builders', { ...newBuilder(), example: true }, {
      ownerEntityId: OWNER_A,
    });
    expect(created.ok).toBe(false);
    if (!created.ok) expect(created.code).toBe('example_reserved');

    await createWorksRecord('builders', newBuilder(), { ownerEntityId: OWNER_A });
    const patched = await updateWorksRecord('builders', 'acme-builder', { example: true }, {
      ownerEntityId: OWNER_A,
    });
    expect(patched.ok).toBe(false);
    if (!patched.ok) expect(patched.code).toBe('example_reserved');
  });
});

describe('same-owner relationships', () => {
  it('requires listing builders to exist and have the same owner', async () => {
    const missing = await createWorksRecord('listings', newListing(), { ownerEntityId: OWNER_A });
    expect(missing.ok).toBe(false);
    if (!missing.ok) expect(missing.code).toBe('reference_not_found');

    await createWorksRecord('builders', newBuilder(), { ownerEntityId: OWNER_B });
    const foreign = await createWorksRecord('listings', newListing(), { ownerEntityId: OWNER_A });
    expect(foreign.ok).toBe(false);
    if (!foreign.ok) expect(foreign.code).toBe('forbidden_reference_owner');
  });

  it('checks activity/card/submission builder and listing references', async () => {
    await createOwnedBuilderAndListing(OWNER_A);
    await createWorksRecord('opportunities', newOpportunity(), { ownerEntityId: OWNER_B });

    const activity = await createWorksRecord('activity', {
      activity_id: 'acme-activity',
      builder_id: 'acme-builder',
      listing_id: 'missing-listing',
      type: 'demo',
      title: 'Demo',
      occurred_at: '2026-08-08T00:00:00Z',
      source_url: 'https://example.com/demo',
      scope: 'Test demo.',
    }, { ownerEntityId: OWNER_A });
    expect(activity.ok).toBe(false);
    if (!activity.ok) expect(activity.code).toBe('reference_not_found');

    const card = await createWorksRecord('cards', {
      card_id: 'acme-card',
      builder_id: 'missing-builder',
      claim: {
        statement: 'A claimant assertion.',
        status: 'ASSERTED',
        scope: 'Test scope.',
        source: { kind: 'claimant', reference: 'mailto:builder@example.com' },
        observed_at: '2026-08-08T00:00:00Z',
      },
    }, { ownerEntityId: OWNER_A });
    expect(card.ok).toBe(false);
    if (!card.ok) expect(card.code).toBe('reference_not_found');

    const submission = await createWorksRecord('submissions', newSubmission('acme-submission', {
      listing_id: 'missing-listing',
    }), { ownerEntityId: OWNER_A });
    expect(submission.ok).toBe(false);
    if (!submission.ok) expect(submission.code).toBe('reference_not_found');
  });

  it('rejects submissions to read-only example opportunities to match the SQL guard', async () => {
    await createOwnedBuilderAndListing(OWNER_A);
    const result = await createWorksRecord('submissions', newSubmission('seed-target-submission', {
      opportunity_id: 'ex-reproduce-conformance',
    }), { ownerEntityId: OWNER_A });
    expect(result.ok).toBe(false);
    if (!result.ok) expect(result.code).toBe('seed_reference_forbidden');
  });

  it('rechecks changed references on PATCH and rejects cross-owner links', async () => {
    const own = await createOwnedBuilderAndListing(OWNER_A);
    const foreign = await createOwnedBuilderAndListing(OWNER_B, '-foreign');
    const created = await createWorksRecord('activity', {
      activity_id: 'acme-activity',
      builder_id: own.builderId,
      listing_id: own.listingId,
      type: 'demo',
      title: 'Demo',
      occurred_at: '2026-08-08T00:00:00Z',
      source_url: 'https://example.com/demo',
      scope: 'Test demo.',
    }, { ownerEntityId: OWNER_A });
    expect(created.ok).toBe(true);

    const patched = await updateWorksRecord('activity', 'acme-activity', {
      builder_id: foreign.builderId,
      listing_id: foreign.listingId,
    }, { ownerEntityId: OWNER_A });
    expect(patched.ok).toBe(false);
    if (!patched.ok) expect(patched.code).toBe('forbidden_reference_owner');
  });
});

describe('ownership and visibility', () => {
  it('does not treat an unmarked example submission as explicitly public', async () => {
    const listed = await listWorksRecords('submissions');
    expect(listed.ok).toBe(true);
    if (listed.ok) {
      expect(listed.records.some((record: any) => (
        record.submission_id === 'ex-submission-conformance'
      ))).toBe(false);
    }
    const anonymous = await getWorksRecord('submissions', 'ex-submission-conformance');
    expect(anonymous.ok).toBe(false);
    expect((await getWorksRecord('submissions', 'ex-submission-conformance', {
      isAdmin: true,
    })).ok).toBe(true);
  });

  it('allows only the owning entity to edit and keeps identity/ownership unpatchable', async () => {
    await createWorksRecord('builders', newBuilder(), { ownerEntityId: OWNER_A });
    const foreign = await updateWorksRecord('builders', 'acme-builder', { name: 'Hijack' }, {
      ownerEntityId: OWNER_B,
    });
    expect(foreign.ok).toBe(false);
    if (!foreign.ok) expect(foreign.code).toBe('forbidden_not_owner');

    const updated = await updateWorksRecord('builders', 'acme-builder', {
      name: 'Acme Autonomy, LLC',
      builder_id: 'stolen-id',
      owner_entity_id: OWNER_B,
    }, { ownerEntityId: OWNER_A });
    expect(updated.ok).toBe(true);
    if (updated.ok) {
      expect((updated.record as any).builder_id).toBe('acme-builder');
      expect((updated.record as any).owner_entity_id).toBeUndefined();
    }
  });

  it('models submissions as private by default and exposes only explicit public visibility', async () => {
    await createOwnedBuilderAndListing(OWNER_A);
    await createWorksRecord('opportunities', newOpportunity(), { ownerEntityId: OWNER_B });
    expect((await createWorksRecord('submissions', newSubmission('private-submission'), {
      ownerEntityId: OWNER_A,
    })).ok).toBe(true);
    expect((await createWorksRecord('submissions', newSubmission('public-submission', {
      visibility: 'public',
    }), {
      ownerEntityId: OWNER_A,
    })).ok).toBe(true);

    const listed = await listWorksRecords('submissions');
    expect(listed.ok).toBe(true);
    if (listed.ok) {
      expect(listed.records.some((record: any) => record.submission_id === 'private-submission')).toBe(false);
      expect(listed.records.some((record: any) => record.submission_id === 'public-submission')).toBe(true);
    }
    const privateRecord = await getWorksRecord('submissions', 'private-submission');
    expect(privateRecord.ok).toBe(false);
    if (!privateRecord.ok) expect(privateRecord.code).toBe('not_found');
    expect((await getWorksRecord('submissions', 'public-submission')).ok).toBe(true);
  });

  it('lets only the submitter, opportunity owner, or admin read a private submission', async () => {
    await createOwnedBuilderAndListing(OWNER_A);
    await createWorksRecord('opportunities', newOpportunity(), { ownerEntityId: OWNER_B });
    const created = await createWorksRecord('submissions', newSubmission('private-submission'), {
      ownerEntityId: OWNER_A,
    });
    expect(created.ok).toBe(true);
    if (created.ok) expect((created.record as any).visibility).toBe('private');

    expect((await getWorksRecord('submissions', 'private-submission')).ok).toBe(false);
    expect((await getWorksRecord('submissions', 'private-submission', {
      viewerEntityId: OWNER_A,
    })).ok).toBe(true);
    expect((await getWorksRecord('submissions', 'private-submission', {
      viewerEntityId: OWNER_B,
    })).ok).toBe(true);
    expect((await getWorksRecord('submissions', 'private-submission', {
      viewerEntityId: '33333333-3333-4333-8333-333333333333',
    })).ok).toBe(false);
    expect((await getWorksRecord('submissions', 'private-submission', {
      viewerEntityId: '33333333-3333-4333-8333-333333333333',
      isAdmin: true,
    })).ok).toBe(true);
  });

  it('keeps example seed ids immutable', async () => {
    const collide = await createWorksRecord('listings', {
      ...newListing('ep-conformance-catalog'),
    }, { ownerEntityId: OWNER_A });
    expect(collide.ok).toBe(false);
    if (!collide.ok) expect(collide.code).toBe('seed_immutable');

    const edit = await updateWorksRecord('listings', 'ep-conformance-catalog', {
      summary: 'Defaced',
    }, { ownerEntityId: OWNER_A });
    expect(edit.ok).toBe(false);
    if (!edit.ok) expect(edit.code).toBe('seed_immutable');
  });
});

describe('backend selection and file hygiene', () => {
  it('uses Supabase and never the implicit repository filesystem when WORKS_DATA_DIR is absent', async () => {
    delete process.env.WORKS_DATA_DIR;
    const query = {
      select: vi.fn().mockReturnThis(),
      eq: vi.fn().mockReturnThis(),
      order: vi.fn().mockResolvedValue({ data: [], error: null }),
    };
    const from = vi.fn().mockReturnValue(query);
    supabaseMocks.getServiceClient.mockReturnValue({ from });

    const listed = await listWorksRecords('builders');
    expect(listed.ok).toBe(true);
    expect(supabaseMocks.getServiceClient).toHaveBeenCalledTimes(1);
    expect(from).toHaveBeenCalledWith('works_records');
  });

  it('persists production records as Supabase rows with ownership outside record JSON', async () => {
    delete process.env.WORKS_DATA_DIR;
    const rows = new Map<string, Record<string, any>>();
    const from = vi.fn(() => {
      const filters: Record<string, unknown> = {};
      const query: Record<string, any> = {};
      query.select = vi.fn(() => query);
      query.eq = vi.fn((field: string, value: unknown) => {
        filters[field] = value;
        return query;
      });
      query.maybeSingle = vi.fn(async () => ({
        data: rows.get(`${filters.collection}:${filters.record_id}`) || null,
        error: null,
      }));
      query.insert = vi.fn(async (row: Record<string, any>) => {
        rows.set(`${row.collection}:${row.record_id}`, row);
        return { error: null };
      });
      return query;
    });
    supabaseMocks.getServiceClient.mockReturnValue({ from });

    const created = await createWorksRecord('builders', newBuilder(), { ownerEntityId: OWNER_A });
    expect(created.ok).toBe(true);
    const row = rows.get('builders:acme-builder');
    expect(row?.owner_entity_id).toBe(OWNER_A);
    expect(row?.record.owner_entity_id).toBeUndefined();
    const fetched = await getWorksRecord('builders', 'acme-builder');
    expect(fetched.ok).toBe(true);
    if (fetched.ok) expect((fetched.record as any).owner_entity_id).toBeUndefined();
  });

  it('uses one deterministic JSON file per record only with WORKS_DATA_DIR', async () => {
    await createWorksRecord('builders', newBuilder(), { ownerEntityId: OWNER_A });
    const file = path.join(dir, 'builders', 'acme-builder.json');
    expect(fs.existsSync(file)).toBe(true);
    const parsed = JSON.parse(fs.readFileSync(file, 'utf8'));
    expect(parsed.owner_entity_id).toBe(OWNER_A);
    expect(parsed.record[WORKS_ID_FIELD.builders]).toBe('acme-builder');
    expect(parsed.record.owner_entity_id).toBeUndefined();
    expect(supabaseMocks.getServiceClient).not.toHaveBeenCalled();
  });

  it('treats a corrupt test-backend file as absent instead of throwing', async () => {
    fs.mkdirSync(path.join(dir, 'builders'), { recursive: true });
    fs.writeFileSync(path.join(dir, 'builders', 'broken-rec.json'), '{not json');
    const got = await getWorksRecord('builders', 'broken-rec');
    expect(got.ok).toBe(false);
    if (!got.ok) expect(got.code).toBe('not_found');
    expect((await listWorksRecords('builders')).ok).toBe(true);
  });
});
