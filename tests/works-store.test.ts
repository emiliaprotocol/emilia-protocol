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

describe('fail-closed model validation', () => {
  it('rejects malformed values at every Works record boundary', () => {
    const builder = newBuilder();
    const listing = newListing();
    const activity = {
      activity_id: 'acme-activity',
      builder_id: 'acme-builder',
      listing_id: 'acme-listing',
      type: 'demo',
      title: 'Demo',
      occurred_at: '2026-08-08T00:00:00Z',
      source_url: 'https://example.com/demo',
      scope: 'Pinned test scope.',
    };
    const assertedClaim = {
      statement: 'A claimant assertion.',
      status: 'ASSERTED',
      scope: 'Pinned test scope.',
      source: { kind: 'claimant', reference: 'mailto:builder@example.com' },
      observed_at: '2026-08-08T00:00:00Z',
    };
    const card = {
      card_id: 'acme-card',
      builder_id: 'acme-builder',
      listing_id: 'acme-listing',
      claim: assertedClaim,
    };
    const opportunity = newOpportunity();
    const submission = newSubmission('acme-submission');

    const cases: Array<{
      validate: (value: unknown) => { ok: boolean; code?: string };
      value: unknown;
      code: string;
    }> = [
      { validate: validateBuilder, value: null, code: 'invalid_builder' },
      { validate: validateBuilder, value: { ...builder, builder_id: 'x' }, code: 'invalid_builder_id' },
      { validate: validateBuilder, value: { ...builder, kind: 'company' }, code: 'invalid_builder_kind' },
      { validate: validateBuilder, value: { ...builder, name: '' }, code: 'invalid_builder_name' },
      { validate: validateBuilder, value: { ...builder, contact_route: 42 }, code: 'invalid_contact_route' },
      { validate: validateBuilder, value: { ...builder, affiliations: {} }, code: 'invalid_affiliations' },
      { validate: validateBuilder, value: { ...builder, affiliations: ['Acme'] }, code: 'invalid_affiliations' },
      { validate: validateBuilder, value: { ...builder, affiliations: [{ name: '', relation: 'parent' }] }, code: 'invalid_affiliations' },
      { validate: validateBuilder, value: { ...builder, summary: '' }, code: 'invalid_builder_summary' },
      { validate: validateBuilder, value: { ...builder, links: {} }, code: 'invalid_links' },
      { validate: validateBuilder, value: { ...builder, links: ['http://example.com'] }, code: 'invalid_links' },

      { validate: validateListing, value: null, code: 'invalid_listing' },
      { validate: validateListing, value: { ...listing, listing_id: 'x' }, code: 'invalid_listing_id' },
      { validate: validateListing, value: { ...listing, builder_id: 'x' }, code: 'invalid_builder_id' },
      { validate: validateListing, value: { ...listing, kind: 'service' }, code: 'invalid_listing_kind' },
      { validate: validateListing, value: { ...listing, name: '' }, code: 'invalid_listing_name' },
      { validate: validateListing, value: { ...listing, summary: '' }, code: 'invalid_listing_summary' },
      { validate: validateListing, value: { ...listing, status: 'unknown' }, code: 'invalid_listing_status' },
      { validate: validateListing, value: { ...listing, repository_url: 'http://example.com' }, code: 'invalid_repository_url' },
      { validate: validateListing, value: { ...listing, service_url: 'http://example.com' }, code: 'invalid_service_url' },
      { validate: validateListing, value: { ...listing, license: '' }, code: 'invalid_license' },
      { validate: validateListing, value: { ...listing, supported_tasks: {} }, code: 'invalid_supported_tasks' },
      { validate: validateListing, value: { ...listing, supported_tasks: [42] }, code: 'invalid_supported_tasks' },
      { validate: validateListing, value: { ...listing, interfaces: {} }, code: 'invalid_interfaces' },
      { validate: validateListing, value: { ...listing, operating_constraints: {} }, code: 'invalid_operating_constraints' },

      { validate: validateActivity, value: null, code: 'invalid_activity' },
      { validate: validateActivity, value: { ...activity, activity_id: 'x' }, code: 'invalid_activity_id' },
      { validate: validateActivity, value: { ...activity, listing_id: 'x' }, code: 'invalid_listing_id' },
      { validate: validateActivity, value: { ...activity, builder_id: 'x' }, code: 'invalid_builder_id' },
      { validate: validateActivity, value: { ...activity, type: 'claim' }, code: 'invalid_activity_type' },
      { validate: validateActivity, value: { ...activity, title: '' }, code: 'invalid_activity_title' },
      { validate: validateActivity, value: { ...activity, occurred_at: 'not-a-date' }, code: 'invalid_occurred_at' },
      { validate: validateActivity, value: { ...activity, source_url: 'http://example.com' }, code: 'invalid_source_url' },
      { validate: validateActivity, value: { ...activity, scope: '' }, code: 'invalid_activity_scope' },

      { validate: validateCapabilityCard, value: null, code: 'invalid_capability_card' },
      { validate: validateCapabilityCard, value: { ...card, card_id: 'x' }, code: 'invalid_card_id' },
      { validate: validateCapabilityCard, value: { ...card, builder_id: 'x' }, code: 'invalid_builder_id' },
      { validate: validateCapabilityCard, value: { ...card, listing_id: 'x' }, code: 'invalid_listing_id' },
      { validate: validateCapabilityCard, value: { ...card, claim: null }, code: 'invalid_claim' },

      { validate: validateOpportunity, value: null, code: 'invalid_opportunity' },
      { validate: validateOpportunity, value: { ...opportunity, opportunity_id: 'x' }, code: 'invalid_opportunity_id' },
      { validate: validateOpportunity, value: { ...opportunity, kind: 'job' }, code: 'invalid_opportunity_kind' },
      { validate: validateOpportunity, value: { ...opportunity, title: '' }, code: 'invalid_opportunity_title' },
      { validate: validateOpportunity, value: { ...opportunity, description: '' }, code: 'invalid_opportunity_description' },
      { validate: validateOpportunity, value: { ...opportunity, posted_by: '' }, code: 'invalid_posted_by' },
      { validate: validateOpportunity, value: { ...opportunity, contact_route: 'ftp://example.com' }, code: 'invalid_contact_route' },
      { validate: validateOpportunity, value: { ...opportunity, claims: {} }, code: 'invalid_opportunity_claims' },
      { validate: validateOpportunity, value: { ...opportunity, claims: [null] }, code: 'invalid_claim' },

      { validate: validateSubmission, value: null, code: 'invalid_submission' },
      { validate: validateSubmission, value: { ...submission, submission_id: 'x' }, code: 'invalid_submission_id' },
      { validate: validateSubmission, value: { ...submission, opportunity_id: 'x' }, code: 'invalid_opportunity_id' },
      { validate: validateSubmission, value: { ...submission, builder_id: 'x' }, code: 'invalid_builder_id' },
      { validate: validateSubmission, value: { ...submission, listing_id: 'x' }, code: 'invalid_listing_id' },
      { validate: validateSubmission, value: { ...submission, proposal: '' }, code: 'invalid_proposal' },
      { validate: validateSubmission, value: { ...submission, team: {} }, code: 'invalid_team' },
      { validate: validateSubmission, value: { ...submission, team: [42] }, code: 'invalid_team' },
    ];

    for (const testCase of cases) {
      const result = testCase.validate(testCase.value);
      expect(result.ok).toBe(false);
      expect(result.code).toBe(testCase.code);
    }
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

  it('rejects invalid write envelopes and visibility changes before persistence', async () => {
    const invalidCollection = await createWorksRecord('rankings', newBuilder(), {
      ownerEntityId: OWNER_A,
    });
    expect(invalidCollection.ok).toBe(false);
    if (!invalidCollection.ok) expect(invalidCollection.code).toBe('invalid_collection');

    const missingOwner = await createWorksRecord('builders', newBuilder(), {
      ownerEntityId: '',
    });
    expect(missingOwner.ok).toBe(false);
    if (!missingOwner.ok) expect(missingOwner.code).toBe('owner_required');

    const legacyPublic = await createWorksRecord('builders', { ...newBuilder(), public: true }, {
      ownerEntityId: OWNER_A,
    });
    expect(legacyPublic.ok).toBe(false);
    if (!legacyPublic.ok) expect(legacyPublic.code).toBe('invalid_visibility');

    const wrongCollectionVisibility = await createWorksRecord('builders', {
      ...newBuilder('visible-builder'), visibility: 'public',
    }, { ownerEntityId: OWNER_A });
    expect(wrongCollectionVisibility.ok).toBe(false);
    if (!wrongCollectionVisibility.ok) expect(wrongCollectionVisibility.code).toBe('invalid_visibility');

    const cycle: Record<string, any> = newBuilder('cycle-builder');
    cycle.self = cycle;
    expect((await createWorksRecord('builders', cycle, { ownerEntityId: OWNER_A })).ok).toBe(true);

    await createWorksRecord('builders', newBuilder(), { ownerEntityId: OWNER_A });
    const updates: Array<[unknown, unknown, unknown, string]> = [
      ['rankings', 'acme-builder', {}, 'invalid_collection'],
      ['builders', '../acme', {}, 'invalid_id'],
      ['builders', 'acme-builder', {}, 'owner_required'],
      ['builders', 'acme-builder', 'rename', 'invalid_patch'],
      ['builders', 'acme-builder', { status: 'VERIFIED' }, 'verified_claim_forbidden'],
      ['builders', 'acme-builder', { visibility: 'public' }, 'invalid_visibility'],
      ['builders', 'acme-builder', { name: '' }, 'invalid_builder_name'],
    ];
    for (const [collection, id, patchValue, code] of updates) {
      const result = await updateWorksRecord(collection, id, patchValue, {
        ownerEntityId: code === 'owner_required' ? '' : OWNER_A,
      });
      expect(result.ok).toBe(false);
      if (!result.ok) expect(result.code).toBe(code);
    }
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

  it('updates through Supabase and fails closed on durable-store errors', async () => {
    delete process.env.WORKS_DATA_DIR;
    const storedBuilder = {
      record: {
        ...newBuilder(),
        affiliations: [{ name: 'Acme Holdings', relation: 'parent company' }],
        example: false,
        created_at: '2026-08-08T00:00:00Z',
        updated_at: '2026-08-08T00:00:00Z',
      },
      owner_entity_id: OWNER_A,
      visibility: 'private',
    };

    function clientForMaybeSingles(responses: Array<{ data: any; error: any }>) {
      const query: Record<string, any> = {};
      query.select = vi.fn(() => query);
      query.eq = vi.fn(() => query);
      query.update = vi.fn(() => query);
      query.maybeSingle = vi.fn(async () => responses.shift() || { data: null, error: null });
      return { from: vi.fn(() => query), query };
    }

    const success = clientForMaybeSingles([
      { data: storedBuilder, error: null },
      { data: { record_id: 'acme-builder' }, error: null },
    ]);
    supabaseMocks.getServiceClient.mockReturnValue(success);
    const updated = await updateWorksRecord('builders', 'acme-builder', { name: 'Acme Updated' }, {
      ownerEntityId: OWNER_A,
    });
    expect(updated.ok).toBe(true);
    expect(success.query.update).toHaveBeenCalledTimes(1);

    const noMatchedOwner = clientForMaybeSingles([
      { data: storedBuilder, error: null },
      { data: null, error: null },
    ]);
    supabaseMocks.getServiceClient.mockReturnValue(noMatchedOwner);
    const refused = await updateWorksRecord('builders', 'acme-builder', { name: 'No match' }, {
      ownerEntityId: OWNER_A,
    });
    expect(refused.ok).toBe(false);
    if (!refused.ok) expect(refused.code).toBe('forbidden_not_owner');

    const writeError = clientForMaybeSingles([
      { data: storedBuilder, error: null },
      { data: null, error: { message: 'write failed' } },
    ]);
    supabaseMocks.getServiceClient.mockReturnValue(writeError);
    const unavailable = await updateWorksRecord('builders', 'acme-builder', { name: 'Unavailable' }, {
      ownerEntityId: OWNER_A,
    });
    expect(unavailable.ok).toBe(false);
    if (!unavailable.ok) expect(unavailable.code).toBe('store_unavailable');

    const readError = clientForMaybeSingles([{ data: null, error: { message: 'read failed' } }]);
    supabaseMocks.getServiceClient.mockReturnValue(readError);
    const unreadable = await getWorksRecord('builders', 'missing-builder');
    expect(unreadable.ok).toBe(false);
    if (!unreadable.ok) expect(unreadable.code).toBe('store_unavailable');

    supabaseMocks.getServiceClient.mockImplementation(() => {
      throw new Error('client unavailable');
    });
    const thrown = await getWorksRecord('builders', 'missing-builder');
    expect(thrown.ok).toBe(false);
    if (!thrown.ok) expect(thrown.code).toBe('store_unavailable');
  });

  it('filters malformed Supabase rows and maps insertion conflicts without guessing', async () => {
    delete process.env.WORKS_DATA_DIR;

    const listQuery: Record<string, any> = {};
    listQuery.select = vi.fn(() => listQuery);
    listQuery.eq = vi.fn(() => listQuery);
    listQuery.order = vi.fn(async () => ({
      data: [null, { record: null }, {
        record: newBuilder('public-builder'),
        owner_entity_id: OWNER_A,
        visibility: 'public',
      }],
      error: null,
    }));
    supabaseMocks.getServiceClient.mockReturnValue({ from: vi.fn(() => listQuery) });
    const listed = await listWorksRecords('builders');
    expect(listed.ok).toBe(true);
    if (listed.ok) {
      expect(listed.records.some((record: any) => record.builder_id === 'public-builder')).toBe(true);
    }

    const listErrorQuery: Record<string, any> = {};
    listErrorQuery.select = vi.fn(() => listErrorQuery);
    listErrorQuery.eq = vi.fn(() => listErrorQuery);
    listErrorQuery.order = vi.fn(async () => ({ data: null, error: { message: 'list failed' } }));
    supabaseMocks.getServiceClient.mockReturnValue({ from: vi.fn(() => listErrorQuery) });
    const listError = await listWorksRecords('builders');
    expect(listError.ok).toBe(false);
    if (!listError.ok) expect(listError.code).toBe('store_unavailable');

    const maybeSingle = vi.fn(async () => ({ data: null, error: null }));
    const insert = vi.fn(async () => ({ error: { code: '23505' } }));
    const createQuery: Record<string, any> = {};
    createQuery.select = vi.fn(() => createQuery);
    createQuery.eq = vi.fn(() => createQuery);
    createQuery.maybeSingle = maybeSingle;
    createQuery.insert = insert;
    supabaseMocks.getServiceClient.mockReturnValue({ from: vi.fn(() => createQuery) });
    const duplicate = await createWorksRecord('builders', newBuilder(), { ownerEntityId: OWNER_A });
    expect(duplicate.ok).toBe(false);
    if (!duplicate.ok) expect(duplicate.code).toBe('already_exists');
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
    fs.writeFileSync(path.join(dir, 'builders', 'README.txt'), 'ignored');
    fs.writeFileSync(path.join(dir, 'builders', '--.json'), '{}');
    fs.writeFileSync(path.join(dir, 'builders', 'wrong-shape.json'), JSON.stringify({ record: null }));
    const got = await getWorksRecord('builders', 'broken-rec');
    expect(got.ok).toBe(false);
    if (!got.ok) expect(got.code).toBe('not_found');
    expect((await listWorksRecords('builders')).ok).toBe(true);
  });
});
