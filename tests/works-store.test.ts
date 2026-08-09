// SPDX-License-Identifier: Apache-2.0
//
// EMILIA Marketplace store — file backend against a temp directory. Covers CRUD,
// seed overlay + immutability, ownership enforcement on edits, and the
// fail-closed posture on malformed input.

import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { afterEach, beforeEach, describe, expect, it } from 'vitest';
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
});

afterEach(() => {
  delete process.env.WORKS_DATA_DIR;
  fs.rmSync(dir, { recursive: true, force: true });
});

const TENANT = 'tenant-a';

function newBuilder(id = 'acme-builder') {
  return {
    builder_id: id,
    kind: 'legal_entity',
    name: 'Acme Autonomy LLC',
    affiliations: [{ name: 'Acme Holdings', relation: 'parent company' }],
    contact_route: 'mailto:works@acme.example',
  };
}

describe('seed integrity', () => {
  it('every seed record passes its own validator and is marked example', () => {
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
  });

  it('seeds are listed and readable without any file backend', () => {
    return (async () => {
      const listed = await listWorksRecords('listings');
      expect(listed.ok).toBe(true);
      if (listed.ok) expect(listed.records.length).toBeGreaterThanOrEqual(6);
      const got = await getWorksRecord('listings', 'ep-conformance-catalog');
      expect(got.ok).toBe(true);
    })();
  });
});

describe('create / read / list', () => {
  it('creates a record, stamps ownership and timestamps, then reads it back', async () => {
    const created = await createWorksRecord('builders', newBuilder(), { ownerTenantId: TENANT });
    expect(created.ok).toBe(true);
    if (created.ok) {
      expect((created.record as any).owner_tenant_id).toBe(TENANT);
      expect((created.record as any).created_at).toBeTruthy();
      expect((created.record as any).example).toBe(false);
    }
    const got = await getWorksRecord('builders', 'acme-builder');
    expect(got.ok).toBe(true);
    const listed = await listWorksRecords('builders');
    expect(listed.ok).toBe(true);
    if (listed.ok) {
      expect(listed.records.some((r: any) => r.builder_id === 'acme-builder')).toBe(true);
    }
  });

  it('refuses duplicate ids', async () => {
    await createWorksRecord('builders', newBuilder(), { ownerTenantId: TENANT });
    const dup = await createWorksRecord('builders', newBuilder(), { ownerTenantId: TENANT });
    expect(dup.ok).toBe(false);
    if (!dup.ok) expect(dup.code).toBe('already_exists');
  });

  it('refuses unknown collections and malformed ids without throwing', async () => {
    const badCollection = await listWorksRecords('leaderboards');
    expect(badCollection.ok).toBe(false);
    if (!badCollection.ok) expect(badCollection.code).toBe('invalid_collection');

    const traversal = await getWorksRecord('builders', '../../etc/passwd');
    expect(traversal.ok).toBe(false);
    if (!traversal.ok) expect(traversal.code).toBe('invalid_id');
  });

  it('refuses malformed records with the validator error', async () => {
    const result = await createWorksRecord('builders', {
      builder_id: 'bad-contact', kind: 'person', name: 'X',
      contact_route: 'javascript:alert(1)',
    }, { ownerTenantId: TENANT });
    expect(result.ok).toBe(false);
    if (!result.ok) expect(result.code).toBe('invalid_contact_route');
  });

  it('refuses a VERIFIED capability card without a source artifact', async () => {
    const result = await createWorksRecord('cards', {
      card_id: 'acme-card',
      builder_id: 'acme-builder',
      claim: {
        statement: 'Operated workflow W under profile P.',
        status: 'VERIFIED',
        scope: 'workflow W at rev abc',
        source: null,
        observed_at: '2026-08-08T00:00:00Z',
      },
    }, { ownerTenantId: TENANT });
    expect(result.ok).toBe(false);
    if (!result.ok) expect(result.code).toBe('verified_requires_source');
  });
});

describe('update', () => {
  it('lets the owning tenant edit, keeps identity and ownership unpatchable', async () => {
    await createWorksRecord('builders', newBuilder(), { ownerTenantId: TENANT });
    const updated = await updateWorksRecord('builders', 'acme-builder', {
      name: 'Acme Autonomy, LLC',
      builder_id: 'stolen-id',
      owner_tenant_id: 'tenant-b',
    }, { ownerTenantId: TENANT });
    expect(updated.ok).toBe(true);
    if (updated.ok) {
      expect((updated.record as any).name).toBe('Acme Autonomy, LLC');
      expect((updated.record as any).builder_id).toBe('acme-builder');
      expect((updated.record as any).owner_tenant_id).toBe(TENANT);
    }
  });

  it('refuses edits from a different tenant', async () => {
    await createWorksRecord('builders', newBuilder(), { ownerTenantId: TENANT });
    const result = await updateWorksRecord('builders', 'acme-builder', { name: 'Hijack' }, {
      ownerTenantId: 'tenant-b',
    });
    expect(result.ok).toBe(false);
    if (!result.ok) expect(result.code).toBe('forbidden_not_owner');
  });

  it('refuses writes to seed records (create collision and edit)', async () => {
    const collide = await createWorksRecord('listings', {
      listing_id: 'ep-conformance-catalog',
      builder_id: 'acme-builder',
      kind: 'project',
      name: 'Impostor',
      summary: 'Attempt to shadow a seed record.',
    }, { ownerTenantId: TENANT });
    expect(collide.ok).toBe(false);
    if (!collide.ok) expect(collide.code).toBe('seed_immutable');

    const edit = await updateWorksRecord('listings', 'ep-conformance-catalog', {
      summary: 'Defaced',
    }, { ownerTenantId: TENANT });
    expect(edit.ok).toBe(false);
    if (!edit.ok) expect(edit.code).toBe('seed_immutable');
  });

  it('refuses a patch that would make the record invalid', async () => {
    await createWorksRecord('builders', newBuilder(), { ownerTenantId: TENANT });
    const result = await updateWorksRecord('builders', 'acme-builder', {
      contact_route: 'ftp://nope',
    }, { ownerTenantId: TENANT });
    expect(result.ok).toBe(false);
    if (!result.ok) expect(result.code).toBe('invalid_contact_route');
  });

  it('requires an owner tenant for any write', async () => {
    const created = await createWorksRecord('builders', newBuilder(), { ownerTenantId: '' });
    expect(created.ok).toBe(false);
    if (!created.ok) expect(created.code).toBe('owner_required');
  });
});

describe('file backend hygiene', () => {
  it('stores one JSON file per record under the collection directory', async () => {
    await createWorksRecord('builders', newBuilder(), { ownerTenantId: TENANT });
    const file = path.join(dir, 'builders', 'acme-builder.json');
    expect(fs.existsSync(file)).toBe(true);
    const parsed = JSON.parse(fs.readFileSync(file, 'utf8'));
    expect(parsed[WORKS_ID_FIELD.builders]).toBe('acme-builder');
  });

  it('treats a corrupt file as absent instead of throwing', async () => {
    fs.mkdirSync(path.join(dir, 'builders'), { recursive: true });
    fs.writeFileSync(path.join(dir, 'builders', 'broken-rec.json'), '{not json');
    const got = await getWorksRecord('builders', 'broken-rec');
    expect(got.ok).toBe(false);
    if (!got.ok) expect(got.code).toBe('not_found');
    const listed = await listWorksRecords('builders');
    expect(listed.ok).toBe(true);
  });
});
