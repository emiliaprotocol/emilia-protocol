// SPDX-License-Identifier: Apache-2.0
//
// EMILIA Marketplace — record store (backend-agnostic, file-backed v0).
//
// Same pattern as lib/trust-desk/store.ts: a clean async interface backed by
// per-record JSON files under data/works/<collection>/<id>.json (override the
// root with WORKS_DATA_DIR for tests). Zero-config locally and in tests;
// NOTE: Vercel's runtime filesystem is read-only, so production writes need a
// database backend swapped in behind this same interface later. No live
// database is touched by this module.
//
// Read-only example seeds (lib/works/seed.ts) are overlaid under every
// collection; writes to a seed id are refused with a typed error. Every entry
// point returns { ok, ... } — malformed input or a store fault never throws.

import fs from 'node:fs';
import path from 'node:path';
import {
  validateActivity,
  validateBuilder,
  validateCapabilityCard,
  validateListing,
  validateOpportunity,
  validateSubmission,
  validWorksId,
  type ModelResult,
  type WorksRecord,
} from './model.js';
import { SEED } from './seed.js';

export const WORKS_COLLECTIONS = Object.freeze([
  'builders', 'listings', 'cards', 'activity', 'opportunities', 'submissions',
] as const);

export type WorksCollection = (typeof WORKS_COLLECTIONS)[number];

export const WORKS_ID_FIELD: Record<WorksCollection, string> = Object.freeze({
  builders: 'builder_id',
  listings: 'listing_id',
  cards: 'card_id',
  activity: 'activity_id',
  opportunities: 'opportunity_id',
  submissions: 'submission_id',
});

const VALIDATORS: Record<WorksCollection, (input: unknown) => ModelResult<any>> = {
  builders: validateBuilder,
  listings: validateListing,
  cards: validateCapabilityCard,
  activity: validateActivity,
  opportunities: validateOpportunity,
  submissions: validateSubmission,
};

export type StoreError = { ok: false; code: string; detail: string };
export type StoreOk<T> = { ok: true } & T;
export type StoreResult<T> = StoreOk<T> | StoreError;

function err(code: string, detail: string): StoreError {
  return { ok: false, code, detail };
}

function isCollection(value: unknown): value is WorksCollection {
  return typeof value === 'string'
    && (WORKS_COLLECTIONS as readonly string[]).includes(value);
}

function dataDir(): string {
  return process.env.WORKS_DATA_DIR || path.join(process.cwd(), 'data', 'works');
}

function collectionDir(collection: WorksCollection): string {
  return path.join(dataDir(), collection);
}

function fileFor(collection: WorksCollection, id: string): string {
  // validWorksId is checked by every caller before this point; the pattern
  // admits only [a-z0-9-], so the joined path cannot traverse.
  return path.join(collectionDir(collection), `${id}.json`);
}

function isoNow(): string {
  return new Date().toISOString();
}

function recordId(collection: WorksCollection, record: any): string | null {
  const id = record?.[WORKS_ID_FIELD[collection]];
  return validWorksId(id) ? id : null;
}

function seedRecords(collection: WorksCollection): WorksRecord[] {
  return SEED[collection] as unknown as WorksRecord[];
}

export function isSeedRecordId(collection: WorksCollection, id: string): boolean {
  return seedRecords(collection).some((record) => recordId(collection, record) === id);
}

function readFileRecord(collection: WorksCollection, id: string): WorksRecord | null {
  try {
    const file = fileFor(collection, id);
    if (!fs.existsSync(file)) return null;
    const parsed = JSON.parse(fs.readFileSync(file, 'utf8'));
    return parsed && typeof parsed === 'object' ? parsed : null;
  } catch {
    // A corrupt file behaves like an absent record rather than throwing
    // through a request handler.
    return null;
  }
}

export async function listWorksRecords(
  collection: unknown,
): Promise<StoreResult<{ records: WorksRecord[] }>> {
  if (!isCollection(collection)) return err('invalid_collection', 'unknown Works collection');
  const byId = new Map<string, WorksRecord>();
  for (const record of seedRecords(collection)) {
    const id = recordId(collection, record);
    if (id) byId.set(id, record);
  }
  try {
    const dir = collectionDir(collection);
    if (fs.existsSync(dir)) {
      for (const name of fs.readdirSync(dir)) {
        if (!name.endsWith('.json')) continue;
        const id = name.slice(0, -'.json'.length);
        if (!validWorksId(id) || byId.has(id)) continue;
        const record = readFileRecord(collection, id);
        if (record) byId.set(id, record);
      }
    }
  } catch {
    return err('store_unavailable', 'Works storage could not be read.');
  }
  return { ok: true, records: [...byId.values()] };
}

export async function getWorksRecord(
  collection: unknown,
  id: unknown,
): Promise<StoreResult<{ record: WorksRecord }>> {
  if (!isCollection(collection)) return err('invalid_collection', 'unknown Works collection');
  if (!validWorksId(id)) return err('invalid_id', 'record id must match [a-z0-9-], 3-64 chars');
  const seed = seedRecords(collection).find((record) => recordId(collection, record) === id);
  if (seed) return { ok: true, record: seed };
  const record = readFileRecord(collection, id);
  if (!record) return err('not_found', 'record not found');
  return { ok: true, record };
}

export async function createWorksRecord(
  collection: unknown,
  input: unknown,
  options: { ownerTenantId: string },
): Promise<StoreResult<{ record: WorksRecord }>> {
  if (!isCollection(collection)) return err('invalid_collection', 'unknown Works collection');
  if (typeof options?.ownerTenantId !== 'string' || options.ownerTenantId.length === 0) {
    return err('owner_required', 'an authenticated owner tenant is required to create records');
  }
  const validated = VALIDATORS[collection](input);
  if (!validated.ok) return validated;
  const record = validated.record;
  const id = recordId(collection, record);
  if (!id) return err('invalid_id', 'record id must match [a-z0-9-], 3-64 chars');
  if (isSeedRecordId(collection, id)) {
    return err('seed_immutable', 'this id belongs to a read-only example record');
  }
  try {
    const file = fileFor(collection, id);
    if (fs.existsSync(file)) return err('already_exists', 'a record with this id already exists');
    const now = isoNow();
    const stored = {
      ...record,
      example: record.example === true,
      owner_tenant_id: options.ownerTenantId,
      created_at: now,
      updated_at: now,
    };
    fs.mkdirSync(collectionDir(collection), { recursive: true });
    fs.writeFileSync(file, JSON.stringify(stored, null, 2));
    return { ok: true, record: stored };
  } catch {
    return err('store_unavailable', 'Works storage could not be written.');
  }
}

export async function updateWorksRecord(
  collection: unknown,
  id: unknown,
  patch: unknown,
  options: { ownerTenantId: string },
): Promise<StoreResult<{ record: WorksRecord }>> {
  if (!isCollection(collection)) return err('invalid_collection', 'unknown Works collection');
  if (!validWorksId(id)) return err('invalid_id', 'record id must match [a-z0-9-], 3-64 chars');
  if (typeof options?.ownerTenantId !== 'string' || options.ownerTenantId.length === 0) {
    return err('owner_required', 'an authenticated owner tenant is required to edit records');
  }
  if (typeof patch !== 'object' || patch === null || Array.isArray(patch)) {
    return err('invalid_patch', 'patch must be an object');
  }
  if (isSeedRecordId(collection, id)) {
    return err('seed_immutable', 'example records are read-only');
  }
  const current = readFileRecord(collection, id);
  if (!current) return err('not_found', 'record not found');
  if ((current as any).owner_tenant_id !== options.ownerTenantId) {
    return err('forbidden_not_owner', 'only the owning tenant may edit this record');
  }

  const idField = WORKS_ID_FIELD[collection];
  const merged = {
    ...current,
    ...(patch as Record<string, unknown>),
    // Identity and ownership are not patchable.
    [idField]: id,
    owner_tenant_id: (current as any).owner_tenant_id,
    example: (current as any).example === true,
  };
  const validated = VALIDATORS[collection](merged);
  if (!validated.ok) return validated;
  const stored = {
    ...validated.record,
    owner_tenant_id: (current as any).owner_tenant_id,
    created_at: (current as any).created_at,
    updated_at: isoNow(),
  };
  try {
    fs.writeFileSync(fileFor(collection, id), JSON.stringify(stored, null, 2));
    return { ok: true, record: stored };
  } catch {
    return err('store_unavailable', 'Works storage could not be written.');
  }
}
