// SPDX-License-Identifier: Apache-2.0
//
// EMILIA Works — durable record store.
//
// WORKS_DATA_DIR is the explicit deterministic-test switch. When it is set,
// records use per-record JSON files. In every other environment records use
// public.works_records through the server service role; there is no implicit
// repository/Vercel filesystem fallback.

import fs from 'node:fs';
import path from 'node:path';
import { getServiceClient } from '../supabase.js';
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

const WORKS_TABLE = 'works_records';
const ENTITY_DB_ID = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;

type StoredRecord = WorksRecord & {
  example?: boolean;
  visibility?: 'private' | 'public';
  created_at?: string;
  updated_at?: string;
};

type StoredRow = {
  record: StoredRecord;
  ownerEntityId: string | null;
  visibility: 'private' | 'public';
};

export type WorksReadOptions = {
  viewerEntityId?: string;
  isAdmin?: boolean;
};

export type StoreError = { ok: false; code: string; detail: string };
export type StoreOk<T> = { ok: true } & T;
export type StoreResult<T> = StoreOk<T> | StoreError;

function err(code: string, detail: string): StoreError {
  return { ok: false, code, detail };
}

function isPlainObject(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

function isCollection(value: unknown): value is WorksCollection {
  return typeof value === 'string'
    && (WORKS_COLLECTIONS as readonly string[]).includes(value);
}

function usesFileBackend(): boolean {
  return typeof process.env.WORKS_DATA_DIR === 'string'
    && process.env.WORKS_DATA_DIR.length > 0;
}

function dataDir(): string {
  // Called only after usesFileBackend() succeeds.
  return process.env.WORKS_DATA_DIR as string;
}

function collectionDir(collection: WorksCollection): string {
  return path.join(dataDir(), collection);
}

function fileFor(collection: WorksCollection, id: string): string {
  // validWorksId is checked before this point; the pattern cannot traverse.
  return path.join(collectionDir(collection), `${id}.json`);
}

function fileOpportunityWorkflowState(id: string): StoreResult<{ state: string }> {
  const file = path.join(dataDir(), '_workflow', 'opportunities', `${id}.json`);
  try {
    if (!fs.existsSync(file)) return { ok: true, state: 'open' };
    const parsed = JSON.parse(fs.readFileSync(file, 'utf8'));
    if (!isPlainObject(parsed) || !['open', 'closed', 'assigned'].includes(String(parsed.state))
      || !Number.isSafeInteger(parsed.revision) || Number(parsed.revision) < 0) {
      return err('store_unavailable', 'Works workflow storage could not be read.');
    }
    return { ok: true, state: String(parsed.state) };
  } catch {
    return err('store_unavailable', 'Works workflow storage could not be read.');
  }
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

function containsVerifiedStatus(value: unknown, seen = new Set<object>()): boolean {
  if (typeof value !== 'object' || value === null) return false;
  if (seen.has(value)) return false;
  seen.add(value);
  if (Array.isArray(value)) {
    return value.some((item) => containsVerifiedStatus(item, seen));
  }
  for (const [key, nested] of Object.entries(value as Record<string, unknown>)) {
    if (key === 'status' && typeof nested === 'string' && nested.trim().toUpperCase() === 'VERIFIED') {
      return true;
    }
    if (containsVerifiedStatus(nested, seen)) return true;
  }
  return false;
}

function requestedVisibility(
  collection: WorksCollection,
  input: Record<string, unknown>,
  current: 'private' | 'public' = 'private',
): StoreResult<{ visibility: 'private' | 'public' }> {
  if (Object.hasOwn(input, 'public')) {
    return err('invalid_visibility', 'use visibility=private or visibility=public for submissions');
  }
  if (!Object.hasOwn(input, 'visibility')) return { ok: true, visibility: current };
  if (collection !== 'submissions'
    || (input.visibility !== 'private' && input.visibility !== 'public')) {
    return err(
      'invalid_visibility',
      'visibility must be private or public and is supported only for submissions',
    );
  }
  return { ok: true, visibility: input.visibility };
}

function readFileStoredRow(collection: WorksCollection, id: string): StoredRow | null {
  try {
    const file = fileFor(collection, id);
    if (!fs.existsSync(file)) return null;
    const parsed = JSON.parse(fs.readFileSync(file, 'utf8'));
    if (!isPlainObject(parsed) || !isPlainObject(parsed.record)) return null;
    return {
      record: parsed.record as unknown as StoredRecord,
      ownerEntityId: typeof parsed.owner_entity_id === 'string' ? parsed.owner_entity_id : null,
      visibility: collection === 'submissions' && parsed.visibility === 'public'
        ? 'public'
        : 'private',
    };
  } catch {
    // A corrupt deterministic fixture behaves as absent and never escapes.
    return null;
  }
}

function normalizeDatabaseRow(value: unknown): StoredRow | null {
  if (!isPlainObject(value) || !isPlainObject(value.record)) return null;
  return {
    record: value.record as unknown as StoredRecord,
    ownerEntityId: typeof value.owner_entity_id === 'string' ? value.owner_entity_id : null,
    visibility: value.visibility === 'public' ? 'public' : 'private',
  };
}

async function readDatabaseStoredRow(
  collection: WorksCollection,
  id: string,
): Promise<StoreResult<{ row: StoredRow | null }>> {
  try {
    const { data, error } = await getServiceClient()
      .from(WORKS_TABLE)
      .select('record, owner_entity_id, visibility')
      .eq('collection', collection)
      .eq('record_id', id)
      .maybeSingle();
    if (error) return err('store_unavailable', 'Works storage could not be read.');
    return { ok: true, row: data ? normalizeDatabaseRow(data) : null };
  } catch {
    return err('store_unavailable', 'Works storage could not be read.');
  }
}

async function readStoredRow(
  collection: WorksCollection,
  id: string,
): Promise<StoreResult<{ row: StoredRow | null }>> {
  if (usesFileBackend()) return { ok: true, row: readFileStoredRow(collection, id) };
  return readDatabaseStoredRow(collection, id);
}

async function listStoredRows(
  collection: WorksCollection,
  includePrivate: boolean,
): Promise<StoreResult<{ rows: StoredRow[] }>> {
  if (usesFileBackend()) {
    const rows: StoredRow[] = [];
    try {
      const dir = collectionDir(collection);
      if (!fs.existsSync(dir)) return { ok: true, rows };
      for (const name of fs.readdirSync(dir)) {
        if (!name.endsWith('.json')) continue;
        const id = name.slice(0, -'.json'.length);
        if (!validWorksId(id)) continue;
        const row = readFileStoredRow(collection, id);
        if (row && (collection !== 'submissions' || includePrivate || row.visibility === 'public')) {
          rows.push(row);
        }
      }
      return { ok: true, rows };
    } catch {
      return err('store_unavailable', 'Works storage could not be read.');
    }
  }

  try {
    let query = getServiceClient()
      .from(WORKS_TABLE)
      .select('record, owner_entity_id, visibility')
      .eq('collection', collection);
    if (collection === 'submissions' && !includePrivate) query = query.eq('visibility', 'public');
    const { data, error } = await query.order('created_at', { ascending: true });
    if (error) return err('store_unavailable', 'Works storage could not be read.');
    const rows = (Array.isArray(data) ? data : [])
      .map(normalizeDatabaseRow)
      .filter((row): row is StoredRow => row !== null);
    return { ok: true, rows };
  } catch {
    return err('store_unavailable', 'Works storage could not be read.');
  }
}

async function writeCreatedRecord(
  collection: WorksCollection,
  id: string,
  stored: StoredRecord,
  ownerEntityId: string,
  visibility: 'private' | 'public',
): Promise<StoreResult<{ complete?: never }>> {
  if (usesFileBackend()) {
    try {
      fs.mkdirSync(collectionDir(collection), { recursive: true });
      fs.writeFileSync(fileFor(collection, id), JSON.stringify({
        collection,
        record_id: id,
        owner_entity_id: ownerEntityId,
        visibility,
        record: stored,
        created_at: stored.created_at,
        updated_at: stored.updated_at,
      }, null, 2));
      return { ok: true };
    } catch {
      return err('store_unavailable', 'Works storage could not be written.');
    }
  }

  try {
    const { error } = await getServiceClient().from(WORKS_TABLE).insert({
      collection,
      record_id: id,
      owner_entity_id: ownerEntityId,
      record: stored,
      visibility,
      created_at: stored.created_at,
      updated_at: stored.updated_at,
    });
    if (error?.code === '23505') return err('already_exists', 'a record with this id already exists');
    if (error?.code === 'EWTRN') return err('invalid_transition', 'This job is not accepting proposals.');
    if (error) return err('store_unavailable', 'Works storage could not be written.');
    return { ok: true };
  } catch {
    return err('store_unavailable', 'Works storage could not be written.');
  }
}

async function writeUpdatedRecord(
  collection: WorksCollection,
  id: string,
  stored: StoredRecord,
  ownerEntityId: string,
  visibility: 'private' | 'public',
): Promise<StoreResult<{ complete?: never }>> {
  if (usesFileBackend()) {
    try {
      fs.writeFileSync(fileFor(collection, id), JSON.stringify({
        collection,
        record_id: id,
        owner_entity_id: ownerEntityId,
        visibility,
        record: stored,
        created_at: stored.created_at,
        updated_at: stored.updated_at,
      }, null, 2));
      return { ok: true };
    } catch {
      return err('store_unavailable', 'Works storage could not be written.');
    }
  }

  try {
    const { data, error } = await getServiceClient()
      .from(WORKS_TABLE)
      .update({ record: stored, visibility, updated_at: stored.updated_at })
      .eq('collection', collection)
      .eq('record_id', id)
      .eq('owner_entity_id', ownerEntityId)
      .select('record_id')
      .maybeSingle();
    if (error?.code === 'EWTRN') {
      return err('invalid_transition', 'Listing status changes require a workflow command.');
    }
    if (error) return err('store_unavailable', 'Works storage could not be written.');
    if (!data) return err('forbidden_not_owner', 'only the owning entity may edit this record');
    return { ok: true };
  } catch {
    return err('store_unavailable', 'Works storage could not be written.');
  }
}

async function ownedReference(
  collection: WorksCollection,
  id: string,
  ownerEntityId: string,
): Promise<StoreResult<{ record: StoredRecord }>> {
  if (isSeedRecordId(collection, id)) {
    return err('forbidden_reference_owner', 'referenced records must belong to the authenticated entity');
  }
  const loaded = await readStoredRow(collection, id);
  if (!loaded.ok) return loaded;
  if (!loaded.row) return err('reference_not_found', `${collection} reference was not found`);
  if (loaded.row.ownerEntityId !== ownerEntityId) {
    return err('forbidden_reference_owner', 'referenced records must belong to the authenticated entity');
  }
  return { ok: true, record: loaded.row.record };
}

async function existingReference(
  collection: WorksCollection,
  id: string,
): Promise<StoreResult<{ record: StoredRecord | WorksRecord }>> {
  const seed = seedRecords(collection).find((record) => recordId(collection, record) === id);
  if (seed) {
    return err(
      'seed_reference_forbidden',
      'submissions must target a durable, non-example opportunity record',
    );
  }
  const loaded = await readStoredRow(collection, id);
  if (!loaded.ok) return loaded;
  if (!loaded.row) return err('reference_not_found', `${collection} reference was not found`);
  return { ok: true, record: loaded.row.record };
}

async function validateRelationships(
  collection: WorksCollection,
  record: WorksRecord,
  ownerEntityId: string,
): Promise<StoreResult<{ complete?: never }>> {
  const value = record as any;
  if (collection === 'builders' || collection === 'opportunities') return { ok: true };

  const builder = await ownedReference('builders', value.builder_id, ownerEntityId);
  if (!builder.ok) return builder;

  if (collection === 'listings') return { ok: true };

  if (value.listing_id) {
    const listing = await ownedReference('listings', value.listing_id, ownerEntityId);
    if (!listing.ok) return listing;
    if ((listing.record as any).builder_id !== value.builder_id) {
      return err('reference_mismatch', 'listing_id does not belong to builder_id');
    }
  } else if (collection === 'activity') {
    return err('reference_not_found', 'activity requires a listing reference');
  }

  if (collection === 'submissions') {
    const opportunity = await existingReference('opportunities', value.opportunity_id);
    if (!opportunity.ok) return opportunity;
  }
  return { ok: true };
}

/** A private employer inbox is narrower than the generic submission reader.
 * Verify the stored opportunity owner before touching any submissions. Public
 * visibility or authorship of one proposal does not grant employer access. */
export async function listOpportunityInbox(
  id: unknown,
  options: WorksReadOptions & { offset?: number } = {},
): Promise<StoreResult<{
  opportunity_id: string;
  access: 'owner' | 'administrator';
  records: StoredRecord[];
  offset: number;
  limit: number;
  has_more: boolean;
}>> {
  const limit = 50;
  const offset = options.offset ?? 0;
  if (!ENTITY_DB_ID.test(options.viewerEntityId || '')) return err('owner_required', 'An authenticated entity is required.');
  if (!validWorksId(id) || isSeedRecordId('opportunities', id)) return err('not_found', 'Inbox not found.');
  if (!Number.isSafeInteger(offset) || offset < 0 || offset > 100_000 || offset % limit !== 0) {
    return err('invalid_offset', 'Choose a valid inbox page.');
  }
  const opportunity = await readStoredRow('opportunities', id);
  if (!opportunity.ok) return opportunity;
  const owner = opportunity.row?.ownerEntityId;
  if (!opportunity.row || opportunity.row.record.example === true || !ENTITY_DB_ID.test(owner || '')
    || (owner !== options.viewerEntityId && options.isAdmin !== true)) return err('not_found', 'Inbox not found.');

  let rows: StoredRow[];
  if (usesFileBackend()) {
    const result = await listStoredRows('submissions', true);
    if (!result.ok) return result;
    rows = result.rows.filter(row => (row.record as any).opportunity_id === id && row.record.example !== true)
      .sort((a, b) => (b.record.created_at || '').localeCompare(a.record.created_at || '')
        || String(recordId('submissions', b.record)).localeCompare(String(recordId('submissions', a.record))))
      .slice(offset, offset + limit + 1);
  } else {
    try {
      const { data, error } = await getServiceClient().from(WORKS_TABLE)
        .select('record, owner_entity_id, visibility')
        .eq('collection', 'submissions').eq('record->>opportunity_id', id)
        .order('created_at', { ascending: false }).order('record_id', { ascending: false })
        .range(offset, offset + limit);
      if (error || !Array.isArray(data) || data.length > limit + 1) return err('store_unavailable', 'Inbox storage could not be read.');
      const normalized = data.map(normalizeDatabaseRow);
      if (normalized.some(row => row === null)) return err('store_unavailable', 'Inbox storage could not be read.');
      rows = normalized as StoredRow[];
    } catch { return err('store_unavailable', 'Inbox storage could not be read.'); }
  }

  const records: StoredRecord[] = [];
  const ids = new Set<string>();
  for (const row of rows) {
    const validated = validateSubmission(row.record);
    if (!validated.ok || validated.record.opportunity_id !== id || validated.record.example === true
      || ids.has(validated.record.submission_id)) return err('store_unavailable', 'Inbox storage could not be read.');
    ids.add(validated.record.submission_id);
    const created = row.record.created_at;
    records.push({ ...validated.record, visibility: row.visibility,
      ...(typeof created === 'string' && created.length <= 40 && Number.isFinite(Date.parse(created)) ? { created_at: created } : {}),
    });
  }
  return { ok: true, opportunity_id: id, access: owner === options.viewerEntityId ? 'owner' : 'administrator',
    records: records.slice(0, limit), offset, limit, has_more: records.length > limit,
  };
}

async function canReadSubmission(
  row: StoredRow,
  options: WorksReadOptions,
): Promise<StoreResult<{ allowed: boolean }>> {
  if (row.visibility === 'public' || options.isAdmin === true) {
    return { ok: true, allowed: true };
  }
  const viewerEntityId = options.viewerEntityId;
  if (!ENTITY_DB_ID.test(viewerEntityId || '')) return { ok: true, allowed: false };
  if (row.ownerEntityId === viewerEntityId) return { ok: true, allowed: true };

  const opportunityId = (row.record as any).opportunity_id;
  if (!validWorksId(opportunityId)) return { ok: true, allowed: false };
  const opportunity = await readStoredRow('opportunities', opportunityId);
  if (!opportunity.ok) return opportunity;
  return {
    ok: true,
    allowed: opportunity.row?.ownerEntityId === viewerEntityId,
  };
}

export async function listWorksRecords(
  collection: unknown,
  options: WorksReadOptions = {},
): Promise<StoreResult<{ records: WorksRecord[] }>> {
  if (!isCollection(collection)) return err('invalid_collection', 'unknown Works collection');
  const byId = new Map<string, WorksRecord>();
  for (const record of seedRecords(collection)) {
    if (collection === 'submissions'
      && (record as any).visibility !== 'public'
      && options.isAdmin !== true) {
      continue;
    }
    const id = recordId(collection, record);
    if (id) byId.set(id, record);
  }

  const includePrivate = collection === 'submissions'
    && (options.isAdmin === true || ENTITY_DB_ID.test(options.viewerEntityId || ''));
  const stored = await listStoredRows(collection, includePrivate);
  if (!stored.ok) return stored;
  for (const row of stored.rows) {
    if (collection === 'submissions') {
      const access = await canReadSubmission(row, options);
      if (!access.ok) return access;
      if (!access.allowed) continue;
    }
    const record = row.record;
    const id = recordId(collection, record);
    if (id && !byId.has(id)) byId.set(id, record);
  }
  return { ok: true, records: [...byId.values()] };
}

export async function getWorksRecord(
  collection: unknown,
  id: unknown,
  options: WorksReadOptions = {},
): Promise<StoreResult<{ record: WorksRecord }>> {
  if (!isCollection(collection)) return err('invalid_collection', 'unknown Works collection');
  if (!validWorksId(id)) return err('invalid_id', 'record id must match [a-z0-9-], 3-64 chars');
  const seed = seedRecords(collection).find((record) => recordId(collection, record) === id);
  if (seed) {
    if (collection === 'submissions'
      && (seed as any).visibility !== 'public'
      && options.isAdmin !== true) {
      return err('not_found', 'record not found');
    }
    return { ok: true, record: seed };
  }
  const loaded = await readStoredRow(collection, id);
  if (!loaded.ok) return loaded;
  if (!loaded.row) return err('not_found', 'record not found');
  if (collection === 'submissions') {
    const access = await canReadSubmission(loaded.row, options);
    if (!access.ok) return access;
    if (!access.allowed) return err('not_found', 'record not found');
  }
  return { ok: true, record: loaded.row.record };
}

/** Owner-only read for builder reuse and publication recovery. Public existence is not ownership. */
export async function getOwnedWorksRecord(
  collection: unknown,
  id: unknown,
  options: { ownerEntityId: string },
): Promise<StoreResult<{ record: WorksRecord }>> {
  if (collection !== 'builders' && collection !== 'listings' && collection !== 'opportunities') return err('invalid_collection', 'unknown owned-record collection');
  if (!ENTITY_DB_ID.test(options?.ownerEntityId || '')) return err('owner_required', 'an authenticated entity DB id is required');
  if (!validWorksId(id)) return err('invalid_id', 'record id must match [a-z0-9-], 3-64 chars');
  if (isSeedRecordId(collection, id)) return err('not_found', 'owned record not found');
  const loaded = await readStoredRow(collection, id);
  if (!loaded.ok) return loaded;
  if (!loaded.row || loaded.row.ownerEntityId !== options.ownerEntityId) return err('not_found', 'owned record not found');
  const checked = VALIDATORS[collection](loaded.row.record);
  if (!checked.ok || recordId(collection, checked.record) !== id) return err('store_unavailable', 'Owned record could not be validated.');
  // Return only schema-approved public fields, never the custody row or owner UUID.
  return { ok: true, record: checked.record };
}

export async function createWorksRecord(
  collection: unknown,
  input: unknown,
  options: { ownerEntityId: string },
): Promise<StoreResult<{ record: WorksRecord }>> {
  if (!isCollection(collection)) return err('invalid_collection', 'unknown Works collection');
  if (!ENTITY_DB_ID.test(options?.ownerEntityId || '')) {
    return err('owner_required', 'an authenticated entity DB id is required to create records');
  }
  if (containsVerifiedStatus(input)) {
    return err('verified_claim_forbidden', 'self-service Works writes cannot create VERIFIED claims');
  }
  if (isPlainObject(input) && input.example === true) {
    return err('example_reserved', 'example records are reserved for server-managed seeds');
  }

  const validated = VALIDATORS[collection](input);
  if (!validated.ok) return validated;
  const record = validated.record as WorksRecord;
  const id = recordId(collection, record);
  if (!id) return err('invalid_id', 'record id must match [a-z0-9-], 3-64 chars');
  if (isSeedRecordId(collection, id)) {
    return err('seed_immutable', 'this id belongs to a read-only example record');
  }
  const visibility = requestedVisibility(collection, input as Record<string, unknown>);
  if (!visibility.ok) return visibility;

  const existing = await readStoredRow(collection, id);
  if (!existing.ok) return existing;
  if (existing.row) return err('already_exists', 'a record with this id already exists');

  const relationships = await validateRelationships(collection, record, options.ownerEntityId);
  if (!relationships.ok) return relationships;
  if (collection === 'submissions' && usesFileBackend()) {
    const target = fileOpportunityWorkflowState((record as any).opportunity_id);
    if (!target.ok) return target;
    if (target.state !== 'open') return err('invalid_transition', 'This job is not accepting proposals.');
  }

  const now = isoNow();
  const stored: StoredRecord = {
    ...record,
    example: false,
    ...(collection === 'submissions' ? { visibility: visibility.visibility } : {}),
    created_at: now,
    updated_at: now,
  };
  const written = await writeCreatedRecord(
    collection, id, stored, options.ownerEntityId, visibility.visibility,
  );
  if (!written.ok) return written;
  return { ok: true, record: stored };
}

export async function updateWorksRecord(
  collection: unknown,
  id: unknown,
  patch: unknown,
  options: { ownerEntityId: string },
): Promise<StoreResult<{ record: WorksRecord }>> {
  if (!isCollection(collection)) return err('invalid_collection', 'unknown Works collection');
  if (!validWorksId(id)) return err('invalid_id', 'record id must match [a-z0-9-], 3-64 chars');
  if (!ENTITY_DB_ID.test(options?.ownerEntityId || '')) {
    return err('owner_required', 'an authenticated entity DB id is required to edit records');
  }
  if (!isPlainObject(patch)) return err('invalid_patch', 'patch must be an object');
  if (containsVerifiedStatus(patch)) {
    return err('verified_claim_forbidden', 'self-service Works writes cannot create VERIFIED claims');
  }
  if (patch.example === true) {
    return err('example_reserved', 'example records are reserved for server-managed seeds');
  }
  if (isSeedRecordId(collection, id)) return err('seed_immutable', 'example records are read-only');

  const loaded = await readStoredRow(collection, id);
  if (!loaded.ok) return loaded;
  if (!loaded.row) return err('not_found', 'record not found');
  if (loaded.row.ownerEntityId !== options.ownerEntityId) {
    return err('forbidden_not_owner', 'only the owning entity may edit this record');
  }
  if (collection === 'listings' && Object.hasOwn(patch, 'status')
    && patch.status !== (loaded.row.record as any).status) {
    return err('invalid_transition', 'Listing status changes require a workflow command.');
  }

  const visibility = requestedVisibility(collection, patch, loaded.row.visibility);
  if (!visibility.ok) return visibility;
  const idField = WORKS_ID_FIELD[collection];
  const merged = {
    ...loaded.row.record,
    ...patch,
    [idField]: id,
    example: false,
  };
  const validated = VALIDATORS[collection](merged);
  if (!validated.ok) return validated;
  const relationships = await validateRelationships(
    collection, validated.record as WorksRecord, options.ownerEntityId,
  );
  if (!relationships.ok) return relationships;

  const stored: StoredRecord = {
    ...validated.record,
    example: false,
    ...(collection === 'submissions' ? { visibility: visibility.visibility } : {}),
    created_at: loaded.row.record.created_at,
    updated_at: isoNow(),
  };
  const written = await writeUpdatedRecord(
    collection, id, stored, options.ownerEntityId, visibility.visibility,
  );
  if (!written.ok) return written;
  return { ok: true, record: stored };
}
