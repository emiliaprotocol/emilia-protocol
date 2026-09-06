// SPDX-License-Identifier: Apache-2.0

import { validateBuilder, validateListing, type BuilderRecord, type ListingRecord } from '@/lib/works/model';

type Collection = 'builders' | 'listings';

export async function readOwnedRecord(collection: Collection, id: string, apiKey: string, signal: AbortSignal): Promise<BuilderRecord | ListingRecord> {
  const response = await fetch(`/api/works/${collection}/${encodeURIComponent(id)}/owned`, {
    headers: { authorization: `Bearer ${apiKey}` }, cache: 'no-store', signal,
    credentials: 'omit', redirect: 'error', referrerPolicy: 'no-referrer',
  });
  if (!response.ok) throw new Error(response.status === 404
    ? 'No profile or listing owned by this key was found at that ID.'
    : response.status === 401 ? 'That key could not be authenticated.' : 'Ownership could not be checked. Nothing is assumed.');
  const body = await response.json();
  const validated = collection === 'builders' ? validateBuilder(body.record) : validateListing(body.record);
  const idField = collection === 'builders' ? 'builder_id' : 'listing_id';
  if (body.owned !== true || body.collection !== collection || !validated.ok
      || (validated.record as unknown as Record<string, unknown>)[idField] !== id) throw new Error('The owned-record response did not match this request.');
  return validated.record;
}

/** Compare normalized public fields. Matching public content alone is never an ownership check. */
export function samePublication(collection: Collection, expected: unknown, observed: unknown): boolean {
  const validate = collection === 'builders' ? validateBuilder : validateListing;
  const left = validate(expected); const right = validate(observed);
  return left.ok && right.ok && JSON.stringify(left.record) === JSON.stringify(right.record);
}

/** A retry can recover a lost response only after an authenticated owner read of identical content. */
export async function publishRecordWithRecovery(collection: Collection, apiKey: string, record: BuilderRecord | ListingRecord, signal: AbortSignal): Promise<void> {
  let failure = 'Publication could not be confirmed.';
  let mayHaveCompleted = false;
  try {
    const response = await fetch(`/api/works/${collection}`, {
      method: 'POST', headers: { 'content-type': 'application/json', authorization: `Bearer ${apiKey}` },
      body: JSON.stringify(record), signal, credentials: 'omit', redirect: 'error', referrerPolicy: 'no-referrer',
    });
    if (response.ok) return;
    mayHaveCompleted = response.status === 409 || response.status >= 500;
    failure = response.status === 409 ? 'That ID already exists. It was not assumed to be yours.' : `The ${collection} write could not be confirmed.`;
  } catch (error) {
    if (signal.aborted) throw error;
    mayHaveCompleted = true;
  }
  if (mayHaveCompleted && !signal.aborted) {
    try {
      const id = collection === 'builders' ? (record as BuilderRecord).builder_id : (record as ListingRecord).listing_id;
      const observed = await readOwnedRecord(collection, id, apiKey, signal);
      if (samePublication(collection, record, observed)) return;
      failure = 'You own that ID, but its public fields differ from this preview. No existing record was changed.';
    } catch { /* Neither public existence nor a failed ownership check confirms publication. */ }
  }
  throw new Error(failure);
}
