// SPDX-License-Identifier: Apache-2.0
import { validWorksId, validateSubmission } from '@/lib/works/model';

export type InboxSubmission = {
  submission_id: string;
  opportunity_id: string;
  builder_id: string;
  listing_id: string | null;
  proposal: string;
  team: string[];
  example: false;
  visibility: 'private' | 'public';
  created_at: string | null;
};

export type InboxPageResult = {
  records: InboxSubmission[];
  access: 'owner' | 'administrator';
  offset: number;
  limit: 50;
  has_more: boolean;
};

function object(value: unknown): value is Record<string, unknown> {
  return value !== null && typeof value === 'object' && !Array.isArray(value);
}

/** The owner-authorized API is the access boundary. Refuse a mismatched scope
 * or malformed response; never present a partial failure as an empty inbox. */
export function projectInboxRecords(value: unknown, opportunityId: string): InboxSubmission[] {
  if (!validWorksId(opportunityId) || !object(value) || value.collection !== 'submissions'
    || value.opportunity_id !== opportunityId || (value.access !== 'owner' && value.access !== 'administrator')
    || value.limit !== 50 || !Number.isSafeInteger(value.offset) || Number(value.offset) < 0
    || Number(value.offset) > 100_000 || Number(value.offset) % 50 !== 0 || typeof value.has_more !== 'boolean'
    || !Array.isArray(value.records) || value.records.length > 50) throw new Error('inbox_response_invalid');
  const records: InboxSubmission[] = [];
  const ids = new Set<string>();
  for (const entry of value.records) {
    if (!object(entry) || entry.opportunity_id !== opportunityId || entry.example === true) throw new Error('inbox_response_invalid');
    const result = validateSubmission(entry);
    if (!result.ok || (entry.visibility !== 'public' && entry.visibility !== 'private')
      || ids.has(result.record.submission_id)) throw new Error('inbox_response_invalid');
    ids.add(result.record.submission_id);
    records.push({
      submission_id: result.record.submission_id,
      opportunity_id: result.record.opportunity_id,
      builder_id: result.record.builder_id,
      listing_id: result.record.listing_id ?? null,
      proposal: result.record.proposal,
      team: result.record.team ?? [],
      example: false,
      visibility: entry.visibility,
      created_at: typeof entry.created_at === 'string' && entry.created_at.length <= 40
        && Number.isFinite(Date.parse(entry.created_at)) ? entry.created_at : null,
    });
  }
  return records;
}

export async function loadOpportunityInbox(opportunityId: string, apiKey: string | null, signal: AbortSignal, offset = 0): Promise<InboxPageResult> {
  if (!validWorksId(opportunityId) || (apiKey !== null && !/^[A-Za-z0-9_-]{8,512}$/.test(apiKey))
    || !Number.isSafeInteger(offset) || offset < 0 || offset > 100_000 || offset % 50 !== 0) throw new Error('inbox_input_invalid');
  const response = await fetch(`/api/works/opportunities/${opportunityId}/inbox?offset=${offset}`, {
    method: 'GET', headers: apiKey === null ? {} : { authorization: `Bearer ${apiKey}` },
    cache: 'no-store', credentials: apiKey === null ? 'same-origin' : 'omit', redirect: 'error', referrerPolicy: 'no-referrer', signal,
  });
  if (!response.ok) {
    if (response.status === 401 || response.status === 403 || response.status === 404) throw new Error('inbox_access_refused');
    if (response.status === 429) throw new Error('inbox_rate_limited');
    throw new Error('inbox_unavailable');
  }
  const body: unknown = await response.json();
  const records = projectInboxRecords(body, opportunityId);
  if (!object(body) || body.offset !== offset) throw new Error('inbox_response_invalid');
  return { records, access: body.access as InboxPageResult['access'], offset,
    limit: 50, has_more: body.has_more as boolean,
  };
}

/** An aborted request may still resolve. A generation check prevents its
 * private result from reappearing after an edit, clear or newer request. */
export function createInboxRequestFence() {
  let generation = 0;
  let controller: AbortController | null = null;
  function cancel() {
    generation += 1;
    controller?.abort();
    controller = null;
  }
  return {
    cancel,
    begin() {
      cancel();
      const current = generation;
      const next = new AbortController();
      controller = next;
      return { signal: next.signal, isCurrent: () => current === generation && !next.signal.aborted };
    },
  };
}
