// SPDX-License-Identifier: Apache-2.0
import { validateOpportunity, type OpportunityRecord } from '@/lib/works/model';
import { buildOpportunityPayload, type OpportunityFormInput } from './form-payloads';

/** Kept only in the open page. The authenticated server replaces the poster name. */
export function prepareOpportunityDraft(input: OpportunityFormInput, observedAt = new Date().toISOString()): OpportunityRecord {
  const checked = validateOpportunity(buildOpportunityPayload({ ...input, postedBy: 'Account name set when published' }, observedAt));
  if (!checked.ok || checked.record.example || checked.record.claims.some(claim => claim.status === 'VERIFIED')) {
    throw new Error('Check the job details, contact route and statement scopes before previewing.');
  }
  for (const claim of checked.record.claims) {
    if (claim.source) Object.freeze(claim.source);
    Object.freeze(claim);
  }
  Object.freeze(checked.record.claims);
  return Object.freeze(checked.record);
}

/** Compare only submitted fields. posted_by is bound to the authenticated account by the server. */
export function sameOpportunityPublication(expected: unknown, observed: unknown): boolean {
  const left = validateOpportunity(expected); const right = validateOpportunity(observed);
  if (!left.ok || !right.ok || left.record.example || right.record.example) return false;
  return JSON.stringify({ ...left.record, posted_by: '' }) === JSON.stringify({ ...right.record, posted_by: '' });
}

function responseRecord(value: unknown, requireOwner: boolean): OpportunityRecord | null {
  if (!value || typeof value !== 'object' || Array.isArray(value)) return null;
  const body = value as Record<string, unknown>;
  if (body.collection !== 'opportunities' || (requireOwner && body.owned !== true)) return null;
  const checked = validateOpportunity(body.record);
  return checked.ok && !checked.record.example ? checked.record : null;
}

/** A lost response can be confirmed only by an exact authenticated owner read, never a public GET. */
export async function publishOpportunityWithRecovery(apiKey: string, draft: OpportunityRecord, signal: AbortSignal): Promise<OpportunityRecord> {
  const checked = validateOpportunity(draft);
  if (!apiKey || apiKey.length > 256 || /[\s\x00-\x1f\x7f]/.test(apiKey) || !checked.ok
      || checked.record.example || checked.record.claims.some(claim => claim.status === 'VERIFIED')) {
    throw new Error('Check the job preview and enter a valid EMILIA key.');
  }
  signal.throwIfAborted();
  let failure = 'Job publication could not be confirmed. Keep this preview and retry the same job; it may already be public.';
  let recover = false;
  try {
    const response = await fetch('/api/works/opportunities', {
      method: 'POST', headers: { 'content-type': 'application/json', authorization: `Bearer ${apiKey}` },
      body: JSON.stringify(draft), signal,
      cache: 'no-store', credentials: 'omit', redirect: 'error', referrerPolicy: 'no-referrer',
    });
    signal.throwIfAborted();
    if (response.ok) {
      const record = responseRecord(await response.json().catch(() => null), false);
      signal.throwIfAborted();
      if (record && sameOpportunityPublication(draft, record)) return record;
      recover = true;
    } else {
      recover = response.status === 409 || response.status >= 500;
      if (response.status === 401 || response.status === 403) failure = 'That key could not publish this job. Use the owning account key or request access.';
      else if (response.status === 429) failure = 'Too many requests. Keep this preview and try again later.';
      else if (!recover) failure = 'The server did not accept this job. Check the details and account access before trying again.';
    }
  } catch {
    signal.throwIfAborted();
    recover = true;
  }
  if (recover) {
    signal.throwIfAborted();
    try {
      const response = await fetch(`/api/works/opportunities/${encodeURIComponent(draft.opportunity_id)}/owned`, {
        method: 'GET', headers: { authorization: `Bearer ${apiKey}` }, signal,
        cache: 'no-store', credentials: 'omit', redirect: 'error', referrerPolicy: 'no-referrer',
      });
      signal.throwIfAborted();
      const record = response.ok ? responseRecord(await response.json().catch(() => null), true) : null;
      signal.throwIfAborted();
      if (record && record.opportunity_id === draft.opportunity_id) {
        if (sameOpportunityPublication(draft, record)) return record;
        failure = 'You own this job ID, but its published details are different from this preview. No existing job was changed.';
      }
    } catch { /* Failed ownership checks never confirm publication. */ }
  }
  signal.throwIfAborted();
  throw new Error(failure);
}
