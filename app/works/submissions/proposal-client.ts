// SPDX-License-Identifier: Apache-2.0
import { validWorksId, validateSubmission } from '@/lib/works/model';

export type ProposalResult = {
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

function object(value: unknown): value is Record<string, unknown> {
  return value !== null && typeof value === 'object' && !Array.isArray(value);
}

/** Authorization belongs to the single-record API. Only its exact validated
 * proposal is projected into this private view, never backend metadata. */
export function projectProposal(value: unknown, submissionId: string): ProposalResult {
  if (!validWorksId(submissionId) || !object(value) || value.collection !== 'submissions'
    || !object(value.record)) throw new Error('proposal_response_invalid');
  const entry = value.record;
  const checked = validateSubmission(entry);
  if (!checked.ok || checked.record.submission_id !== submissionId || entry.example === true
    || (entry.visibility !== 'private' && entry.visibility !== 'public')) throw new Error('proposal_response_invalid');
  return {
    submission_id: checked.record.submission_id,
    opportunity_id: checked.record.opportunity_id,
    builder_id: checked.record.builder_id,
    listing_id: checked.record.listing_id ?? null,
    proposal: checked.record.proposal,
    team: checked.record.team ?? [],
    example: false,
    visibility: entry.visibility,
    created_at: typeof entry.created_at === 'string' && entry.created_at.length <= 40
      && Number.isFinite(Date.parse(entry.created_at)) ? entry.created_at : null,
  };
}

export async function loadProposal(submissionId: string, apiKey: string, signal: AbortSignal): Promise<ProposalResult> {
  if (!validWorksId(submissionId) || !/^[A-Za-z0-9_-]{8,512}$/.test(apiKey)) throw new Error('proposal_input_invalid');
  const response = await fetch(`/api/works/submissions/${submissionId}`, {
    method: 'GET', headers: { authorization: `Bearer ${apiKey}` },
    cache: 'no-store', credentials: 'omit', redirect: 'error', referrerPolicy: 'no-referrer', signal,
  });
  if (!response.ok) {
    if (response.status === 401 || response.status === 403 || response.status === 404) throw new Error('proposal_access_refused');
    if (response.status === 429) throw new Error('proposal_rate_limited');
    throw new Error('proposal_unavailable');
  }
  return projectProposal(await response.json(), submissionId);
}

/** Transport abort alone is insufficient: a late result or error must not
 * reappear after the viewer clears the page or begins another request. */
export function createProposalRequestFence() {
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
      const isCurrent = () => current === generation && !next.signal.aborted;
      return {
        signal: next.signal,
        isCurrent,
        async load(submissionId: string, apiKey: string): Promise<ProposalResult | null> {
          try {
            const result = await loadProposal(submissionId, apiKey, next.signal);
            return isCurrent() ? result : null;
          } catch (error) {
            if (!isCurrent()) return null;
            throw error;
          }
        },
      };
    },
  };
}
