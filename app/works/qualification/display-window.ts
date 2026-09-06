// SPDX-License-Identifier: Apache-2.0

import type { MarketplaceQualificationResponse } from '@/lib/works/marketplace-qualification';

export interface QualificationDisplayWindow {
  deadline: number;
  monotonicStartedAt: number;
  wallStartedAt: number;
}

/** Server-issued TTL, charged for the entire request round trip. No comparison
 * between the user's wall clock and the server's absolute timestamp is needed. */
export function qualificationDisplayDeadline(
  checkedAt: string,
  expiresAt: string,
  requestStartedAt: number,
  receivedAt: number,
): number | null {
  const ttl = Date.parse(expiresAt) - Date.parse(checkedAt);
  const deadline = requestStartedAt + ttl;
  if (![ttl, requestStartedAt, receivedAt, deadline].every(Number.isFinite)
    || ttl <= 0 || ttl > 300_000 || requestStartedAt < 0
    || receivedAt < requestStartedAt || deadline <= receivedAt) return null;
  return deadline;
}

export function qualificationDisplayRemaining(deadline: number | null, now: number): number {
  return deadline !== null && Number.isFinite(deadline) && Number.isFinite(now)
    ? Math.max(0, Math.ceil((deadline - now) / 1000)) : 0;
}

/** Wall-clock deltas cover browsers whose monotonic clock pauses during sleep.
 * Clock rollback beyond small scheduling jitter invalidates the display. The
 * wall clock's absolute relationship to the server is never used. */
export function qualificationWindowRemaining(window: QualificationDisplayWindow, monotonicNow: number, wallNow: number): number {
  const monotonicElapsed = monotonicNow - window.monotonicStartedAt;
  const wallElapsed = wallNow - window.wallStartedAt;
  if (![monotonicElapsed, wallElapsed, window.deadline].every(Number.isFinite)
    || monotonicElapsed < 0 || wallElapsed < 0 || wallElapsed < monotonicElapsed - 1000) return 0;
  return qualificationDisplayRemaining(window.deadline,
    window.monotonicStartedAt + Math.max(monotonicElapsed, wallElapsed));
}

/** Malformed proxy/error responses must never become a badge or a render crash. */
export function isQualificationResponseProjection(value: unknown): value is MarketplaceQualificationResponse {
  if (!value || typeof value !== 'object' || Array.isArray(value)) return false;
  const data = value as Record<string, unknown>;
  if (typeof data.reason !== 'string' || data.reason.length > 240
    || !['QUALIFIED', 'NOT_QUALIFIED', 'INDETERMINATE', 'INVALID_REQUEST', 'UNAVAILABLE'].includes(data.status as string)) return false;
  if (data.status === 'INVALID_REQUEST' || data.status === 'UNAVAILABLE') return data.result === null && data.display === null;
  if (!data.result || typeof data.result !== 'object' || Array.isArray(data.result)) return false;
  const result = data.result as Record<string, unknown>;
  if (result.decision !== data.status) return false;
  const dimensions = {
    verification: ['VERIFIED', 'NOT_VERIFIED'], acceptance: ['ACCEPTED', 'NOT_ACCEPTED'],
    candidate_match: ['EXACT_MATCH', 'MISMATCH', 'UNPINNABLE', 'STALE', 'UNKNOWN'],
    assignment_scope: ['IN_SCOPE', 'OUT_OF_SCOPE', 'UNKNOWN'],
    currentness: ['CURRENT_AS_OBSERVED', 'STALE', 'REVOKED', 'SUSPENDED', 'EXPIRED', 'EQUIVOCATED', 'UNKNOWN'],
    campaign_graph: ['COMPLETE', 'INCOMPLETE', 'INVALID'],
  };
  if (!Object.entries(dimensions).every(([key, options]) => options.includes(result[key] as string))) return false;
  if (data.status !== 'QUALIFIED') return data.display === null;
  if (result.verification !== 'VERIFIED' || result.acceptance !== 'ACCEPTED'
    || result.candidate_match !== 'EXACT_MATCH' || result.assignment_scope !== 'IN_SCOPE'
    || result.currentness !== 'CURRENT_AS_OBSERVED' || result.campaign_graph !== 'COMPLETE'
    || !data.display || typeof data.display !== 'object' || Array.isArray(data.display)) return false;
  const display = data.display as Record<string, unknown>;
  for (const key of ['scope_id', 'scope_label', 'checked_at', 'expires_at', 'status_observed_at']) {
    if (typeof display[key] !== 'string' || !display[key].length || display[key].length > 240) return false;
  }
  return ['candidate_manifest_digest', 'assignment_digest', 'qualification_policy_digest',
    'protected_request_digest', 'qualification_statement_digest', 'qualification_status_head_digest']
    .every((key) => typeof display[key] === 'string' && /^sha256:[a-f0-9]{64}$/.test(display[key] as string));
}
