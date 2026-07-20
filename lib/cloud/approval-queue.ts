// SPDX-License-Identifier: Apache-2.0
// Tenant-scoped audit_events read model for fixed high-risk payment approvals.
// The service-role client bypasses RLS, so receipt ownership is established
// before timeline loading and re-checked while replaying every response.

import type { SupabaseClient } from '@supabase/supabase-js';
import { findBoundSignoffDecision } from '../guard-signoff-binding.js';

/** Minimal logger surface this module actually calls; callers may pass any logger. */
interface ApprovalQueueLogger {
  warn?: (...args: unknown[]) => void;
}

/** Console-safe projection of a single fixed high-risk payment approval. */
interface ApprovalQueueEntry {
  receipt_id: string;
  action_hash: string | null;
  action_caid: string | null;
  action_type: string;
  amount: number | null;
  currency: string | null;
  counterparty_name: string | null;
  target_resource_id: string | null;
  payment_destination_hash: string | null;
  created_at: string | null;
  expires_at: string | null;
  status: 'pending' | 'consumed' | 'rejected' | 'approved' | 'expired';
  signoff_id: string | null;
  approver_id: string | null;
  review_path: string | null;
  consumed_at: string | null;
}

export const APPROVAL_EVENT_LIMIT = 500;
export const APPROVAL_RECEIPT_LIMIT = 100;
export const APPROVAL_ACTION_TYPE = 'large_payment_release';

const CLOUD_KEY_PREFIX = 'ep:cloud-key:';

/** @param {unknown} value @returns {value is string} */
function validTenantId(value) {
  return typeof value === 'string' && value.length > 0 && value.length <= 256;
}

function isCloudKeyCreator(value) {
  return typeof value === 'string'
    && value.startsWith(CLOUD_KEY_PREFIX)
    && value.length > CLOUD_KEY_PREFIX.length;
}

function safeString(value) {
  return typeof value === 'string' ? value : null;
}

function safeNumber(value) {
  return typeof value === 'number' && Number.isFinite(value) ? value : null;
}

function timestamp(value) {
  if (value instanceof Date) return value.getTime();
  if (typeof value === 'number') return value;
  return Date.parse(value);
}

function creatorBoundRequests(events, createdEvent) {
  const actionHash = safeString(createdEvent?.after_state?.action_hash);
  if (!actionHash) return [];
  return (events || []).filter((event) => (
    event?.event_type === 'guard.signoff.requested'
    && event.actor_id === createdEvent?.actor_id
    && safeString(event.after_state?.signoff_id)
    && safeString(event.after_state?.action_hash) === actionHash
  ));
}

function intendedApprover(requestState) {
  return safeString(requestState?.approver_id)
    || safeString(requestState?.quorum?.approver_id);
}

function requestForDecision(requestEvents, decisionEvent) {
  const signoffId = decisionEvent?.after_state?.signoff_id;
  return requestEvents.find((event) => event.after_state?.signoff_id === signoffId) || null;
}

/**
 * Replay tenant-owned audit timelines into a console-safe approval projection.
 *
 * @param {Array<object>} events
 * @param {Array<string>} allowedReceiptIds
 * @param {string} tenantId
 * @param {Date|string|number} [now]
 */
export function replayApprovalQueue(
  events,
  allowedReceiptIds,
  tenantId,
  now: Date | string | number = Date.now(),
) {
  if (!validTenantId(tenantId)) return [];

  const allowed = new Set(Array.isArray(allowedReceiptIds) ? allowedReceiptIds : []);
  const byReceipt = new Map();
  for (const event of events || []) {
    const receiptId = event?.target_id;
    if (!allowed.has(receiptId)) continue;
    if (!byReceipt.has(receiptId)) byReceipt.set(receiptId, []);
    byReceipt.get(receiptId).push(event);
  }

  const nowMs = timestamp(now);
  const requests: ApprovalQueueEntry[] = [];
  for (const [receiptId, receiptEvents] of byReceipt) {
    const eventsAsc = [...receiptEvents]
      .sort((a, b) => String(a?.created_at).localeCompare(String(b?.created_at)));
    const created = eventsAsc.find((event) => (
      event?.event_type === 'guard.trust_receipt.created'
      && event.after_state?.organization_id === tenantId
      && event.after_state?.action_type === APPROVAL_ACTION_TYPE
      && isCloudKeyCreator(event.actor_id)
    ));
    if (!created) continue;

    const requestEvents = creatorBoundRequests(eventsAsc, created);
    if (requestEvents.length === 0) continue;
    const actionHash = safeString(created.after_state?.action_hash);

    // Restrict the shared binding predicate to creator- and action-hash-bound
    // requests before considering any decision rows from an overbroad response.
    const bindingTimeline = [
      created,
      ...requestEvents,
      ...eventsAsc.filter((event) => (
        event?.event_type === 'guard.signoff.approved'
        || event?.event_type === 'guard.signoff.rejected'
      )),
    ];
    const rejected = findBoundSignoffDecision(
      bindingTimeline,
      created,
      'guard.signoff.rejected',
    );
    const approved = findBoundSignoffDecision(
      bindingTimeline,
      created,
      'guard.signoff.approved',
    );
    const consumed = eventsAsc.find(
      (event) => (
        event?.event_type === 'guard.trust_receipt.consumed'
        && safeString(event.after_state?.action_hash) === actionHash
      ),
    ) || null;

    const decisionEvent = rejected || approved;
    const requestEvent = requestForDecision(requestEvents, decisionEvent) || requestEvents[0];
    const requestState = requestEvent.after_state || {};
    const base = created.after_state || {};
    const canonicalAction = base.canonical_action && typeof base.canonical_action === 'object'
      && !Array.isArray(base.canonical_action)
      ? base.canonical_action
      : {};
    const signoffId = safeString(requestState.signoff_id);
    const expiresAt = safeString(requestState.expires_at) || safeString(base.expires_at);
    const expiresAtMs = timestamp(expiresAt);

    let status: ApprovalQueueEntry['status'] = 'pending';
    if (consumed) status = 'consumed';
    else if (rejected) status = 'rejected';
    else if (approved) status = 'approved';
    else if (!Number.isFinite(expiresAtMs) || !Number.isFinite(nowMs) || expiresAtMs <= nowMs) {
      status = 'expired';
    }

    requests.push({
      receipt_id: receiptId,
      action_hash: actionHash,
      action_caid: safeString(canonicalAction.action_caid),
      action_type: APPROVAL_ACTION_TYPE,
      amount: safeNumber(base.amount) ?? safeNumber(canonicalAction.amount),
      currency: safeString(base.currency) || safeString(canonicalAction.currency),
      counterparty_name: safeString(base.counterparty_name)
        || safeString(canonicalAction.counterparty_name),
      target_resource_id: safeString(base.target_resource_id)
        || safeString(canonicalAction.target_resource_id),
      payment_destination_hash: safeString(base.payment_destination_hash)
        || safeString(canonicalAction.payment_destination_hash),
      created_at: safeString(created.created_at),
      expires_at: expiresAt,
      status,
      signoff_id: signoffId,
      approver_id: intendedApprover(requestState)
        || safeString(decisionEvent?.after_state?.approver_id)
        || safeString(decisionEvent?.actor_id),
      review_path: signoffId ? `/signoff/${encodeURIComponent(signoffId)}` : null,
      consumed_at: consumed
        ? safeString(consumed.after_state?.consumed_at) || safeString(consumed.created_at)
        : null,
    });
  }

  requests.sort((a, b) => String(b.created_at).localeCompare(String(a.created_at)));
  return requests;
}

/**
 * @param {object} [opts]
 * @param {*} [opts.supabase]
 * @param {string} [opts.tenantId]
 * @param {*} [opts.log]
 * @param {Date|string|number} [opts.now]
 */
export async function loadTenantApprovalQueue({
  supabase,
  tenantId,
  log,
  now = Date.now(),
}: {
  supabase?: SupabaseClient;
  tenantId?: string;
  log?: ApprovalQueueLogger;
  now?: Date | string | number;
} = {}) {
  if (!supabase || typeof supabase.from !== 'function') {
    return { approvals: [], error: 'Approval storage unavailable.' };
  }
  if (!validTenantId(tenantId)) {
    return { approvals: [], error: 'Tenant scope is required.' };
  }

  try {
    const { data: createdEvents, error: createdError } = await supabase
      .from('audit_events')
      .select('target_id')
      .eq('event_type', 'guard.trust_receipt.created')
      .contains('after_state', { organization_id: tenantId })
      .eq('after_state->>action_type', APPROVAL_ACTION_TYPE)
      .like('actor_id', `${CLOUD_KEY_PREFIX}%`)
      .order('created_at', { ascending: false })
      .limit(APPROVAL_RECEIPT_LIMIT);
    if (createdError) {
      log?.warn?.('[approval queue] tenant receipt lookup failed:', createdError.message);
      return { approvals: [], error: createdError.message };
    }

    const receiptIds = [...new Set((createdEvents || [])
      .map((event) => event?.target_id)
      .filter((id) => typeof id === 'string' && id.length > 0))];
    if (receiptIds.length === 0) return { approvals: [], error: null };

    const { data: events, error: eventError } = await supabase
      .from('audit_events')
      .select('event_type, target_id, actor_id, after_state, created_at')
      .like('event_type', 'guard.%')
      .in('target_id', receiptIds)
      .order('created_at', { ascending: false })
      .limit(APPROVAL_EVENT_LIMIT);
    if (eventError) {
      log?.warn?.('[approval queue] tenant timeline lookup failed:', eventError.message);
      return { approvals: [], error: eventError.message };
    }

    return {
      approvals: replayApprovalQueue(events, receiptIds, tenantId, now),
      error: null,
    };
  } catch (error) {
    log?.warn?.('[approval queue] query threw:', error?.message);
    return { approvals: [], error: 'Approval queue query failed.' };
  }
}

export default loadTenantApprovalQueue;
