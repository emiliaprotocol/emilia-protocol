// SPDX-License-Identifier: Apache-2.0
// Tenant-scoped read model for the Guard receipts dashboard. The service-role
// client bypasses RLS, so tenancy must be part of every query and re-checked
// while building the response.

import type { SupabaseClient } from '@supabase/supabase-js';
import { findBoundSignoffDecision } from '@/lib/guard-signoff-binding.js';

/** Minimal logger surface this module actually calls; callers may pass any logger. */
interface GuardReceiptsLogger {
  warn?: (...args: unknown[]) => void;
}

/** Console-safe projection of a single Guard trust receipt's lifecycle state. */
interface GuardReceipt {
  receipt_id: string;
  action_type: string;
  action_hash: string | null;
  caid: string | null;
  organization_id: string;
  decision: string;
  enforcement_mode: string;
  policy_id: string | null;
  authority_verdict: string | null;
  status: string;
  adapter: string | null;
  amount: number | null;
  currency: string | null;
  created_at: string;
  signoff_required: boolean;
}

export const RECENT_EVENT_LIMIT = 500;
export const RECENT_RECEIPT_LIMIT = 100;

const RECEIPT_BINDINGS_TABLE = 'guard_receipt_event_bindings';
const EVIDENCE_EVENT_TYPES = [
  'guard.trust_receipt.created',
  'guard.signoff.requested',
  'guard.signoff.approved',
  'guard.signoff.rejected',
  'guard.trust_receipt.consumed',
];

function validTenantId(value) {
  return typeof value === 'string' && value.length > 0 && value.length <= 256;
}

function validEnvironment(value) {
  return value === 'development' || value === 'staging' || value === 'production';
}

export function replayGuardReceipts(events, allowedReceiptIds, tenantId, environment) {
  if (!validTenantId(tenantId) || !validEnvironment(environment)) return [];
  const allowed = new Set(allowedReceiptIds);
  const byReceipt = new Map();
  for (const event of events || []) {
    if (!allowed.has(event?.target_id)) continue;
    // Re-check the binding projection in memory. The service-role client can
    // bypass RLS, so an overbroad response must still fail closed.
    if (event?.tenant_id !== tenantId || event?.environment !== environment) continue;
    if (!byReceipt.has(event.target_id)) byReceipt.set(event.target_id, []);
    byReceipt.get(event.target_id).push(event);
  }

  const receipts: GuardReceipt[] = [];
  for (const [receiptId, receiptEvents] of byReceipt) {
    const eventsAsc = [...receiptEvents].sort((a, b) => String(a.created_at).localeCompare(String(b.created_at)));
    const created = eventsAsc.find((event) => (
      event.event_type === 'guard.trust_receipt.created'
      && event.after_state?.organization_id === tenantId
    ));
    if (!created) continue;
    const base = created.after_state || {};

    let status = base.receipt_status || 'issued';
    if (eventsAsc.some((event) => event.event_type === 'guard.trust_receipt.consumed')) status = 'consumed';
    else if (findBoundSignoffDecision(eventsAsc, created, 'guard.signoff.rejected')) status = 'rejected';
    else if (findBoundSignoffDecision(eventsAsc, created, 'guard.signoff.approved')) status = 'approved_pending_consume';

    receipts.push({
      receipt_id: receiptId,
      action_type: base.action_type || 'unknown',
      action_hash: typeof base.action_hash === 'string' ? base.action_hash : null,
      caid: typeof base.caid === 'string'
        ? base.caid
        : (typeof base.canonical_action?.caid === 'string'
          ? base.canonical_action.caid
          : (typeof base.canonical_action?.action_caid === 'string'
            ? base.canonical_action.action_caid
            : null)),
      organization_id: base.organization_id || 'unknown',
      decision: base.decision || 'unknown',
      enforcement_mode: base.enforcement_mode || 'enforce',
      policy_id: typeof base.policy_id === 'string' ? base.policy_id : null,
      authority_verdict: typeof base.authority_verdict === 'string'
        ? base.authority_verdict
        : null,
      status,
      adapter: base.adapter || null,
      amount: base.amount ?? null,
      currency: base.currency ?? null,
      created_at: created.created_at,
      signoff_required: !!base.signoff_required,
    });
  }

  receipts.sort((a, b) => String(b.created_at).localeCompare(String(a.created_at)));
  return receipts;
}

/**
 * @param {object} [opts]
 * @param {*} [opts.supabase]
 * @param {string} [opts.tenantId]
 * @param {string} [opts.environment]
 * @param {*} [opts.log]
 */
export async function loadTenantGuardReceipts({
  supabase,
  tenantId,
  environment,
  log,
  limit = RECENT_RECEIPT_LIMIT,
  dateFrom,
  dateTo,
}: {
  supabase?: SupabaseClient;
  tenantId?: string;
  environment?: string;
  log?: GuardReceiptsLogger;
  limit?: number;
  dateFrom?: string;
  dateTo?: string;
} = {}) {
  if (!supabase || typeof supabase.from !== 'function') {
    return { receipts: [], error: 'Dashboard storage unavailable.' };
  }
  if (!validTenantId(tenantId)) {
    return { receipts: [], error: 'Tenant scope is required.' };
  }
  if (!validEnvironment(environment)) {
    return { receipts: [], error: 'Environment scope is required.' };
  }
  try {
    const receiptLimit = Math.min(
      Math.max(Number.isSafeInteger(limit) ? limit : RECENT_RECEIPT_LIMIT, 1),
      RECENT_RECEIPT_LIMIT,
    );
    // Establish receipt ownership from the append-only binding ledger. Legacy
    // or ambiguous audit rows have no binding and therefore fail closed.
    let createdQuery = supabase
      .from(RECEIPT_BINDINGS_TABLE)
      .select('event_id, receipt_id, tenant_id, environment, event_type, event_created_at')
      .eq('tenant_id', tenantId)
      .eq('environment', environment)
      .eq('event_type', 'guard.trust_receipt.created')
      .order('event_created_at', { ascending: false });
    if (dateFrom) createdQuery = createdQuery.gte('event_created_at', dateFrom);
    if (dateTo) createdQuery = createdQuery.lte('event_created_at', dateTo);
    const { data: createdBindings, error: createdError } = await createdQuery.limit(receiptLimit);
    if (createdError) {
      log?.warn?.('[guard-receipts dashboard] tenant receipt lookup failed:', createdError.message);
      return { receipts: [], error: createdError.message };
    }

    const ownedCreatedBindings = (createdBindings || []).filter((binding) => (
      binding?.tenant_id === tenantId
      && binding?.environment === environment
      && binding?.event_type === 'guard.trust_receipt.created'
      && typeof binding?.event_id === 'string'
      && binding.event_id.length > 0
      && typeof binding?.receipt_id === 'string'
      && binding.receipt_id.length > 0
    ));
    const receiptIds = [...new Set(ownedCreatedBindings.map((binding) => binding.receipt_id))];
    if (receiptIds.length === 0) return { receipts: [], error: null, truncated: false };

    // Scope timeline membership before touching audit_events. Fetching audit
    // rows by target_id would merge colliding identifiers across ownership
    // domains; bindings instead identify exact immutable event rows.
    const { data: timelineBindings, error: bindingError } = await supabase
      .from(RECEIPT_BINDINGS_TABLE)
      .select('event_id, receipt_id, tenant_id, environment, event_type, event_created_at')
      .eq('tenant_id', tenantId)
      .eq('environment', environment)
      .in('receipt_id', receiptIds)
      .in('event_type', EVIDENCE_EVENT_TYPES)
      .order('event_created_at', { ascending: false })
      .limit(RECENT_EVENT_LIMIT);
    if (bindingError) {
      log?.warn?.('[guard-receipts dashboard] tenant event binding lookup failed:', bindingError.message);
      return { receipts: [], error: bindingError.message };
    }

    const allowedReceipts = new Set(receiptIds);
    const bindingsByEventId = new Map();
    for (const binding of [...ownedCreatedBindings, ...(timelineBindings || [])]) {
      if (binding?.tenant_id !== tenantId || binding?.environment !== environment) continue;
      if (!allowedReceipts.has(binding?.receipt_id)) continue;
      if (!EVIDENCE_EVENT_TYPES.includes(binding?.event_type)) continue;
      if (typeof binding?.event_id !== 'string' || binding.event_id.length === 0) continue;
      const prior = bindingsByEventId.get(binding.event_id);
      if (prior && (
        prior.receipt_id !== binding.receipt_id
        || prior.event_type !== binding.event_type
      )) {
        // Contradictory rows violate the binding table's primary-key contract.
        bindingsByEventId.set(binding.event_id, null);
        continue;
      }
      if (!prior) bindingsByEventId.set(binding.event_id, binding);
    }
    const eventIds = [...bindingsByEventId.entries()]
      .filter(([, binding]) => binding !== null)
      .map(([eventId]) => eventId);
    if (eventIds.length === 0) {
      return { receipts: [], error: 'No tenant-bound audit events were available.' };
    }

    const { data: auditEvents, error: eventError } = await supabase
      .from('audit_events')
      .select('id, event_type, target_id, actor_id, after_state, created_at')
      .in('id', eventIds)
      .order('created_at', { ascending: false })
      .limit(eventIds.length);
    if (eventError) {
      log?.warn?.('[guard-receipts dashboard] bound audit event lookup failed:', eventError.message);
      return { receipts: [], error: eventError.message };
    }

    const events = (auditEvents || []).flatMap((event) => {
      const binding = bindingsByEventId.get(event?.id);
      if (!binding
          || event?.target_id !== binding.receipt_id
          || event?.event_type !== binding.event_type) {
        return [];
      }
      return [{ ...event, tenant_id: tenantId, environment }];
    });

    return {
      receipts: replayGuardReceipts(events, receiptIds, tenantId, environment),
      error: null,
      // The tenant prequery is deliberately capped. Equality means that more
      // rows may exist; callers must label the page as bounded, not complete.
      truncated: ownedCreatedBindings.length === receiptLimit
        || (timelineBindings?.length ?? 0) === RECENT_EVENT_LIMIT,
    };
  } catch (error) {
    log?.warn?.('[guard-receipts dashboard] threw:', error?.message);
    return { receipts: [], error: 'Dashboard query failed.' };
  }
}

export default loadTenantGuardReceipts;
