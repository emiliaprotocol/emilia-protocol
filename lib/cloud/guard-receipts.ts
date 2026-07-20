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
  organization_id: string;
  decision: string;
  enforcement_mode: string;
  status: string;
  adapter: string | null;
  amount: number | null;
  currency: string | null;
  created_at: string;
  signoff_required: boolean;
}

export const RECENT_EVENT_LIMIT = 500;
export const RECENT_RECEIPT_LIMIT = 100;

function validTenantId(value) {
  return typeof value === 'string' && value.length > 0 && value.length <= 256;
}

export function replayGuardReceipts(events, allowedReceiptIds) {
  const allowed = new Set(allowedReceiptIds);
  const byReceipt = new Map();
  for (const event of events || []) {
    if (!allowed.has(event?.target_id)) continue;
    if (!byReceipt.has(event.target_id)) byReceipt.set(event.target_id, []);
    byReceipt.get(event.target_id).push(event);
  }

  const receipts: GuardReceipt[] = [];
  for (const [receiptId, receiptEvents] of byReceipt) {
    const eventsAsc = [...receiptEvents].sort((a, b) => String(a.created_at).localeCompare(String(b.created_at)));
    const created = eventsAsc.find((event) => event.event_type === 'guard.trust_receipt.created');
    if (!created) continue;
    const base = created.after_state || {};

    let status = base.receipt_status || 'issued';
    if (eventsAsc.some((event) => event.event_type === 'guard.trust_receipt.consumed')) status = 'consumed';
    else if (findBoundSignoffDecision(eventsAsc, created, 'guard.signoff.rejected')) status = 'rejected';
    else if (findBoundSignoffDecision(eventsAsc, created, 'guard.signoff.approved')) status = 'approved_pending_consume';

    receipts.push({
      receipt_id: receiptId,
      action_type: base.action_type || 'unknown',
      organization_id: base.organization_id || 'unknown',
      decision: base.decision || 'unknown',
      enforcement_mode: base.enforcement_mode || 'enforce',
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
 * @param {*} [opts.log]
 */
export async function loadTenantGuardReceipts({
  supabase,
  tenantId,
  log,
}: {
  supabase?: SupabaseClient;
  tenantId?: string;
  log?: GuardReceiptsLogger;
} = {}) {
  if (!supabase || typeof supabase.from !== 'function') {
    return { receipts: [], error: 'Dashboard storage unavailable.' };
  }
  if (!validTenantId(tenantId)) {
    return { receipts: [], error: 'Tenant scope is required.' };
  }
  try {
    // First establish the tenant-owned receipt set. Do not fetch every guard
    // event and filter afterward: a service-role client is not constrained by
    // RLS and cross-tenant rows must never enter the application response path.
    const { data: createdEvents, error: createdError } = await supabase
      .from('audit_events')
      .select('target_id')
      .eq('event_type', 'guard.trust_receipt.created')
      .contains('after_state', { organization_id: tenantId })
      .order('created_at', { ascending: false })
      .limit(RECENT_RECEIPT_LIMIT);
    if (createdError) {
      log?.warn?.('[guard-receipts dashboard] tenant receipt lookup failed:', createdError.message);
      return { receipts: [], error: createdError.message };
    }

    const receiptIds = [...new Set((createdEvents || [])
      .map((event) => event?.target_id)
      .filter((id) => typeof id === 'string' && id.length > 0))];
    if (receiptIds.length === 0) return { receipts: [], error: null };

    const { data: events, error: eventError } = await supabase
      .from('audit_events')
      .select('event_type, target_id, actor_id, after_state, created_at')
      .like('event_type', 'guard.%')
      .in('target_id', receiptIds)
      .order('created_at', { ascending: false })
      .limit(RECENT_EVENT_LIMIT);
    if (eventError) {
      log?.warn?.('[guard-receipts dashboard] tenant event lookup failed:', eventError.message);
      return { receipts: [], error: eventError.message };
    }

    return { receipts: replayGuardReceipts(events, receiptIds), error: null };
  } catch (error) {
    log?.warn?.('[guard-receipts dashboard] threw:', error?.message);
    return { receipts: [], error: 'Dashboard query failed.' };
  }
}

export default loadTenantGuardReceipts;
