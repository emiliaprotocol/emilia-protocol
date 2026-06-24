// SPDX-License-Identifier: Apache-2.0
// EP GovGuard + FinGuard — GET /api/v1/trust-receipts/[receiptId]
//
// Reconstructs a trust receipt's current state from the audit_events log.
// The audit_events insert at create time is the source of truth (immutable
// append-only); this endpoint replays the event stream to derive the
// current receipt status.

import { NextResponse } from 'next/server';
import { authenticateRequest } from '@/lib/supabase';
import { getGuardedClient } from '@/lib/write-guard';
import { epProblem } from '@/lib/errors';
import { logger } from '@/lib/logger.js';
import { findBoundSignoffDecision } from '@/lib/guard-signoff-binding.js';
import { canReadReceipt } from '@/lib/tenant-binding';

const RECEIPT_ID_PATTERN = /^tr_[a-f0-9]{32}$/;

export async function GET(request, { params }) {
  try {
    const auth = await authenticateRequest(request);
    if (auth.error) return epProblem(401, 'unauthorized', auth.error);

    const { receiptId } = await params;

    if (!RECEIPT_ID_PATTERN.test(receiptId)) {
      return epProblem(400, 'invalid_receipt_id', 'receipt_id must match tr_<32-hex>');
    }

    const supabase = getGuardedClient();

    // Pull the full event timeline for this receipt. Ordered by created_at
    // so the latest state wins.
    const { data: events, error } = await supabase
      .from('audit_events')
      .select('event_type, actor_id, action, before_state, after_state, created_at')
      .eq('target_type', 'trust_receipt')
      .eq('target_id', receiptId)
      .order('created_at', { ascending: true });

    if (error) {
      logger.error('[guard] audit_events fetch failed:', error);
      return epProblem(500, 'internal_error', 'Failed to load receipt');
    }

    if (!events || events.length === 0) {
      return epProblem(404, 'receipt_not_found', `Trust receipt ${receiptId} not found`);
    }

    // Replay event stream to derive current state.
    const created = events.find((e) => e.event_type === 'guard.trust_receipt.created');
    if (!created) {
      return epProblem(500, 'corrupted_receipt', 'Receipt missing creation event');
    }

    const base = created.after_state;

    // Tenant scoping (IDOR): only the receipt's own org (or, transitionally,
    // its creator) may read it. Mismatch => 404, not 403, so a cross-tenant
    // caller cannot even confirm the receipt exists.
    if (!canReadReceipt(auth, { organizationId: base.organization_id, creatorActorId: created.actor_id })) {
      return epProblem(404, 'receipt_not_found', `Trust receipt ${receiptId} not found`);
    }

    const consumed = events.find((e) => e.event_type === 'guard.trust_receipt.consumed');
    const signoffApproved = findBoundSignoffDecision(events, created, 'guard.signoff.approved');
    const signoffRejected = findBoundSignoffDecision(events, created, 'guard.signoff.rejected');

    let receipt_status = base.receipt_status;
    if (consumed) receipt_status = 'consumed';
    else if (signoffRejected) receipt_status = 'rejected';
    else if (signoffApproved) receipt_status = 'approved_pending_consume';

    return NextResponse.json({
      receipt_id: receiptId,
      organization_id: base.organization_id,
      action_type: base.action_type,
      decision: base.decision,
      enforcement_mode: base.enforcement_mode,
      policy_id: base.policy_id,
      policy_hash: base.policy_hash,
      action_hash: base.action_hash,
      before_state_hash: base.before_state_hash,
      after_state_hash: base.after_state_hash,
      expires_at: base.expires_at,
      signoff_required: base.signoff_required,
      receipt_status,
      // Key class of the decisive signoff, per the EP draft §5.1 labeling
      // requirement: 'A' = approver-held device key (WebAuthn assertion on
      // file), 'C' = operator-custodied (bearer-key auth, server-recorded).
      // Pre-labeling decisions default to 'C' — that is what they were.
      signoff_key_class: signoffApproved || signoffRejected
        ? ((signoffApproved || signoffRejected).after_state?.key_class || 'C')
        : null,
      timeline_event_count: events.length,
    });
  } catch (err) {
    logger.error('[guard] GET /api/v1/trust-receipts/[receiptId] error:', err);
    return epProblem(500, 'internal_error', 'Failed to fetch receipt');
  }
}
