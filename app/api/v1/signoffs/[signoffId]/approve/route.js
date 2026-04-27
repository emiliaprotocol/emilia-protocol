// SPDX-License-Identifier: Apache-2.0
// EP GovGuard + FinGuard — POST /api/v1/signoffs/[signoffId]/approve
//
// Critical invariants enforced (per MD §5.2 + §12.2):
//   - approver MUST NOT be the initiator (self-approval guard)
//   - approval MUST bind to the exact action_hash issued at receipt creation
//   - approval MUST NOT be reusable for a different action
//   - approval expires per the request's expires_at; expired approvals fail
//   - approval cannot be repeated (one-shot per signoff)

import { NextResponse } from 'next/server';
import { authenticateRequest } from '@/lib/supabase';
import { getGuardedClient } from '@/lib/write-guard';
import { epProblem } from '@/lib/errors';
import { logger } from '@/lib/logger.js';

export async function POST(request, { params }) {
  return handleSignoffDecision(request, params, 'approved');
}

export async function handleSignoffDecision(request, params, decision) {
  try {
    const auth = await authenticateRequest(request);
    if (auth.error) return epProblem(401, 'unauthorized', auth.error);

    const { signoffId } = await params;
    const body = await request.json().catch(() => ({}));

    if (!body.approved_action_hash) {
      return epProblem(400, 'missing_action_hash', 'approved_action_hash is required');
    }

    const supabase = getGuardedClient();

    // Find the signoff request — search by event_type + signoff_id in
    // after_state. The audit_events table is the source of truth.
    const { data: requests, error: reqErr } = await supabase
      .from('audit_events')
      .select('target_id, actor_id, after_state, created_at')
      .eq('event_type', 'guard.signoff.requested');

    if (reqErr) {
      logger.error('[guard] signoff approve: load requests failed:', reqErr);
      return epProblem(500, 'internal_error', 'Failed to load signoff request');
    }

    const requestEvent = (requests || []).find((e) => e.after_state?.signoff_id === signoffId);
    if (!requestEvent) {
      return epProblem(404, 'signoff_not_found', `Signoff ${signoffId} not found`);
    }

    const receiptId = requestEvent.target_id;
    const initiatorId = requestEvent.after_state.initiator_id;
    const expectedActionHash = requestEvent.after_state.action_hash;
    const expiresAt = requestEvent.after_state.expires_at;

    // ── Self-approval guard (per MD §5.2 + §12.2.2) ──────────────────────
    if (auth.entity === initiatorId) {
      return epProblem(
        403,
        'self_approval_forbidden',
        'Approver cannot be the initiator of the signoff request',
      );
    }

    // ── Action-hash binding (per MD §5.2 + §12.2.5) ──────────────────────
    if (body.approved_action_hash !== expectedActionHash) {
      return epProblem(
        409,
        'action_hash_mismatch',
        'approved_action_hash does not match the receipt-issued action_hash',
      );
    }

    // ── Expiry check ──────────────────────────────────────────────────────
    if (new Date(expiresAt) < new Date()) {
      return epProblem(410, 'signoff_expired', 'Signoff approval window has expired');
    }

    // ── One-shot guard (no repeat approve/reject) ────────────────────────
    const { data: priorDecisions } = await supabase
      .from('audit_events')
      .select('event_type, after_state')
      .eq('target_type', 'trust_receipt')
      .eq('target_id', receiptId)
      .in('event_type', ['guard.signoff.approved', 'guard.signoff.rejected']);

    const alreadyDecided = (priorDecisions || []).some(
      (e) => e.after_state?.signoff_id === signoffId,
    );
    if (alreadyDecided) {
      return epProblem(409, 'signoff_already_decided', 'Signoff has already been decided');
    }

    // ── Record decision ───────────────────────────────────────────────────
    const decidedAt = new Date().toISOString();
    const { error: insertErr } = await supabase.from('audit_events').insert({
      event_type: `guard.signoff.${decision}`,
      actor_id: auth.entity,
      actor_type: 'principal',
      target_type: 'trust_receipt',
      target_id: receiptId,
      action: decision,
      before_state: { signoff_status: 'pending' },
      after_state: {
        signoff_id: signoffId,
        approver_id: auth.entity,
        approved_action_hash: body.approved_action_hash,
        comment: typeof body.comment === 'string' ? body.comment.slice(0, 500) : null,
        decided_at: decidedAt,
      },
    });

    if (insertErr) {
      logger.error('[guard] signoff decision: audit insert failed:', insertErr);
      return epProblem(500, 'internal_error', 'Failed to record signoff decision');
    }

    return NextResponse.json({
      signoff_id: signoffId,
      receipt_id: receiptId,
      decision,
      approver_id: auth.entity,
      decided_at: decidedAt,
    });
  } catch (err) {
    logger.error('[guard] signoff decision error:', err);
    return epProblem(500, 'internal_error', 'Signoff decision failed');
  }
}
