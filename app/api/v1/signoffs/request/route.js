// SPDX-License-Identifier: Apache-2.0
// EP GovGuard + FinGuard — POST /api/v1/signoffs/request
//
// Records a signoff request against an existing trust receipt. The
// receipt must (a) exist, (b) have signoff_required=true. The signoff_id
// is the binding key for /approve and /reject calls.

import { NextResponse } from 'next/server';
import crypto from 'node:crypto';
import { authenticateRequest } from '@/lib/supabase';
import { getGuardedClient } from '@/lib/write-guard';
import { epProblem } from '@/lib/errors';
import { logger } from '@/lib/logger.js';

// Approval window — per MD §5.2 approvals must expire. 4 hours is a
// reasonable default for high-risk financial / government workflows;
// callers can shorten via expires_in_minutes.
const DEFAULT_APPROVAL_TTL_MS = 4 * 60 * 60 * 1000;

export async function POST(request) {
  try {
    const auth = await authenticateRequest(request);
    if (auth.error) return epProblem(401, 'unauthorized', auth.error);

    const body = await request.json().catch(() => ({}));
    if (!body.receipt_id) return epProblem(400, 'missing_receipt_id', 'receipt_id is required');

    const supabase = getGuardedClient();

    const { data: events, error } = await supabase
      .from('audit_events')
      .select('event_type, after_state, created_at')
      .eq('target_type', 'trust_receipt')
      .eq('target_id', body.receipt_id)
      .order('created_at', { ascending: true });

    if (error) {
      logger.error('[guard] signoff request: load events failed:', error);
      return epProblem(500, 'internal_error', 'Failed to load receipt');
    }
    if (!events || events.length === 0) {
      return epProblem(404, 'receipt_not_found', `Trust receipt ${body.receipt_id} not found`);
    }

    const created = events.find((e) => e.event_type === 'guard.trust_receipt.created');
    if (!created) return epProblem(500, 'corrupted_receipt', 'Receipt missing creation event');

    if (!created.after_state.signoff_required) {
      return epProblem(409, 'signoff_not_required', 'Receipt does not require signoff');
    }

    const existing = events.find((e) => e.event_type === 'guard.signoff.requested');
    if (existing) {
      return epProblem(409, 'signoff_already_requested', 'Signoff already requested for this receipt');
    }

    const ttl = Number.isFinite(body.expires_in_minutes)
      ? Math.max(1, Math.min(body.expires_in_minutes, 1440)) * 60 * 1000
      : DEFAULT_APPROVAL_TTL_MS;
    const signoffId = `sig_${crypto.randomBytes(16).toString('hex')}`;
    const expiresAt = new Date(Date.now() + ttl).toISOString();

    const { error: insertErr } = await supabase.from('audit_events').insert({
      event_type: 'guard.signoff.requested',
      actor_id: auth.entity,
      actor_type: 'principal',
      target_type: 'trust_receipt',
      target_id: body.receipt_id,
      action: 'request_signoff',
      before_state: null,
      after_state: {
        signoff_id: signoffId,
        initiator_id: auth.entity,
        action_hash: created.after_state.action_hash,
        expires_at: expiresAt,
        comment: typeof body.comment === 'string' ? body.comment.slice(0, 500) : null,
      },
    });

    if (insertErr) {
      logger.error('[guard] signoff request: audit insert failed:', insertErr);
      return epProblem(500, 'internal_error', 'Failed to record signoff request');
    }

    return NextResponse.json({
      signoff_id: signoffId,
      receipt_id: body.receipt_id,
      action_hash: created.after_state.action_hash,
      initiator_id: auth.entity,
      expires_at: expiresAt,
      status: 'pending',
    }, { status: 201 });
  } catch (err) {
    logger.error('[guard] POST signoffs/request error:', err);
    return epProblem(500, 'internal_error', 'Signoff request failed');
  }
}
