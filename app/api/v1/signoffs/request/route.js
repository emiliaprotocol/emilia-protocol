// SPDX-License-Identifier: Apache-2.0
// EP GovGuard + FinGuard — POST /api/v1/signoffs/request
//
// Records a signoff request against an existing trust receipt. The
// receipt must (a) exist, (b) have signoff_required=true. The signoff_id
// is the binding key for /approve and /reject calls.

import { NextResponse } from 'next/server';
import crypto from 'node:crypto';
import { authenticateRequest, authEntityId } from '@/lib/supabase';
import { getGuardedClient } from '@/lib/write-guard';
import { epProblem } from '@/lib/errors';
import { logger } from '@/lib/logger.js';
import { APPROVER_ID_PATTERN } from '@/lib/webauthn';

// Approval window — per MD §5.2 approvals must expire. 4 hours is a
// reasonable default for high-risk financial / government workflows;
// callers can shorten via expires_in_minutes.
const DEFAULT_APPROVAL_TTL_MS = 4 * 60 * 60 * 1000;

// Mirror the pattern enforced on GET /api/v1/trust-receipts/{id} so a
// malformed or path-traversal-shaped receipt_id never reaches the DB.
const RECEIPT_ID_PATTERN = /^tr_[a-f0-9]{32}$/;

export async function POST(request) {
  try {
    const auth = await authenticateRequest(request);
    if (auth.error) return epProblem(401, 'unauthorized', auth.error);
    // String identity, not the entity row — the stored initiator_id is what
    // the SoD check compares against at approve time.
    const initiatorEntityId = authEntityId(auth);

    const body = await request.json().catch(() => ({}));
    if (!body.receipt_id) return epProblem(400, 'missing_receipt_id', 'receipt_id is required');
    if (!RECEIPT_ID_PATTERN.test(body.receipt_id)) {
      return epProblem(400, 'invalid_receipt_id', 'receipt_id must match tr_<32-hex>');
    }

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
    if (!created.actor_id || created.actor_id !== initiatorEntityId) {
      return epProblem(
        403,
        'receipt_actor_mismatch',
        'Only the entity that created this receipt can request signoff for it',
      );
    }

    // A quorum policy implies a signoff is required, even if the policy decision
    // didn't set signoff_required.
    const quorumPolicy = created.after_state.quorum_policy || null;
    if (!created.after_state.signoff_required && !quorumPolicy) {
      return epProblem(409, 'signoff_not_required', 'Receipt does not require signoff');
    }

    const existing = events.find((e) => e.event_type === 'guard.signoff.requested');
    if (existing) {
      return epProblem(409, 'signoff_already_requested', 'Signoff already requested for this receipt');
    }

    const ttl = Number.isFinite(body.expires_in_minutes)
      ? Math.max(1, Math.min(body.expires_in_minutes, 1440)) * 60 * 1000
      : DEFAULT_APPROVAL_TTL_MS;
    const expiresAt = new Date(Date.now() + ttl).toISOString();
    const comment = typeof body.comment === 'string' ? body.comment.slice(0, 500) : null;

    // ── Quorum fan-out (EP-QUORUM-v1) ────────────────────────────────────────
    // For a quorum-gated receipt, issue ONE signoff request per roster approver.
    // Each gets its own signoff_id, so the existing one-decision-per-signoff
    // invariant (guard_signoff_decided_once) holds per approver; the consume
    // gate aggregates the resulting guard.signoff.approved events by receipt.
    if (quorumPolicy) {
      const roster = Array.isArray(quorumPolicy.approvers) ? quorumPolicy.approvers : [];
      if (roster.length === 0) {
        return epProblem(422, 'invalid_quorum_policy', 'quorum_policy.approvers must be a non-empty roster');
      }
      const signoffs = roster.map((a) => ({ signoff_id: `sig_${crypto.randomBytes(16).toString('hex')}`, role: a.role, approver_id: a.approver }));
      const rows = signoffs.map((s) => ({
        event_type: 'guard.signoff.requested',
        actor_id: initiatorEntityId,
        actor_type: 'principal',
        target_type: 'trust_receipt',
        target_id: body.receipt_id,
        action: 'request_signoff',
        before_state: null,
        after_state: {
          signoff_id: s.signoff_id,
          initiator_id: initiatorEntityId,
          action_hash: created.after_state.action_hash,
          expires_at: expiresAt,
          comment,
          // Quorum context — which seat this signoff fills.
          quorum: { role: s.role, approver_id: s.approver_id, mode: quorumPolicy.mode || 'threshold', required: quorumPolicy.required },
        },
      }));
      const { error: insertErr } = await supabase.from('audit_events').insert(rows);
      if (insertErr) {
        logger.error('[guard] signoff request (quorum): audit insert failed:', insertErr);
        return epProblem(500, 'internal_error', 'Failed to record quorum signoff requests');
      }
      return NextResponse.json({
        receipt_id: body.receipt_id,
        action_hash: created.after_state.action_hash,
        initiator_id: initiatorEntityId,
        expires_at: expiresAt,
        quorum: { mode: quorumPolicy.mode || 'threshold', required: quorumPolicy.required, count: signoffs.length },
        signoffs,
        status: 'pending',
      }, { status: 201 });
    }

    if (!body.approver_id || !APPROVER_ID_PATTERN.test(body.approver_id)) {
      return epProblem(400, 'invalid_approver_id', 'approver_id is required (3-128 chars of [A-Za-z0-9:_.@-])');
    }

    const signoffId = `sig_${crypto.randomBytes(16).toString('hex')}`;

    const { error: insertErr } = await supabase.from('audit_events').insert({
      event_type: 'guard.signoff.requested',
      actor_id: initiatorEntityId,
      actor_type: 'principal',
      target_type: 'trust_receipt',
      target_id: body.receipt_id,
      action: 'request_signoff',
      before_state: null,
      after_state: {
        signoff_id: signoffId,
        initiator_id: initiatorEntityId,
        approver_id: body.approver_id,
        action_hash: created.after_state.action_hash,
        expires_at: expiresAt,
        comment,
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
      initiator_id: initiatorEntityId,
      approver_id: body.approver_id,
      expires_at: expiresAt,
      status: 'pending',
    }, { status: 201 });
  } catch (err) {
    logger.error('[guard] POST signoffs/request error:', err);
    return epProblem(500, 'internal_error', 'Signoff request failed');
  }
}
