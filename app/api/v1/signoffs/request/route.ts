// SPDX-License-Identifier: Apache-2.0
// EP GovGuard + FinGuard — POST /api/v1/signoffs/request
//
// Records a signoff request against an existing trust receipt. The
// receipt must (a) exist, (b) have signoff_required=true. The signoff_id
// is the binding key for /approve and /reject calls.

import { NextRequest, NextResponse } from 'next/server';
import crypto from 'node:crypto';
import { authenticateGuardRequest, isCloudGuardPrincipal } from '@/lib/guard-auth.js';
import { authEntityId } from '@/lib/auth-projections.js';
import { getGuardedClient } from '@/lib/write-guard';
import { epProblem } from '@/lib/errors';
import { logger } from '@/lib/logger.js';
import { APPROVER_ID_PATTERN } from '@/lib/webauthn';
import { readLimitedJson } from '@/lib/http/body-limit';

// Approval window — per MD §5.2 approvals must expire. 4 hours is a
// reasonable default for high-risk financial / government workflows;
// callers can shorten via expires_in_minutes.
const DEFAULT_APPROVAL_TTL_MS = 4 * 60 * 60 * 1000;

// Mirror the pattern enforced on GET /api/v1/trust-receipts/{id} so a
// malformed or path-traversal-shaped receipt_id never reaches the DB.
const RECEIPT_ID_PATTERN = /^tr_[a-f0-9]{32}$/;
const MAX_SIGNOFF_REQUEST_BYTES = 64 * 1024;
const ACQUISITION_REQUEST_PATTERN = /^apr_[a-f0-9]{32}$/;
const SHA256_DIGEST_PATTERN = /^sha256:[a-f0-9]{64}$/;

export async function POST(request: NextRequest): Promise<NextResponse> {
  try {
    const auth = await authenticateGuardRequest(request);
    if (auth.error) return epProblem(auth.status || 401, auth.code || 'unauthorized', auth.error);
    // String identity, not the entity row — the stored initiator_id is what
    // the SoD check compares against at approve time.
    const initiatorEntityId = authEntityId(auth);

    const parsed = await readLimitedJson(request, MAX_SIGNOFF_REQUEST_BYTES, { invalidValue: {} } as any);
    if (!parsed.ok) {
      const failure = parsed as { ok: false; status: number; code: string; detail: string };
      return epProblem(failure.status, failure.code, failure.detail);
    }
    const body = (parsed as { ok: true; value: any }).value;
    if (!body.receipt_id) return epProblem(400, 'missing_receipt_id', 'receipt_id is required');
    if (!RECEIPT_ID_PATTERN.test(body.receipt_id)) {
      return epProblem(400, 'invalid_receipt_id', 'receipt_id must match tr_<32-hex>');
    }

    const supabase = getGuardedClient();

    const { data: events, error } = await supabase
      .from('audit_events')
      .select('event_type, actor_id, after_state, created_at')
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
    if (isCloudGuardPrincipal(auth)) {
      const permissions = Array.isArray(auth.permissions) ? auth.permissions : [];
      const isAdmin = permissions.includes('admin');
      const actionType = created.after_state?.action_type;
      const allowed = (actionType === 'policy_rollout'
          && (isAdmin || permissions.includes('policy_rollout')))
        || (actionType === 'large_payment_release'
          && (isAdmin || permissions.includes('approval_request')));
      if (!allowed) {
        return epProblem(
          403,
          'cloud_guard_action_forbidden',
          'Tenant control-plane keys may request signoff only for the Guard action authorized by their named capability',
        );
      }
    }
    if (!created.actor_id || created.actor_id !== initiatorEntityId) {
      return epProblem(
        403,
        'receipt_actor_mismatch',
        'Only the entity that created this receipt can request signoff for it',
      );
    }

    const nowMs = Date.now();
    const receiptExpiresAtMs = Date.parse(created.after_state?.expires_at);
    if (!Number.isFinite(receiptExpiresAtMs)) {
      return epProblem(500, 'corrupted_receipt', 'Receipt has invalid expiry');
    }
    if (receiptExpiresAtMs <= nowMs) {
      return epProblem(410, 'receipt_expired', 'Receipt has expired');
    }

    // A quorum policy implies a signoff is required, even if the policy decision
    // didn't set signoff_required.
    const quorumPolicy = created.after_state.quorum_policy || null;
    if (!created.after_state.signoff_required && !quorumPolicy) {
      return epProblem(409, 'signoff_not_required', 'Receipt does not require signoff');
    }

    const acquisitionReplayRequested = body.return_existing === true
      || body.acquisition_request_id !== undefined
      || body.acquisition_request_digest !== undefined
      || body.acquisition_tenant_id !== undefined
      || body.acquisition_environment !== undefined;
    const acquisitionReplayValid = acquisitionReplayRequested
      && isCloudGuardPrincipal(auth)
      && !quorumPolicy
      && ACQUISITION_REQUEST_PATTERN.test(body.acquisition_request_id || '')
      && SHA256_DIGEST_PATTERN.test(body.acquisition_request_digest || '')
      && body.acquisition_tenant_id === created.after_state?.organization_id
      && body.acquisition_tenant_id === authEntityId(auth)
      && body.acquisition_environment === auth.guard_cloud?.environment
      && created.after_state?.acquisition_request_id === body.acquisition_request_id
      && created.after_state?.acquisition_request_digest === body.acquisition_request_digest
      && created.after_state?.acquisition_tenant_id === body.acquisition_tenant_id
      && created.after_state?.acquisition_environment === body.acquisition_environment
      && APPROVER_ID_PATTERN.test(body.approver_id || '');
    if (acquisitionReplayRequested && !acquisitionReplayValid) {
      return epProblem(409, 'acquisition_binding_conflict', 'The signoff replay binding does not match the durable receipt');
    }

    const existing = events.find((e) => e.event_type === 'guard.signoff.requested');
    if (existing) {
      if (acquisitionReplayValid
          && existing.actor_id === initiatorEntityId
          && existing.after_state?.approver_id === body.approver_id
          && existing.after_state?.action_hash === created.after_state.action_hash
          && existing.after_state?.acquisition_request_id === body.acquisition_request_id
          && existing.after_state?.acquisition_request_digest === body.acquisition_request_digest
          && existing.after_state?.acquisition_tenant_id === body.acquisition_tenant_id
          && existing.after_state?.acquisition_environment === body.acquisition_environment
          && /^sig_[a-f0-9]{32}$/.test(existing.after_state?.signoff_id || '')) {
        return NextResponse.json({
          signoff_id: existing.after_state.signoff_id,
          receipt_id: body.receipt_id,
          action_hash: created.after_state.action_hash,
          initiator_id: initiatorEntityId,
          approver_id: existing.after_state.approver_id,
          expires_at: existing.after_state.expires_at,
          status: 'pending',
        }, {
          status: 200,
          headers: { 'cache-control': 'no-store, private', 'x-emilia-idempotent-replay': 'true' },
        });
      }
      return epProblem(409, 'signoff_already_requested', 'Signoff already requested for this receipt');
    }

    const ttl = Number.isFinite(body.expires_in_minutes)
      ? Math.max(1, Math.min(body.expires_in_minutes, 1440)) * 60 * 1000
      : DEFAULT_APPROVAL_TTL_MS;
    const expiresAt = new Date(Math.min(receiptExpiresAtMs, nowMs + ttl)).toISOString();
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
          required_assurance: created.after_state.required_assurance || null,
          // Quorum context — which seat this signoff fills.
          quorum: { role: s.role, approver_id: s.approver_id, mode: quorumPolicy.mode || 'threshold', required: quorumPolicy.required },
        },
      }));
      const { error: insertErr } = await supabase.from('audit_events').insert(rows);
      if (insertErr) {
        if (insertErr.code === '23505') {
          return epProblem(409, 'signoff_already_requested', 'Signoff already requested for this receipt');
        }
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
        required_assurance: created.after_state.required_assurance || null,
        ...(acquisitionReplayValid ? {
          acquisition_request_id: body.acquisition_request_id,
          acquisition_request_digest: body.acquisition_request_digest,
          acquisition_tenant_id: body.acquisition_tenant_id,
          acquisition_environment: body.acquisition_environment,
        } : {}),
      },
    });

    if (insertErr) {
      if (insertErr.code === '23505') {
        return epProblem(409, 'signoff_already_requested', 'Signoff already requested for this receipt');
      }
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
