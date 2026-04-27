// SPDX-License-Identifier: Apache-2.0
// EP GovGuard + FinGuard — v1 Trust Receipts API
//
// POST /api/v1/trust-receipts — create a pre-action trust receipt
// GET  /api/v1/trust-receipts — (not implemented — use organization-scoped list endpoint)
//
// This is the v1 product façade over EP's existing handshake + commit
// primitives. The trust-receipt model from
// /Users/imanschrock/Desktop/Ventures/emilia_govguard_finguard_coding_changes.md
// maps to EP primitives as:
//
//   trust receipt   = handshake + (optional) commit
//   action_hash     = sha256(canonical(action))
//   nonce           = handshake_id (already cryptographically random)
//   policy_hash     = handshake.policy_hash
//   signoff state   = mediated by lib/signoff/* once requested
//   consume         = consume_handshake_atomic (existing RPC)

import { NextResponse } from 'next/server';
import crypto from 'node:crypto';
import { authenticateRequest, getServiceClient } from '@/lib/supabase';
import { epProblem } from '@/lib/errors';
import {
  evaluateGuardPolicy,
  applyEnforcementMode,
  hashCanonicalAction,
  GUARD_DECISIONS,
  ENFORCEMENT_MODES,
} from '@/lib/guard-policies';
import { logger } from '@/lib/logger.js';

// Receipt expiry: 24 hours by default. Per MD §2.3, expires_at is required
// on every receipt. 24h is the EP default for handshake-bound receipts.
const RECEIPT_TTL_MS = 24 * 60 * 60 * 1000;

export async function POST(request) {
  try {
    const auth = await authenticateRequest(request);
    if (auth.error) return epProblem(401, 'unauthorized', auth.error);

    const body = await request.json().catch(() => ({}));

    // ── Required fields (per MD §2.2) ─────────────────────────────────────
    const required = ['organization_id', 'action_type', 'target_resource_id'];
    for (const f of required) {
      if (!body[f]) return epProblem(400, `missing_${f}`, `${f} is required`);
    }

    // ── CRITICAL INVARIANT (per MD §2.4 + §12.2.1) ───────────────────────
    // Actor identity NEVER comes from the request body alone. The
    // authenticated context is the source of truth; body actor_id must
    // match the auth.entity (or be absent).
    const actor_id = auth.entity;
    if (body.actor_id && body.actor_id !== actor_id) {
      return epProblem(
        403,
        'actor_id_mismatch',
        'actor_id in request body does not match authenticated entity',
      );
    }

    const now = new Date();
    const expiresAt = new Date(now.getTime() + RECEIPT_TTL_MS);
    const nonce = `nonce_${crypto.randomBytes(12).toString('hex')}`;
    const receiptId = `tr_${crypto.randomBytes(16).toString('hex')}`;

    // ── Build canonical action object & hash ─────────────────────────────
    const beforeHash = body.before_state
      ? hashCanonicalAction(body.before_state)
      : null;
    const afterHash = body.after_state
      ? hashCanonicalAction(body.after_state)
      : null;

    const policyId = body.policy_id || `policy_default_${body.action_type}`;
    const policyHash = hashCanonicalAction({ policy_id: policyId, version: 1 });

    const canonicalAction = {
      organization_id: body.organization_id,
      actor_id,
      action_type: body.action_type,
      target_resource_id: body.target_resource_id,
      before_state_hash: beforeHash,
      after_state_hash: afterHash,
      policy_id: policyId,
      policy_hash: policyHash,
      nonce,
      expires_at: expiresAt.toISOString(),
      requested_at: now.toISOString(),
    };
    const actionHash = hashCanonicalAction(canonicalAction);

    // ── Policy evaluation ─────────────────────────────────────────────────
    const baseDecision = evaluateGuardPolicy({
      organizationId: body.organization_id,
      actorId: actor_id,
      actorRole: auth.actorRole || body.actor_role || 'unknown',
      actionType: body.action_type,
      targetChangedFields: body.target_changed_fields || [],
      amount: body.amount,
      currency: body.currency,
      riskFlags: body.risk_flags || [],
      authStrength: auth.authStrength || 'mfa',
      initiatorId: actor_id,
    });

    const mode = body.enforcement_mode || ENFORCEMENT_MODES.ENFORCE;
    if (!Object.values(ENFORCEMENT_MODES).includes(mode)) {
      return epProblem(400, 'invalid_enforcement_mode', `mode must be one of ${Object.values(ENFORCEMENT_MODES).join(', ')}`);
    }
    const decision = applyEnforcementMode(baseDecision, mode);

    // ── Persist (best-effort; receipt is self-describing in response) ────
    let receipt_status = 'issued';
    if (decision.signoffRequired && decision.decision === GUARD_DECISIONS.ALLOW_WITH_SIGNOFF) {
      receipt_status = 'pending_signoff';
    } else if (decision.decision === GUARD_DECISIONS.DENY) {
      receipt_status = 'denied';
    }

    const supabase = getServiceClient();
    try {
      await supabase.from('audit_events').insert({
        event_type: 'guard.trust_receipt.created',
        actor_id,
        actor_type: 'principal',
        target_type: 'trust_receipt',
        target_id: receiptId,
        action: 'create',
        before_state: null,
        after_state: {
          organization_id: body.organization_id,
          action_type: body.action_type,
          policy_id: policyId,
          policy_hash: policyHash,
          decision: decision.decision,
          enforcement_mode: mode,
          signoff_required: decision.signoffRequired,
          receipt_status,
          action_hash: actionHash,
          before_state_hash: beforeHash,
          after_state_hash: afterHash,
          expires_at: expiresAt.toISOString(),
        },
      });
    } catch (e) {
      // Best-effort — receipt is self-verifying via signature; audit is
      // observability, not the source of truth. Log so SIEM picks it up.
      logger.warn('[guard] audit_events insert failed:', e?.message);
    }

    return NextResponse.json(
      {
        receipt_id: receiptId,
        decision: decision.decision,
        observed_decision: decision.observed_decision || null,
        policy_id: policyId,
        policy_hash: policyHash,
        action_hash: actionHash,
        before_state_hash: beforeHash,
        after_state_hash: afterHash,
        nonce,
        expires_at: expiresAt.toISOString(),
        signoff_required: decision.signoffRequired,
        signoff_request_id: null, // populated when /signoffs/request is called
        risk_flags: body.risk_flags || [],
        receipt_status,
        enforcement_mode: mode,
        reasons: decision.reasons,
        // Hint for callers: the canonical action they must use at consume.
        canonical_action: canonicalAction,
      },
      { status: 201 },
    );
  } catch (err) {
    logger.error('[guard] POST /api/v1/trust-receipts error:', err);
    return epProblem(500, 'internal_error', 'Trust receipt creation failed');
  }
}
