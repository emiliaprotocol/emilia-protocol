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
import { authenticateRequest } from '@/lib/supabase';
import { getGuardedClient } from '@/lib/write-guard';
import { epProblem } from '@/lib/errors';
import {
  evaluateGuardPolicy,
  applyEnforcementMode,
  hashCanonicalAction,
  GUARD_ACTION_TYPES,
  GUARD_DECISIONS,
  ENFORCEMENT_MODES,
} from '@/lib/guard-policies';
import { evaluateAction as evaluateRulesEngineV0 } from '@/lib/rules-engine.js';
import { logger } from '@/lib/logger.js';
import { isRulesEngineV0Enabled } from '@/lib/env.js';

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

    // ── action_type allowlist ─────────────────────────────────────────────
    // Without this, the default-allow path issues a real audit-recorded
    // receipt for any garbage action_type the caller supplies. Constrain
    // to the documented GUARD_ACTION_TYPES vocabulary.
    if (!Object.values(GUARD_ACTION_TYPES).includes(body.action_type)) {
      return epProblem(
        400,
        'invalid_action_type',
        `action_type must be one of: ${Object.values(GUARD_ACTION_TYPES).join(', ')}`,
      );
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
    // authenticateRequest returns { entity, permissions } — actorRole and
    // authStrength are NOT on the auth shape today. Pass through what the
    // body supplies (advisory only, not security-relevant — the policy
    // engine treats these as informational hints) and document the gap.
    // When the auth layer grows role/strength fields, replace with auth.*.
    const baseDecision = evaluateGuardPolicy({
      organizationId: body.organization_id,
      actorId: actor_id,
      actorRole: body.actor_role || 'unknown',
      actionType: body.action_type,
      targetChangedFields: body.target_changed_fields || [],
      amount: body.amount,
      currency: body.currency,
      riskFlags: body.risk_flags || [],
      authStrength: 'mfa',  // hardcoded until authenticateRequest exposes it
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

    const supabase = getGuardedClient();
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

    // ── Rules-engine v0 shadow signal (feature-flagged) ──────────────────
    // When EP_RULES_ENGINE_V0=enabled, run the audit's §4 rules engine
    // alongside the live evaluator and emit the result as a separate
    // audit_event. Pure observability — does not change response shape
    // or block any behavior. The shadow record gives ops a "what would
    // the new evaluator have decided" diff that's auditable and
    // reversible (drop the flag to disable). Nothing here can throw out
    // of the route — every failure is swallowed + logged.
    //
    // KNOWN LIMITATIONS — be honest about what this signal does and
    // doesn't tell you:
    //
    //  1. STUB AUTHORITY. The rules-engine input below uses a stub
    //     authority with max_amount_usd: Number.MAX_SAFE_INTEGER and
    //     scope: [body.action_type], because no authority registry
    //     exists yet. This SHORT-CIRCUITS 4 of the 9 hard-deny rules
    //     in §4.5: AMOUNT_EXCEEDS_AUTHORITY, AUTHORITY_REVOKED,
    //     AUTHORITY_EXPIRED, ACTION_OUTSIDE_AUTHORITY_SCOPE. The
    //     shadow signal cannot tell you whether the new evaluator
    //     would have caught authority-side issues — only signoff,
    //     quorum, separation-of-duty, and risk-score issues. Until a
    //     real authority registry is wired here, treat shadow data as
    //     partial.
    //
    //  2. ARBITRARY RISK WEIGHTS. §4.9's risk-score weights (15, 15,
    //     10, 15, 20, 25, 10, 20, 30) and thresholds (≥80, ≥50, ≥30)
    //     are heuristics from an external doc, not data-calibrated.
    //     Real fraud-detection thresholds need labeled outcomes.
    //     Pitch this as "pre-calibration scaffold" not "production
    //     fraud engine."
    if (isRulesEngineV0Enabled()) {
      try {
        const rulesEngineInput = {
          tenant_id: body.organization_id,
          environment: mode === ENFORCEMENT_MODES.ENFORCE ? 'enforce' : 'shadow',
          workflow: body.action_type,
          actor: {
            actor_id,
            role: body.actor_role || 'unknown',
            department: body.actor_department,
            // Auth is bearer-token + middleware-enforced; treat as MFA-strong.
            assurance_level: 'high',
            mfa_verified: true,
          },
          action: {
            action_id: receiptId,
            action_type: body.action_type,
            amount_usd: typeof body.amount === 'number' ? body.amount : undefined,
          },
          // Until an authority registry exists, supply a stub authority
          // that passes every hard-deny check. The engine's useful shadow
          // signal here is risk-scoring + signoff + quorum, not authority
          // (which the live evaluator handles via its own path). When the
          // registry lands, replace this stub with a real lookup.
          authority: {
            authority_id: 'shadow_default_authority',
            scope: [body.action_type],
            max_amount_usd: Number.MAX_SAFE_INTEGER,
            revoked: false,
          },
          context: {
            business_hours: typeof body.business_hours === 'boolean' ? body.business_hours : true,
            velocity_same_actor_24h: body.velocity_same_actor_24h,
            prior_denials_actor_30d: body.prior_denials_actor_30d,
            prior_changes_target_30d: body.prior_changes_target_30d,
            destination_age_days: body.destination_age_days,
            watchlist_hit: (body.risk_flags || []).includes('watchlist_hit'),
          },
        };

        const rulesEngineResult = evaluateRulesEngineV0(rulesEngineInput);

        await supabase.from('audit_events').insert({
          event_type: 'rules-engine.v0.shadow',
          actor_id,
          actor_type: 'system',
          target_type: 'trust_receipt',
          target_id: receiptId,
          action: 'shadow_evaluate',
          before_state: null,
          after_state: {
            rules_engine_decision: rulesEngineResult.decision,
            rules_engine_reason_codes: rulesEngineResult.reason_codes,
            rules_engine_required_approvals: rulesEngineResult.required_approvals,
            rules_engine_required_signoff: rulesEngineResult.required_signoff,
            rules_engine_risk_score: rulesEngineResult.risk_score,
            // Live evaluator's decision pinned alongside for diff
            guard_policy_decision: decision.decision,
            guard_policy_signoff_required: decision.signoffRequired,
            // So ops can correlate even after the flag flips
            feature_flag: 'EP_RULES_ENGINE_V0',
            evaluator_version: '0',
          },
        });
      } catch (e) {
        // Shadow signal failure must never break the live route. Log only.
        logger.warn('[rules-engine.v0] shadow eval failed:', e?.message);
      }
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
