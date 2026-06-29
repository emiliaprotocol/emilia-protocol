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
import { authenticateRequest, authEntityId } from '@/lib/supabase';
import { resolveAuthorizedOrg } from '@/lib/tenant-binding';
import { getGuardedClient } from '@/lib/write-guard';
import { epProblem } from '@/lib/errors';
import {
  evaluateGuardPolicy,
  applyEnforcementMode,
  hashCanonicalAction,
  computeGuardPolicyHash,
  GUARD_ACTION_TYPES,
  GUARD_DECISIONS,
  ENFORCEMENT_MODES,
} from '@/lib/guard-policies';
import { evaluateAction as evaluateRulesEngineV0 } from '@/lib/rules-engine.js';
import { logger } from '@/lib/logger.js';
import { isRulesEngineV0Enabled } from '@/lib/env.js';
import { readLimitedJson } from '@/lib/http/body-limit';
import {
  buildExecutionBindingContract,
  enrichCanonicalActionForExecution,
} from '@/lib/execution/binding-contract';

// Receipt expiry: 24 hours by default AND hard maximum. Per MD §2.3, expires_at
// is required on every receipt. Higher-risk actions should live for minutes, not
// hours — callers may request a SHORTER ttl via body.expires_in_sec (clamped to
// [MIN, MAX]). A shorter TTL is strictly more restrictive, so honoring a
// body-supplied value is safe; a longer one is never allowed.
const RECEIPT_TTL_MS = 24 * 60 * 60 * 1000;
const RECEIPT_TTL_MIN_MS = 60 * 1000;
const MAX_TRUST_RECEIPT_CREATE_BYTES = 256 * 1024;

function resolveReceiptTtlMs(expiresInSec) {
  const n = Number(expiresInSec);
  if (!Number.isFinite(n) || n <= 0) return RECEIPT_TTL_MS;
  return Math.min(RECEIPT_TTL_MS, Math.max(RECEIPT_TTL_MIN_MS, Math.floor(n) * 1000));
}

export async function POST(request) {
  try {
    const auth = await authenticateRequest(request);
    if (auth.error) return epProblem(401, 'unauthorized', auth.error);

    const parsed = await readLimitedJson(request, MAX_TRUST_RECEIPT_CREATE_BYTES, { invalidValue: {} });
    if (!parsed.ok) return epProblem(parsed.status, parsed.code, parsed.detail);
    const body = parsed.value;

    // ── Tenant binding: derive org from the AUTHENTICATED entity, not the body.
    // An authenticated caller must not be able to scope a receipt to another
    // org by passing organization_id. (lib/tenant-binding.js + migration 101.)
    const orgResolution = resolveAuthorizedOrg(auth, body.organization_id, { requireBound: true });
    if (orgResolution.error) {
      return epProblem(orgResolution.error.status, orgResolution.error.code, orgResolution.error.detail);
    }
    body.organization_id = orgResolution.organizationId;

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
    const actor_id = authEntityId(auth);
    if (body.actor_id && body.actor_id !== actor_id) {
      return epProblem(
        403,
        'actor_id_mismatch',
        'actor_id in request body does not match authenticated entity',
      );
    }

    const now = new Date();
    const expiresAt = new Date(now.getTime() + resolveReceiptTtlMs(body.expires_in_sec));
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
    const policyHash = computeGuardPolicyHash(policyId); // #4: binds full rule content

    const canonicalActionBase = {
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
    const actionDetails = {
      amount: body.amount,
      currency: body.currency,
      risk_flags: body.risk_flags,
      target_changed_fields: body.target_changed_fields,
      counterparty_name: body.counterparty_name,
      counterparty_country: body.counterparty_country,
      beneficiary_name: body.beneficiary_name,
      beneficiary_country: body.beneficiary_country,
      payee_name: body.payee_name,
      payment_instruction_id: body.payment_instruction_id,
      bank_account: body.bank_account,
      routing_number: body.routing_number,
      iban: body.iban,
      swift_bic: body.swift_bic,
      payment_address: body.payment_address,
      case_id: body.case_id,
      decision_id: body.decision_id,
      subject_id: body.subject_id,
      record_id: body.record_id,
      override_reason: body.override_reason,
      regulated_decision: body.regulated_decision,
      principal_id: body.principal_id,
      permission: body.permission,
      role: body.role,
      scope: body.scope,
      repo: body.repo,
      ref: body.ref,
      commit_sha: body.commit_sha,
      artifact_digest: body.artifact_digest,
      environment: body.environment,
    };
    const canonicalAction = enrichCanonicalActionForExecution(canonicalActionBase, actionDetails);
    const actionHash = hashCanonicalAction(canonicalAction);

    // ── Policy evaluation ─────────────────────────────────────────────────
    // authenticateRequest returns { entity, permissions } — actorRole and
    // authStrength are NOT on the auth shape today, and no current policy branches
    // on authStrength. We therefore pass the WEAKEST credible value ('password')
    // as a fail-SAFE default: if/when a policy starts gating on auth strength, an
    // unproven request escalates to signoff rather than being assumed MFA. Never
    // trust a body-supplied strength (the agent controls it). Replace with the
    // verified value when the auth layer exposes role/strength.
    const baseDecision = evaluateGuardPolicy({
      organizationId: body.organization_id,
      actorId: actor_id,
      actorRole: body.actor_role || 'unknown',
      actionType: body.action_type,
      targetChangedFields: body.target_changed_fields || [],
      amount: body.amount,
      currency: body.currency,
      riskFlags: body.risk_flags || [],
      authStrength: 'password',  // fail-safe default (weakest); NOT verified MFA
      initiatorId: actor_id,
    });

    const mode = body.enforcement_mode || ENFORCEMENT_MODES.ENFORCE;
    if (!Object.values(ENFORCEMENT_MODES).includes(mode)) {
      return epProblem(400, 'invalid_enforcement_mode', `mode must be one of ${Object.values(ENFORCEMENT_MODES).join(', ')}`);
    }
    const decision = applyEnforcementMode(baseDecision, mode);
    const executionBinding = buildExecutionBindingContract({
      canonicalAction,
      actionDetails,
      decision,
    });

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
          required_assurance: decision.requiredAssurance ?? null,
          // Value-tier ('single' | 'dual' | null) — persisted so consume can
          // enforce dual authorization (2 distinct Class-A approvers) for the tier.
          signoff_tier: decision.signoffTier ?? null,
          // EP-QUORUM-v1: an optional multi-party policy. When present, consume
          // requires a SATISFIED quorum of Class-A signoffs (not just one
          // approval). NULL = single-signoff, unchanged. The quorum implies a
          // signoff is required regardless of the policy decision.
          quorum_policy: body.quorum_policy || null,
          receipt_status,
          action_hash: actionHash,
          before_state_hash: beforeHash,
          after_state_hash: afterHash,
          expires_at: expiresAt.toISOString(),
          // WYSIWYS (draft §11.3 control 1): the signoff render surface MUST
          // draw from the exact bytes that were hashed, so the canonical
          // action is persisted with the receipt — not re-described later.
          canonical_action: canonicalAction,
          execution_binding: executionBinding,
          // Display-material parameters for the approval surface.
          amount: typeof body.amount === 'number' ? body.amount : null,
          currency: body.currency || null,
          risk_flags: body.risk_flags || [],
          target_resource_id: body.target_resource_id,
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
        execution_binding: executionBinding,
      },
      { status: 201 },
    );
  } catch (err) {
    logger.error('[guard] POST /api/v1/trust-receipts error:', err);
    return epProblem(500, 'internal_error', 'Trust receipt creation failed');
  }
}
