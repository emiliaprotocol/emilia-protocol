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
import { authenticateGuardRequest, isCloudGuardPrincipal } from '@/lib/guard-auth.js';
import { authEntityId } from '@/lib/auth-projections.js';
import { resolveVerifiedAuthStrength } from '@/lib/auth-strength.js';
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
import { isRulesEngineV0Enabled, isQuorumTemplateRequired, authorityEnforcementMode } from '@/lib/env.js';
import { supabaseAuthorityStore, resolveAuthority } from '@/lib/authority/store.js';
import { authorityBinding } from '@/lib/authority/resolver.js';
import { applyAuthorityEnforcement } from '@/lib/authority/enforcement.js';
import { resolveOrgQuorumTemplate, evaluateQuorumAgainstTemplate } from '@/lib/guard-quorum-template.js';
import { readLimitedJson } from '@/lib/http/body-limit';
import {
  buildExecutionBindingContract,
  enrichCanonicalActionForExecution,
} from '@/lib/execution/binding-contract';
import {
  extractGuardActionDetails,
  resolveGuardChangedFields,
  resolveGuardEnforcementMode,
  validateGuardActionInput,
} from '@/lib/guard-action-inputs';
import { computeCaid } from '@/caid/impl/js/caid.mjs';
import caidActionTypeRegistry from '@/caid/registry/action-types.json';

// Receipt expiry: 24 hours by default AND hard maximum. Per MD §2.3, expires_at
// is required on every receipt. Higher-risk actions should live for minutes, not
// hours — callers may request a SHORTER ttl via body.expires_in_sec (clamped to
// [MIN, MAX]). A shorter TTL is strictly more restrictive, so honoring a
// body-supplied value is safe; a longer one is never allowed.
const RECEIPT_TTL_MS = 24 * 60 * 60 * 1000;
const RECEIPT_TTL_MIN_MS = 60 * 1000;
const MAX_TRUST_RECEIPT_CREATE_BYTES = 256 * 1024;
const SHA256_DIGEST_PATTERN = /^sha256:[a-f0-9]{64}$/;
const PAYMENT_RELEASE_CAID_DEFINITION = caidActionTypeRegistry.types.find(
  (definition) => definition.action_type === 'payment.release.1'
    && definition.status === 'active',
);

function resolveReceiptTtlMs(expiresInSec, maxTtlMs = RECEIPT_TTL_MS) {
  const n = Number(expiresInSec);
  if (!Number.isFinite(n) || n <= 0) return maxTtlMs;
  return Math.min(maxTtlMs, Math.max(RECEIPT_TTL_MIN_MS, Math.floor(n) * 1000));
}

export async function POST(request) {
  try {
    const auth = await authenticateGuardRequest(request);
    if (auth.error) return epProblem(auth.status || 401, auth.code || 'unauthorized', auth.error);

    const parsed = await readLimitedJson(request, MAX_TRUST_RECEIPT_CREATE_BYTES, { invalidValue: {} });
    if (!parsed.ok) return epProblem(parsed.status, parsed.code, parsed.detail);
    const body = parsed.value;
    // A valid top-level JSON null / array / scalar parses cleanly (invalidValue only
    // catches parse errors), so guard the shape before any field dereference below.
    if (body === null || typeof body !== 'object' || Array.isArray(body)) {
      return epProblem(400, 'invalid_body', 'request body must be a JSON object');
    }

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
    // match the authenticated entity id (or be absent).
    const actor_id = authEntityId(auth);
    const authStrength = resolveVerifiedAuthStrength(auth);
    const cloudPermissions = Array.isArray(auth.permissions) ? auth.permissions : [];
    const cloudIsAdmin = cloudPermissions.includes('admin');
    const cloudMayRollout = cloudIsAdmin || cloudPermissions.includes('policy_rollout');
    const cloudMayRequestApproval = cloudIsAdmin || cloudPermissions.includes('approval_request');
    if (body.action_type === GUARD_ACTION_TYPES.POLICY_ROLLOUT
        && !isCloudGuardPrincipal(auth)) {
      return epProblem(
        403,
        'policy_rollout_cloud_key_required',
        'Policy rollout Trust Receipts may be created only by the authenticated tenant rollout key',
      );
    }
    if (isCloudGuardPrincipal(auth)) {
      const isRollout = body.action_type === GUARD_ACTION_TYPES.POLICY_ROLLOUT;
      const isApprovalRequest = body.action_type === GUARD_ACTION_TYPES.LARGE_PAYMENT_RELEASE;
      if ((!isRollout && !isApprovalRequest)
          || (isRollout && !cloudMayRollout)
          || (isApprovalRequest && !cloudMayRequestApproval)) {
        return epProblem(
          403,
          'cloud_guard_action_forbidden',
          'Tenant control-plane keys may create only the Guard action authorized by their named capability',
        );
      }
      if (isRollout && body.executing_key_id !== auth.guard_cloud.key_id) {
        return epProblem(
          403,
          'executing_key_mismatch',
          'Policy rollout executing_key_id must match the authenticated tenant API key',
        );
      }
      if (isApprovalRequest) {
        // approval_request is deliberately a narrow product capability. It
        // cannot put a high-risk payment into observe/warn mode or stretch the
        // review window beyond the reference endpoint's one-hour bound.
        const requestedMode = body.enforcement_mode ?? body.mode ?? ENFORCEMENT_MODES.ENFORCE;
        if (requestedMode !== ENFORCEMENT_MODES.ENFORCE) {
          return epProblem(
            403,
            'cloud_approval_enforcement_required',
            'Cloud payment approvals must use enforce mode',
          );
        }
        if (body.expires_in_sec !== undefined
            && (!Number.isFinite(Number(body.expires_in_sec))
              || Number(body.expires_in_sec) < 60
              || Number(body.expires_in_sec) > 3600)) {
          return epProblem(
            400,
            'invalid_approval_expiry',
            'Cloud payment approval receipts must expire from 60 through 3600 seconds after issuance',
          );
        }
        body.enforcement_mode = ENFORCEMENT_MODES.ENFORCE;
        if (!SHA256_DIGEST_PATTERN.test(body.payment_destination_hash || '')) {
          return epProblem(
            400,
            'invalid_payment_destination_hash',
            'Cloud payment approvals require payment_destination_hash as sha256:<64 lowercase hex>',
          );
        }

        // CAID is derived by the server from the same typed material the
        // executor must later observe. A caller-supplied identifier is ignored:
        // CAID equality identifies content but never grants authority.
        const caidAction = {
          action_type: 'payment.release.1',
          amount: String(body.amount),
          currency: body.currency,
          beneficiary_account: body.payment_destination_hash,
          payment_instruction_id: body.target_resource_id,
          ...(typeof body.counterparty_name === 'string' && body.counterparty_name.trim()
            ? { memo: body.counterparty_name.trim() }
            : {}),
        };
        const caidResult = computeCaid(caidAction, {
          suite: 'jcs-sha256',
          definitions: [PAYMENT_RELEASE_CAID_DEFINITION],
        });
        if (!caidResult.caid || !caidResult.digest) {
          return epProblem(
            400,
            'invalid_caid_action',
            `Payment material cannot form payment.release.1 CAID (${(caidResult.refusals || []).join(', ')})`,
          );
        }
        body.action_caid = caidResult.caid;
        body.caid_digest = caidResult.digest;
        body.caid_action = caidAction;
      }
    }
    if (body.actor_id && body.actor_id !== actor_id) {
      return epProblem(
        403,
        'actor_id_mismatch',
        'actor_id in request body does not match authenticated entity',
      );
    }
    const changedFields = resolveGuardChangedFields(body, []);
    const inputError = validateGuardActionInput(body, { actionType: body.action_type, changedFields });
    if (inputError) return epProblem(inputError.status, inputError.code, inputError.detail);

    const supabase = getGuardedClient();

    // ── Org-pinned quorum template gate (policy authenticity) ─────────────
    // verifyQuorum proves a quorum is internally consistent against WHATEVER
    // policy it is handed; that policy has, until now, been creator-declared on
    // the receipt. Bind it to org intent: a submitted quorum_policy may EXCEED
    // the org's pinned template for this action_type but never fall below it
    // (lower threshold, longer window, disabled distinct-humans, out-of-roster
    // approver). Also honor a template that MANDATES quorum for the action.
    // See lib/guard-quorum-template.js + migration 124.
    const quorumTpl = await resolveOrgQuorumTemplate(supabase, {
      organizationId: body.organization_id,
      actionType: body.action_type,
    });
    if (quorumTpl.error) {
      // A real policy-store fault. Only the quorum path is high-stakes enough to
      // fail closed on — non-quorum creation is unaffected (a not-yet-migrated
      // table is surfaced as template:null, not error, so it does not block).
      if (body.quorum_policy) {
        return epProblem(
          503,
          'quorum_template_unavailable',
          'Could not verify the submitted quorum against the organization policy template; failing closed.',
        );
      }
    } else if (quorumTpl.template) {
      if (body.quorum_policy) {
        const cmp = evaluateQuorumAgainstTemplate(body.quorum_policy, quorumTpl.template);
        if (!cmp.ok) {
          return epProblem(
            422,
            'quorum_policy_below_template',
            `Submitted quorum_policy is weaker than the organization template (${cmp.violations.join(', ')})`,
          );
        }
      } else if (quorumTpl.template.quorum_required) {
        return epProblem(
          422,
          'quorum_required',
          'Organization policy requires a multi-party quorum for this action_type',
        );
      }
    } else if (body.quorum_policy && isQuorumTemplateRequired()) {
      // Hardened posture (EP_QUORUM_TEMPLATE_REQUIRED=true): refuse a quorum
      // receipt that has no org template to anchor its strength against.
      return epProblem(
        422,
        'quorum_template_missing',
        'Organization requires a pinned quorum template for quorum-gated actions, but none is configured for this action_type',
      );
    }

    const now = new Date();
    const receiptMaxTtlMs = body.action_type === GUARD_ACTION_TYPES.POLICY_ROLLOUT
      ? 15 * 60 * 1000
      : (isCloudGuardPrincipal(auth)
          && body.action_type === GUARD_ACTION_TYPES.LARGE_PAYMENT_RELEASE)
        ? 60 * 60 * 1000
        : RECEIPT_TTL_MS;
    const expiresAt = new Date(
      now.getTime() + resolveReceiptTtlMs(body.expires_in_sec, receiptMaxTtlMs),
    );
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

    // ── EP-AUTHORITY-REGISTRY-v1: resolve the INITIATOR's scoped authority ───
    // This replaces the fabricated stub authority (max_amount_usd:
    // MAX_SAFE_INTEGER, scope: the requested action) that used to short-circuit
    // every authority-side check. We resolve REAL authority from the registry —
    // role, scope, amount ceiling, validity, revocation, delegation, policy pin
    // — as of `now`, and bind the closed verdict into the receipt so an offline
    // verifier sees exactly which authority was relied on. Fail-closed: an
    // unreadable/absent registry yields `registry_unavailable`, never allow.
    // (The APPROVER's authority is resolved separately at consume time via
    // resolveGuardAuthority; mint binds the initiator leg of the same chain.)
    const authorityInput = {
      organization_id: body.organization_id,
      principal_id: actor_id,
      action_type: body.action_type,
      amount: typeof body.amount === 'number' ? body.amount : undefined,
      currency: body.currency || undefined,
      policy_hash: policyHash,
      issued_at: now.toISOString(),
    };
    const authorityResult = await resolveAuthority(supabaseAuthorityStore(supabase), authorityInput);
    const authorityBindingFields = authorityBinding(authorityResult);

    const canonicalActionBase = {
      organization_id: body.organization_id,
      actor_id,
      action_type: body.action_type,
      target_resource_id: body.target_resource_id,
      before_state_hash: beforeHash,
      after_state_hash: afterHash,
      policy_id: policyId,
      policy_hash: policyHash,
      // The six authority-binding fields are folded into the canonical action,
      // so they are covered by action_hash and, transitively, by every
      // approver signature over context_hash. They cannot be altered after the
      // fact to pretend a different authority decision was relied on.
      authority: authorityBindingFields,
      nonce,
      expires_at: expiresAt.toISOString(),
      requested_at: now.toISOString(),
      // CAID is computed above by the server for the connected payment
      // approval endpoint. Keep the typed action and digest inside the
      // canonical action so action_hash, every approver assertion, and the
      // exported evidence all bind the same cross-system identifier. These are
      // correlation fields, not a substitute for the execution-binding fields
      // that the executor must observe independently.
      ...(body.action_caid
        ? {
            action_caid: body.action_caid,
            caid_digest: body.caid_digest,
            caid_action: body.caid_action,
          }
        : {}),
    };
    const actionDetails = extractGuardActionDetails(body, changedFields);
    const canonicalAction = enrichCanonicalActionForExecution(canonicalActionBase, actionDetails);
    const actionHash = hashCanonicalAction(canonicalAction);

    // ── Policy evaluation ─────────────────────────────────────────────────
    // actor_role is caller-supplied policy context; authentication strength is
    // the server-derived credential projection and cannot be raised by the
    // request body.
    const baseDecision = evaluateGuardPolicy({
      organizationId: body.organization_id,
      actorId: actor_id,
      actorRole: body.actor_role || 'unknown',
      actionType: body.action_type,
      targetChangedFields: changedFields,
      amount: body.amount,
      currency: body.currency,
      riskFlags: body.risk_flags || [],
      authStrength,
      initiatorId: actor_id,
    });

    const mode = resolveGuardEnforcementMode(body, ENFORCEMENT_MODES.ENFORCE);
    if (!Object.values(ENFORCEMENT_MODES).includes(mode)) {
      return epProblem(400, 'invalid_enforcement_mode', `mode must be one of ${Object.values(ENFORCEMENT_MODES).join(', ')}`);
    }
    /** @type {{ decision: string, reasons: string[], signoffRequired: boolean, requiredAssurance?: string, signoffTier?: string, observed_decision?: string, aml_signals?: string[] }} */
    const decision = applyEnforcementMode(baseDecision, mode);

    // ── EP-AUTHORITY-REGISTRY-v1: staged enforcement (server-pinned) ─────────
    // The guard enforcement `mode` above is caller-selected and can downgrade a
    // block to observe. Authority enforcement runs on its OWN axis, resolved
    // from the environment and NEVER from the request body, so a caller cannot
    // opt out of it. An action is "critical" (fails closed once
    // enforce_critical is on) when the guard requires a named human (Class-A
    // assurance) or any signoff. Under 'shadow' (the default) nothing is
    // blocked — the verdict is bound + logged only.
    const authorityMode = authorityEnforcementMode();
    const isCriticalAction = decision.requiredAssurance === 'A' || decision.signoffRequired === true;
    const authorityEnforcement = applyAuthorityEnforcement({
      verdict: authorityResult.verdict,
      isCritical: isCriticalAction,
      mode: authorityMode,
    });
    if (authorityEnforcement.block) {
      // Fail closed: record the refusal as evidence, then refuse. An unresolved
      // or insufficient authority is NOT "unknown but allow."
      try {
        await supabase.from('audit_events').insert({
          event_type: 'guard.authority.denied',
          actor_id,
          actor_type: 'system',
          target_type: 'trust_receipt',
          target_id: receiptId,
          action: 'authority_deny',
          before_state: null,
          after_state: {
            organization_id: body.organization_id,
            action_type: body.action_type,
            authority_verdict: authorityResult.verdict,
            authority_detail: authorityResult.detail,
            authority_code: authorityEnforcement.code,
            authority_mode: authorityMode,
            authority_result_hash: authorityBindingFields.authority_result_hash,
            authority_registry_head: authorityBindingFields.authority_registry_head,
            authority_registry_epoch: authorityBindingFields.authority_registry_epoch,
            policy_hash: policyHash,
            is_critical: isCriticalAction,
          },
        });
      } catch (e) {
        logger.warn('[authority] denial audit insert failed:', e?.message);
      }
      return epProblem(
        403,
        `not_admissible:${authorityEnforcement.code}`,
        `Authority not admissible for this action (${authorityResult.verdict}); ${authorityMode} enforcement fails closed for critical actions.`,
      );
    }

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

    let evidenceStatus = 'durable';
    try {
      const { error: auditError } = await supabase.from('audit_events').insert({
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
          reasons: decision.reasons,
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
          // EP-AUTHORITY-REGISTRY-v1: the resolved authority verdict + binding.
          authority_verdict: authorityResult.verdict,
          authority_detail: authorityResult.detail,
          authority_binding: authorityBindingFields,
          authority_enforcement: {
            mode: authorityMode,
            admissibility: authorityEnforcement.admissibility,
            code: authorityEnforcement.code,
            is_critical: isCriticalAction,
          },
          // Display-material parameters for the approval surface.
          amount: typeof body.amount === 'number' ? body.amount : null,
          currency: body.currency || null,
          risk_flags: body.risk_flags || [],
          target_resource_id: body.target_resource_id,
        },
      });
      if (auditError) throw auditError;
    } catch (e) {
      evidenceStatus = 'degraded';
      logger.warn('[guard] audit_events insert failed:', e?.message);
      if (mode === ENFORCEMENT_MODES.ENFORCE || body.strict_evidence === true) {
        return epProblem(
          503,
          'evidence_write_failed',
          'Could not durably record the GovGuard evidence event; enforce/strict-evidence mode fails closed.',
        );
      }
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
    // AUTHORITY is now REAL (EP-AUTHORITY-REGISTRY-v1). The former stub
    // authority (max_amount_usd: MAX_SAFE_INTEGER, scope: the requested
    // action) that short-circuited AMOUNT_EXCEEDS_AUTHORITY /
    // AUTHORITY_REVOKED / AUTHORITY_EXPIRED / ACTION_OUTSIDE_AUTHORITY_SCOPE
    // is gone: the block below feeds the rules engine the SAME resolved
    // authority the live authority layer bound into the receipt, so the
    // shadow diff finally covers the authority-side hard-deny rules too.
    //
    //  NOTE — ARBITRARY RISK WEIGHTS. §4.9's risk-score weights (15, 15,
    //  10, 15, 20, 25, 10, 20, 30) and thresholds (≥80, ≥50, ≥30) are
    //  heuristics from an external doc, not data-calibrated. Real
    //  fraud-detection thresholds need labeled outcomes. Pitch this as
    //  "pre-calibration scaffold," not "production fraud engine."
    if (isRulesEngineV0Enabled()) {
      try {
        /** @type {Parameters<typeof evaluateRulesEngineV0>[0]} */
        const rulesEngineInput = {
          tenant_id: body.organization_id,
          environment: mode === ENFORCEMENT_MODES.ENFORCE ? 'enforce' : 'shadow',
          workflow: body.action_type,
          actor: {
            actor_id,
            role: body.actor_role || 'unknown',
            department: body.actor_department,
            // FAIL-SAFE (weakest credible values). A bearer API key is a
            // long-lived shared secret; it does NOT establish MFA or a
            // user-verification (UV) signal. There is no WebAuthn assertion on
            // the mint request today (authenticateRequest resolves a bearer key
            // via resolve_authenticated_actor and returns { entity, permissions }
            // with no assurance/UV field), so we MUST NOT claim MFA-strong here.
            // The previous 'high' / mfa_verified:true was a fail-OPEN default:
            // if this shadow engine is ever promoted to enforce, treating every
            // bearer request as MFA-verified would let a bare bearer token clear
            // the §4.5 MFA/assurance hard-deny gate. Mirror the same fail-safe
            // the live evaluator uses at authStrength (line ~219): weakest
            // credible tier. The rules engine will hard-deny (MFA_REQUIRED) a
            // bearer-only request — which is the HONEST shadow result until a
            // verified UV signal is threaded through (see wiring note below).
            //
            // WIRING NEEDED to safely raise this above the floor: a genuine
            // WebAuthn user-verification signal (UV flag from a Class-A device
            // key / passkey assertion) must be surfaced on the authenticated
            // request. That signal exists at signoff/consume time, NOT at mint
            // time, so authenticateRequest would need to accept and verify a
            // fresh UV-bearing assertion on the mint call before assurance_level
            // 'high' / mfa_verified:true could be asserted. Never trust a
            // body-supplied assurance/mfa value (the caller/agent controls it).
            assurance_level: 'low',
            mfa_verified: false,
          },
          action: {
            action_id: receiptId,
            action_type: body.action_type,
            amount_usd: typeof body.amount === 'number' ? body.amount : undefined,
          },
          // REAL authority (EP-AUTHORITY-REGISTRY-v1) — the exact grant the
          // live authority layer resolved and bound into this receipt. A
          // missing/insufficient authority now flows through to the rules
          // engine's authority hard-deny rules instead of being fabricated
          // away. A null authority_id means the registry had no grant for the
          // initiator, which the engine correctly reads as AUTHORITY_MISSING.
          authority: {
            authority_id: authorityResult.authority_id || undefined,
            scope: Array.isArray(authorityResult.scope) ? authorityResult.scope : undefined,
            max_amount_usd: typeof authorityResult.max_amount_usd === 'number' ? authorityResult.max_amount_usd : undefined,
            revoked: authorityResult.verdict === 'revoked_authority',
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
        required_assurance: decision.requiredAssurance ?? null,
        signoff_request_id: null, // populated when /signoffs/request is called
        risk_flags: body.risk_flags || [],
        receipt_status,
        enforcement_mode: mode,
        evidence_status: evidenceStatus,
        // EP-AUTHORITY-REGISTRY-v1: the scoped-authority verdict bound into the
        // receipt, and how the staged rollout treated it (observed vs enforced).
        authority: {
          ...authorityBindingFields,
          detail: authorityResult.detail,
          admissibility: authorityEnforcement.admissibility,
          enforcement_mode: authorityMode,
          is_critical: isCriticalAction,
        },
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
