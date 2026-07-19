// SPDX-License-Identifier: Apache-2.0
// EP GovGuard + FinGuard — shared adapter precheck handler.
//
// Every demo adapter (`/api/v1/adapters/{gov,fin}/*/precheck`) does the
// same thing: take a domain-specific request body, build a canonical
// action object, run the policy engine, and emit an audit event. The
// adapter-specific bits are:
//   - the action_type
//   - the default policy_id
//   - which body fields name the target_resource_id
//   - the default target_changed_fields used when the request omits them
//
// Everything else (auth, hashing, mode application, audit emission,
// response shape) is identical. This module factors out the identical
// path so each route file is a thin spec object.

import { NextResponse } from 'next/server';
import crypto from 'node:crypto';
import { authenticateRequest, authEntityId } from './supabase.js';
import { resolveVerifiedAuthStrength } from './auth-strength.js';
import { resolveAuthorizedOrg } from './tenant-binding.js';
import { getGuardedClient } from './write-guard.js';
import { epProblem } from './errors.js';
import { logger } from './logger.js';
import {
  evaluateGuardPolicy,
  applyEnforcementMode,
  buildInitiatorAttestation,
  hashCanonicalAction,
  computeGuardPolicyHash,
  GUARD_DECISIONS,
  ENFORCEMENT_MODES,
} from './guard-policies.js';
import { readLimitedJson } from './http/body-limit.js';
import {
  buildExecutionBindingContract,
  enrichCanonicalActionForExecution,
} from './execution/binding-contract.js';
import {
  extractGuardActionDetails,
  resolveGuardChangedFields,
  resolveGuardEnforcementMode,
  validateGuardActionInput,
} from './guard-action-inputs.js';

const RECEIPT_TTL_MS = 24 * 60 * 60 * 1000;
const MAX_GUARD_PRECHECK_BYTES = 256 * 1024;

/**
 * Run a domain-specific precheck adapter.
 *
 * @param {Request} request
 * @param {object} spec
 * @param {string}   spec.adapterName             — short slug for audit, e.g. 'gov.benefit-bank-change'
 * @param {typeof import('./guard-policies.js').GUARD_ACTION_TYPES[keyof typeof import('./guard-policies.js').GUARD_ACTION_TYPES]}   spec.actionType              — GUARD_ACTION_TYPES.* value
 * @param {string}   spec.policyId                — default policy_id when body omits one
 * @param {string}   spec.targetResourceField     — body field that names target_resource_id
 * @param {string[]} [spec.defaultChangedFields]  - used when body.target_changed_fields omitted
 * @param {string}   [spec.actorRole]             - default actor role when body omits
 */
export async function runGuardPrecheck(request, spec) {
  try {
    const auth = await authenticateRequest(request);
    if (auth.error) return epProblem(401, 'unauthorized', auth.error);
    // auth.entity is the resolved entity object; actor_id must be the string
    // entity_id (same unwrap as /api/receipt + the v1 routes, 7c5cfcf).
    const actorId = authEntityId(auth);
    const authStrength = resolveVerifiedAuthStrength(auth);

    const parsed = await readLimitedJson(request, MAX_GUARD_PRECHECK_BYTES, /** @type {any} */ ({ invalidValue: {} }));
    if (!parsed.ok) return epProblem(parsed.status, parsed.code, parsed.detail);
    const body = parsed.value;

    // ── Tenant binding: derive org from the AUTHENTICATED entity, not the body.
    // Prevents an authenticated caller from scoping receipts to another org by
    // passing organization_id. (See lib/tenant-binding.js + migration 101.)
    const orgResolution = resolveAuthorizedOrg(auth, body.organization_id, { requireBound: true });
    if (orgResolution.error) {
      return epProblem(orgResolution.error.status, orgResolution.error.code, orgResolution.error.detail);
    }
    // Normalize so every downstream read of body.organization_id (canonical
    // action, policy eval, audit write, AML tenant_id queries) uses the authorized org.
    body.organization_id = orgResolution.organizationId;

    const targetResourceId = body[spec.targetResourceField];
    if (!targetResourceId) {
      return epProblem(400, `missing_${spec.targetResourceField}`, `${spec.targetResourceField} is required`);
    }
    if (!body.before_state || !body.after_state) {
      return epProblem(400, 'missing_state', 'before_state and after_state are required');
    }
    const changedFields = resolveGuardChangedFields(body, spec.defaultChangedFields || []);
    const inputError = validateGuardActionInput(body, { actionType: spec.actionType, changedFields });
    if (inputError) return epProblem(inputError.status, inputError.code, inputError.detail);

    const now = new Date();
    const expiresAt = new Date(now.getTime() + RECEIPT_TTL_MS);
    const nonce = `nonce_${crypto.randomBytes(12).toString('hex')}`;
    const receiptId = `tr_${crypto.randomBytes(16).toString('hex')}`;

    const beforeHash = hashCanonicalAction(body.before_state);
    const afterHash = hashCanonicalAction(body.after_state);
    const policyId = body.policy_id || spec.policyId;
    const policyHash = computeGuardPolicyHash(policyId); // #4: binds full rule content

    // Optional NATIVE consent-grant binding. When the caller mints this action
    // under a standing EP-CONSENT-GRANT-v1, grant_hash goes INSIDE the canonical
    // Action Object, so it is covered by the action hash and therefore by the
    // human signature over the action — not a side field an intermediary can
    // rewrite. Backwards-compatible: absent grant_hash, the signed bytes are
    // byte-for-byte what they were before. Fail-closed on shape: a malformed
    // grant_hash is REFUSED here rather than folded into signed material where a
    // downstream verifier would silently reject it (see
    // packages/verify/consent-grant.js receiptReferencedGrantHash, which prefers
    // this signed field over any caller override). Verifying that grant_hash
    // actually matches a presented grant is verifyReceiptUnderGrant's job.
    let grantHash;
    if (body.grant_hash !== undefined) {
      if (typeof body.grant_hash !== 'string' || !/^sha256:[0-9a-f]{64}$/.test(body.grant_hash)) {
        return epProblem(400, 'invalid_grant_hash', 'grant_hash must be a "sha256:<64-hex>" string');
      }
      grantHash = body.grant_hash;
    }

    const canonicalActionBase = {
      organization_id: body.organization_id,
      actor_id: actorId,
      action_type: spec.actionType,
      target_resource_id: targetResourceId,
      before_state_hash: beforeHash,
      after_state_hash: afterHash,
      policy_id: policyId,
      policy_hash: policyHash,
      // grant_hash is included ONLY when supplied, so an action minted without a
      // standing grant canonicalizes and hashes exactly as before (optional +
      // backwards-compatible). When present it is part of the signed Action Object.
      ...(grantHash !== undefined ? { grant_hash: grantHash } : {}),
      nonce,
      expires_at: expiresAt.toISOString(),
      requested_at: now.toISOString(),
    };
    const actionDetails = extractGuardActionDetails(body, changedFields);
    const canonicalAction = enrichCanonicalActionForExecution(canonicalActionBase, actionDetails);
    const actionHash = hashCanonicalAction(canonicalAction);

    // actor_role + spec.actorRole are advisory policy context, not verified
    // authentication claims. Authentication strength comes only from the
    // server-derived auth projection; an unlabeled credential remains
    // password strength and therefore escalates rather than being treated as
    // MFA by accident.
    const mode = resolveGuardEnforcementMode(body, ENFORCEMENT_MODES.ENFORCE);
    if (!Object.values(ENFORCEMENT_MODES).includes(mode)) {
      return epProblem(400, 'invalid_enforcement_mode', `mode must be one of ${Object.values(ENFORCEMENT_MODES).join(', ')}`);
    }

    // AML identity and amount are derived from the canonical action fields,
    // never an alternate caller-supplied `aml` object. Caller history can add
    // context but cannot replace EP's own tenant-scoped history window.
    const supabase = getGuardedClient();
    let aml;
    let amlHistoryStatus = 'durable';
    try {
      aml = await resolveAmlContext(supabase, body);
    } catch (e) {
      logger.warn('[guard-adapter] aml_history lookup failed:', e?.message);
      if (mode === ENFORCEMENT_MODES.ENFORCE || body.strict_evidence === true) {
        return epProblem(
          503,
          'aml_history_unavailable',
          'Authoritative AML history is unavailable; enforce/strict-evidence mode fails closed.',
        );
      }
      aml = buildAmlContext(body);
      amlHistoryStatus = 'degraded';
    }

    const baseDecision = evaluateGuardPolicy({
      organizationId: body.organization_id,
      actorId,
      actorRole: body.actor_role || spec.actorRole || 'unknown',
      actionType: spec.actionType,
      targetChangedFields: changedFields,
      amount: body.amount,
      currency: body.currency,
      riskFlags: body.risk_flags || [],
      authStrength,
      aml,
    });

    /**
     * @type {{
     *   decision: string,
     *   reasons: string[],
     *   signoffRequired: boolean,
     *   observed_decision?: string,
     *   signoffTier?: string,
     *   requiredAssurance?: unknown,
     *   aml_signals?: unknown,
     * }}
     */
    const decision = applyEnforcementMode(baseDecision, mode);
    const executionBinding = buildExecutionBindingContract(/** @type {any} */ ({
      canonicalAction,
      actionDetails,
      decision,
    }));

    let receipt_status = 'issued';
    if (decision.signoffRequired && decision.decision === GUARD_DECISIONS.ALLOW_WITH_SIGNOFF) {
      receipt_status = 'pending_signoff';
    } else if (decision.decision === GUARD_DECISIONS.DENY) {
      receipt_status = 'denied';
    }

    // PIP-007: when this escalates to signoff, mint the initiator escalation
    // attestation from the deterministic decision the engine produced. Built
    // from the BASE decision so observe mode (which downgrades the surfaced
    // decision to OBSERVE but preserves signoffRequired) still records what the
    // initiator would attest. A caller minting §6.2 contexts passes this through
    // to the issuer's `initiatorAttestation`; it is undefined on non-escalation.
    const initiator_attestation = buildInitiatorAttestation(baseDecision, {
      actionType: spec.actionType,
      policyId,
      targetChangedFields: changedFields,
    });

    // Record this transfer into the per-counterparty history so FUTURE
    // prechecks see it (structuring/velocity build from EP's own record).
    const amlHistoryRecorded = await recordAmlHistory(supabase, body, spec, receiptId, aml);
    if (!amlHistoryRecorded) {
      amlHistoryStatus = 'degraded';
      if (mode === ENFORCEMENT_MODES.ENFORCE || body.strict_evidence === true) {
        return epProblem(
          503,
          'aml_history_write_failed',
          'Could not durably record AML history; enforce/strict-evidence mode fails closed.',
        );
      }
    }

    let evidenceStatus = amlHistoryStatus === 'degraded' ? 'degraded' : 'durable';
    try {
      const { error: auditError } = await supabase.from('audit_events').insert({
        event_type: 'guard.trust_receipt.created',
        actor_id: actorId,
        actor_type: 'principal',
        target_type: 'trust_receipt',
        target_id: receiptId,
        action: 'create',
        before_state: null,
        after_state: {
          organization_id: body.organization_id,
          action_type: spec.actionType,
          policy_id: policyId,
          policy_hash: policyHash,
          decision: decision.decision,
          reasons: decision.reasons,
          observed_decision: decision.observed_decision || null,
          enforcement_mode: mode,
          signoff_required: decision.signoffRequired,
          signoff_tier: decision.signoffTier || null,
          required_assurance: decision.requiredAssurance ?? null,
          aml_signals: decision.aml_signals || null,
          initiator_attestation: initiator_attestation || null,
          receipt_status,
          action_hash: actionHash,
          canonical_action: canonicalAction,
          execution_binding: executionBinding,
          before_state_hash: beforeHash,
          after_state_hash: afterHash,
          expires_at: expiresAt.toISOString(),
          adapter: `${spec.adapterName}.precheck`,
          target_resource_id: targetResourceId,
          amount: body.amount ?? null,
          currency: body.currency ?? null,
        },
      });
      if (auditError) throw auditError;
    } catch (e) {
      evidenceStatus = 'degraded';
      logger.warn(`[adapter:${spec.adapterName}] audit_events insert failed:`, e?.message);
      if (mode === ENFORCEMENT_MODES.ENFORCE || body.strict_evidence === true) {
        return epProblem(
          503,
          'evidence_write_failed',
          'Could not durably record the GovGuard evidence event; enforce/strict-evidence mode fails closed.',
        );
      }
    }

    return NextResponse.json({
      receipt_id: receiptId,
      decision: decision.decision,
      observed_decision: decision.observed_decision || null,
      action_hash: actionHash,
      canonical_action: canonicalAction,
      execution_binding: executionBinding,
      nonce,
      expires_at: expiresAt.toISOString(),
      signoff_required: decision.signoffRequired,
      signoff_tier: decision.signoffTier || null,
      required_assurance: decision.requiredAssurance ?? null,
      aml_signals: decision.aml_signals || null,
      initiator_attestation: initiator_attestation || null,
      receipt_status,
      evidence_status: evidenceStatus,
      aml_history_status: amlHistoryStatus,
      reasons: decision.reasons,
      next_step: receipt_status === 'pending_signoff'
        ? 'POST /api/v1/signoffs/request with this receipt_id'
        : receipt_status === 'denied'
        ? 'Action denied. See reasons.'
        : 'POST /api/v1/trust-receipts/{receipt_id}/consume with action_hash to complete the change.',
    }, { status: 201 });
  } catch (err) {
    logger.error(`[adapter:${spec.adapterName}] precheck error:`, err);
    return epProblem(500, 'internal_error', 'Adapter precheck failed');
  }
}

// Assemble an AML context from common request fields. Returns undefined (a
// no-op in the policy engine) when no AML field is present, so non-financial
// callers are unaffected.
function buildAmlContext(body) {
  const counterpartyName = body.counterparty_name || body.beneficiary_name || body.payee_name;
  const counterpartyCountry = body.counterparty_country || body.beneficiary_country;
  const recentAmounts = Array.isArray(body.recent_amounts) ? body.recent_amounts : undefined;
  if (!counterpartyName && !counterpartyCountry && recentAmounts === undefined) {
    return undefined;
  }
  return {
    counterpartyName,
    counterpartyCountry,
    amount: typeof body.amount === 'number' ? body.amount : undefined,
    recentAmounts,
  };
}

// History key: case/whitespace-insensitive. (Sanctions matching does deeper
// normalization; for the window key this is deliberate-collision-friendly.)
function amlCounterpartyKey(name) {
  return String(name).toLowerCase().trim();
}

const AML_WINDOW_DAYS = 30;
const AML_WINDOW_LIMIT = 20;

// Resolve AML context against EP's tenant-scoped history on every monetary
// counterparty check. Caller-supplied history is supplemental only; it cannot
// erase records already known to EP. Datastore failure is surfaced to the
// caller so enforcement mode can fail closed.
async function resolveAmlContext(supabase, body) {
  const ctx = buildAmlContext(body);
  if (!ctx) return undefined;
  if (!ctx.counterpartyName || typeof ctx.amount !== 'number') {
    return ctx;
  }
  const since = new Date(Date.now() - AML_WINDOW_DAYS * 24 * 60 * 60 * 1000).toISOString();
  const { data, error } = await supabase
    .from('aml_history')
    .select('amount')
    .eq('tenant_id', body.organization_id)
    .eq('counterparty', amlCounterpartyKey(ctx.counterpartyName))
    .gte('occurred_at', since)
    .order('occurred_at', { ascending: false })
    .limit(AML_WINDOW_LIMIT);
  if (error) throw error;
  const authoritative = (data || []).map((r) => Number(r.amount)).filter(Number.isFinite);
  return { ...ctx, recentAmounts: [...authoritative, ...(ctx.recentAmounts || [])] };
}

// Append this transfer to the per-counterparty history. Return durability so
// enforce mode can refuse instead of silently weakening future AML decisions.
async function recordAmlHistory(supabase, body, spec, receiptId, aml) {
  if (!aml?.counterpartyName || typeof aml.amount !== 'number') return true;
  try {
    const { error } = await supabase.from('aml_history').insert({
      tenant_id: body.organization_id,
      counterparty: amlCounterpartyKey(aml.counterpartyName),
      amount: aml.amount,
      currency: body.currency || null,
      action_type: spec.actionType,
      receipt_id: receiptId,
    });
    if (error) throw error;
    return true;
  } catch (e) {
    logger.warn('[guard-adapter] aml_history insert failed:', e?.message);
    return false;
  }
}
