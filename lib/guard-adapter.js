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
import { authenticateRequest } from './supabase.js';
import { getGuardedClient } from './write-guard.js';
import { epProblem } from './errors.js';
import { logger } from './logger.js';
import {
  evaluateGuardPolicy,
  applyEnforcementMode,
  hashCanonicalAction,
  GUARD_DECISIONS,
  ENFORCEMENT_MODES,
} from './guard-policies.js';

const RECEIPT_TTL_MS = 24 * 60 * 60 * 1000;

/**
 * Run a domain-specific precheck adapter.
 *
 * @param {Request} request
 * @param {object} spec
 * @param {string}   spec.adapterName             — short slug for audit, e.g. 'gov.benefit-bank-change'
 * @param {string}   spec.actionType              — GUARD_ACTION_TYPES.* value
 * @param {string}   spec.policyId                — default policy_id when body omits one
 * @param {string}   spec.targetResourceField     — body field that names target_resource_id
 * @param {string[]} [spec.defaultChangedFields]  — used when body.target_changed_fields omitted
 * @param {string}   [spec.actorRole]             — default actor role when body omits
 */
export async function runGuardPrecheck(request, spec) {
  try {
    const auth = await authenticateRequest(request);
    if (auth.error) return epProblem(401, 'unauthorized', auth.error);

    const body = await request.json().catch(() => ({}));

    if (!body.organization_id) {
      return epProblem(400, 'missing_organization_id', 'organization_id is required');
    }
    const targetResourceId = body[spec.targetResourceField];
    if (!targetResourceId) {
      return epProblem(400, `missing_${spec.targetResourceField}`, `${spec.targetResourceField} is required`);
    }
    if (!body.before_state || !body.after_state) {
      return epProblem(400, 'missing_state', 'before_state and after_state are required');
    }

    const now = new Date();
    const expiresAt = new Date(now.getTime() + RECEIPT_TTL_MS);
    const nonce = `nonce_${crypto.randomBytes(12).toString('hex')}`;
    const receiptId = `tr_${crypto.randomBytes(16).toString('hex')}`;

    const beforeHash = hashCanonicalAction(body.before_state);
    const afterHash = hashCanonicalAction(body.after_state);
    const policyId = body.policy_id || spec.policyId;
    const policyHash = hashCanonicalAction({ policy_id: policyId, version: 1 });

    const canonicalAction = {
      organization_id: body.organization_id,
      actor_id: auth.entity,
      action_type: spec.actionType,
      target_resource_id: targetResourceId,
      before_state_hash: beforeHash,
      after_state_hash: afterHash,
      policy_id: policyId,
      policy_hash: policyHash,
      nonce,
      expires_at: expiresAt.toISOString(),
      requested_at: now.toISOString(),
    };
    const actionHash = hashCanonicalAction(canonicalAction);

    const baseDecision = evaluateGuardPolicy({
      organizationId: body.organization_id,
      actorId: auth.entity,
      actorRole: auth.actorRole || body.actor_role || spec.actorRole || 'unknown',
      actionType: spec.actionType,
      targetChangedFields: body.target_changed_fields || spec.defaultChangedFields || [],
      amount: body.amount,
      currency: body.currency,
      riskFlags: body.risk_flags || [],
      authStrength: auth.authStrength || 'mfa',
    });

    const mode = body.enforcement_mode || ENFORCEMENT_MODES.ENFORCE;
    if (!Object.values(ENFORCEMENT_MODES).includes(mode)) {
      return epProblem(400, 'invalid_enforcement_mode', `mode must be one of ${Object.values(ENFORCEMENT_MODES).join(', ')}`);
    }
    const decision = applyEnforcementMode(baseDecision, mode);

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
        actor_id: auth.entity,
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
          enforcement_mode: mode,
          signoff_required: decision.signoffRequired,
          receipt_status,
          action_hash: actionHash,
          before_state_hash: beforeHash,
          after_state_hash: afterHash,
          expires_at: expiresAt.toISOString(),
          adapter: `${spec.adapterName}.precheck`,
          target_resource_id: targetResourceId,
          amount: body.amount ?? null,
          currency: body.currency ?? null,
        },
      });
    } catch (e) {
      logger.warn(`[adapter:${spec.adapterName}] audit_events insert failed:`, e?.message);
    }

    return NextResponse.json({
      receipt_id: receiptId,
      decision: decision.decision,
      observed_decision: decision.observed_decision || null,
      action_hash: actionHash,
      nonce,
      expires_at: expiresAt.toISOString(),
      signoff_required: decision.signoffRequired,
      receipt_status,
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
