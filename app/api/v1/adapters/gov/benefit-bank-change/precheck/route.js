// SPDX-License-Identifier: Apache-2.0
// EP GovGuard demo adapter — POST /api/v1/adapters/gov/benefit-bank-change/precheck
//
// Thin façade over POST /api/v1/trust-receipts that pre-fills the
// action_type + target_changed_fields for a benefit-bank-account-change
// scenario. Pilots can wire their benefits-core system to this URL with
// minimal custom code; the adapter handles canonical action shape.
//
// This is a DEMO adapter. Production deployments should call
// /api/v1/trust-receipts directly with a domain-specific canonical action
// — that gives the operator full control over the action_hash binding.

import { NextResponse } from 'next/server';
import { authenticateRequest } from '@/lib/supabase';
import { epProblem } from '@/lib/errors';
import { logger } from '@/lib/logger.js';
import {
  evaluateGuardPolicy,
  applyEnforcementMode,
  hashCanonicalAction,
  GUARD_DECISIONS,
  GUARD_ACTION_TYPES,
  ENFORCEMENT_MODES,
} from '@/lib/guard-policies.js';
import { getGuardedClient } from '@/lib/write-guard';
import crypto from 'node:crypto';

const RECEIPT_TTL_MS = 24 * 60 * 60 * 1000;

export async function POST(request) {
  try {
    const auth = await authenticateRequest(request);
    if (auth.error) return epProblem(401, 'unauthorized', auth.error);

    const body = await request.json().catch(() => ({}));

    if (!body.organization_id) {
      return epProblem(400, 'missing_organization_id', 'organization_id is required');
    }
    if (!body.recipient_id) {
      return epProblem(400, 'missing_recipient_id', 'recipient_id is required');
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
    const policyId = body.policy_id || 'policy_gov_benefit_bank_change_v1';
    const policyHash = hashCanonicalAction({ policy_id: policyId, version: 1 });

    const canonicalAction = {
      organization_id: body.organization_id,
      actor_id: auth.entity,
      action_type: GUARD_ACTION_TYPES.BENEFIT_BANK_ACCOUNT_CHANGE,
      target_resource_id: body.recipient_id,
      before_state_hash: beforeHash,
      after_state_hash: afterHash,
      policy_id: policyId,
      policy_hash: policyHash,
      nonce,
      expires_at: expiresAt.toISOString(),
      requested_at: now.toISOString(),
    };
    const actionHash = hashCanonicalAction(canonicalAction);

    // The adapter assumes any benefit-bank-change touches money destination
    // (it's the whole point of the action). Evaluate as such — callers can
    // override target_changed_fields to test different policy paths.
    const baseDecision = evaluateGuardPolicy({
      organizationId: body.organization_id,
      actorId: auth.entity,
      actorRole: auth.actorRole || 'caseworker',
      actionType: GUARD_ACTION_TYPES.BENEFIT_BANK_ACCOUNT_CHANGE,
      targetChangedFields: body.target_changed_fields || ['bank_account', 'routing_number'],
      riskFlags: body.risk_flags || [],
      authStrength: auth.authStrength || 'mfa',
    });

    const mode = body.enforcement_mode || ENFORCEMENT_MODES.ENFORCE;
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
          action_type: canonicalAction.action_type,
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
          adapter: 'gov.benefit-bank-change.precheck',
          recipient_id: body.recipient_id,
        },
      });
    } catch (e) {
      logger.warn('[adapter] audit_events insert failed:', e?.message);
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
    logger.error('[adapter] gov benefit-bank-change precheck error:', err);
    return epProblem(500, 'internal_error', 'Adapter precheck failed');
  }
}
