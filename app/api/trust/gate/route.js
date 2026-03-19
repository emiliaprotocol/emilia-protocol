// SPDX-License-Identifier: Apache-2.0
// EMILIA Protocol — POST /api/trust/gate
// Trust gate: pre-action check. Returns allow/block before executing a high-stakes action.

import { NextResponse } from 'next/server';
import { verifyDelegation } from '@/lib/delegation';
import { canonicalEvaluate } from '@/lib/canonical-evaluator';
import { EP_ERRORS } from '@/lib/errors';
import { buildTrustDecision } from '@/lib/trust-decision';

const GATE_POLICIES = {
  strict:     { min_ee: 40,  max_dispute_rate: 0.02, require_established: true },
  standard:   { min_ee: 15,  max_dispute_rate: 0.05, require_established: false },
  permissive: { min_ee: 5,   max_dispute_rate: 0.15, require_established: false },
};

export async function POST(request) {
  try {
    const body = await request.json().catch(() => ({}));
    const { entity_id, action, policy = 'standard', value_usd, delegation_id } = body;

    if (!entity_id || !action) {
      return EP_ERRORS.BAD_REQUEST('entity_id and action are required');
    }

    // Fetch entity trust data via canonical evaluator
    const result = await canonicalEvaluate(entity_id, {
      includeDisputes: true,
      includeEstablishment: true,
    });

    if (result.error) {
      return NextResponse.json(buildTrustDecision({
        decision: 'block',
        entityId: entity_id,
        policyUsed: policy,
        confidence: 'unknown',
        reasons: ['Entity not found in EP registry'],
        warnings: [],
        appealPath: 'https://emiliaprotocol.ai/appeal',
        extensions: {
          action,
        },
      }));
    }

    const policyConfig = GATE_POLICIES[policy] || GATE_POLICIES.standard;
    const reasons = [];
    const warnings = [];
    const ee = result.effectiveEvidence || 0;
    const conf = result.confidence || 'pending';
    const disputeRate = result.profile?.behavioral?.dispute_rate ?? 0;

    // Evaluate gate conditions
    if (ee < policyConfig.min_ee) {
      reasons.push(`Insufficient evidence: ${ee.toFixed(1)} (required: ${policyConfig.min_ee})`);
    }

    if (policyConfig.require_established && !result.establishment?.established) {
      reasons.push('Entity has not established long-term trust history');
    }

    if (disputeRate / 100 > policyConfig.max_dispute_rate) {
      reasons.push(`Dispute rate ${disputeRate}% exceeds policy max ${policyConfig.max_dispute_rate * 100}%`);
    }

    // Scale policy strictness with transaction value
    if (value_usd && value_usd > 10000 && policy !== 'strict') {
      if (ee < GATE_POLICIES.strict.min_ee) {
        reasons.push(`High-value transaction ($${value_usd}) requires strict policy threshold`);
      }
    }

    // Verify delegation if provided
    let delegationVerified = null;
    if (delegation_id) {
      try {
        const dlg = await verifyDelegation(delegation_id, action);
        delegationVerified = dlg.valid && (dlg.action_permitted !== false);
        if (!delegationVerified) {
          reasons.push(dlg.reason || 'Delegation is invalid or action not in scope');
        }
      } catch {
        delegationVerified = false;
        reasons.push('Could not verify delegation');
      }
    }

    const decision = reasons.length === 0 ? 'allow' : 'block';

    const extensions = {
      action,
      display_name: result.display_name,
    };

    if (delegation_id) extensions.delegation_verified = delegationVerified;

    if (value_usd) extensions.value_threshold = {
      value_usd,
      escalated_to_strict: value_usd > 10000 && policy !== 'strict',
    };

    if (decision === 'block') {
      extensions._note = 'Trust must never be more powerful than appeal.';
    }

    return NextResponse.json(buildTrustDecision({
      decision,
      entityId: result.entity_id,
      policyUsed: policy,
      confidence: conf,
      reasons,
      warnings,
      appealPath: 'https://emiliaprotocol.ai/appeal',
      contextUsed: null,
      profileSummary: {
        confidence: conf,
        evidence_level: ee,
        dispute_rate: disputeRate,
      },
      extensions,
    }));
  } catch (err) {
    console.error('[trust/gate] error:', err);
    return EP_ERRORS.INTERNAL();
  }
}
