// SPDX-License-Identifier: Apache-2.0
// EMILIA Protocol — POST /api/trust/gate
// Trust gate: pre-action check. Returns allow/review/deny before executing a high-stakes action.

import { NextResponse } from 'next/server';
import { verifyDelegation } from '@/lib/delegation';
import { canonicalEvaluate } from '@/lib/canonical-evaluator';
import { EP_ERRORS } from '@/lib/errors';
import { buildTrustDecision } from '@/lib/trust-decision';
import { authenticateRequest } from '@/lib/supabase';
import { getGuardedClient } from '@/lib/write-guard';
import { protocolWrite, COMMAND_TYPES } from '@/lib/protocol-write';
import { sha256 } from '@/lib/handshake/invariants';

const GATE_POLICIES = {
  strict:     { min_ee: 40,  max_dispute_rate: 0.02, require_established: true },
  standard:   { min_ee: 15,  max_dispute_rate: 0.05, require_established: false },
  permissive: { min_ee: 5,   max_dispute_rate: 0.15, require_established: false },
};

export async function POST(request) {
  try {
    const body = await request.json().catch(() => ({}));

    const auth = await authenticateRequest(request);
    if (auth.error) return EP_ERRORS.UNAUTHORIZED();

    const { entity_id, action, policy = 'standard', value_usd, delegation_id, handshake_id, resource_ref, intent_ref } = body;

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
        decision: 'deny',
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

    // Verify handshake if provided
    let handshakeVerified = null;
    if (body.handshake_id) {
      try {
        const hsReadClient = getGuardedClient();
        const { data: hs } = await hsReadClient
          .from('handshakes')
          .select('handshake_id, status, action_type, resource_ref, action_hash, policy_hash')
          .eq('handshake_id', body.handshake_id)
          .maybeSingle();

        if (!hs) {
          reasons.push('Handshake not found');
          handshakeVerified = false;
        } else if (hs.status !== 'verified') {
          reasons.push(`Handshake status is '${hs.status}', expected 'verified'`);
          handshakeVerified = false;
        } else {
          // Verify action binding matches
          if (hs.action_type && hs.action_type !== action) {
            reasons.push(`Handshake action_type '${hs.action_type}' does not match requested action '${action}'`);
            handshakeVerified = false;
          } else if (body.resource_ref && hs.resource_ref && hs.resource_ref !== body.resource_ref) {
            reasons.push(`Handshake resource_ref mismatch`);
            handshakeVerified = false;
          } else if (hs.action_hash) {
            // Verify action_hash: re-compute from current request and compare with initiation snapshot
            const actionIntent = { action_type: action || null, resource_ref: body.resource_ref || null, intent_ref: body.intent_ref || null };
            const currentActionHash = sha256(JSON.stringify(actionIntent, Object.keys(actionIntent).sort()));
            if (currentActionHash !== hs.action_hash) {
              reasons.push('Handshake action_hash mismatch — action intent tampered');
              handshakeVerified = false;
            }
          }

          if (handshakeVerified !== false) {
            // Check binding not consumed
            const { data: binding } = await hsReadClient
              .from('handshake_bindings')
              .select('consumed_at, expires_at')
              .eq('handshake_id', body.handshake_id)
              .maybeSingle();

            if (binding?.consumed_at) {
              reasons.push('Handshake binding already consumed');
              handshakeVerified = false;
            } else if (binding && new Date(binding.expires_at) < new Date()) {
              reasons.push('Handshake binding expired');
              handshakeVerified = false;
            } else {
              handshakeVerified = true;
            }
          }
        }
      } catch {
        handshakeVerified = false;
        reasons.push('Could not verify handshake');
      }
    }

    const decision = reasons.length === 0 ? 'allow' : 'deny';

    const extensions = {
      action,
      display_name: result.display_name,
    };

    if (delegation_id) extensions.delegation_verified = delegationVerified;

    if (value_usd) extensions.value_threshold = {
      value_usd,
      escalated_to_strict: value_usd > 10000 && policy !== 'strict',
    };

    if (body.handshake_id) extensions.handshake_verified = handshakeVerified;

    if (decision === 'deny') {
      extensions._note = 'Trust must never be more powerful than appeal.';
    }

    // Mint commit if allowed
    let commit_ref = null;
    if (decision === 'allow') {
      try {
        const commitResult = await protocolWrite({
          type: COMMAND_TYPES.ISSUE_COMMIT,
          actor: auth.entity || 'system',
          input: {
            entity_id,
            action_type: action,
            scope: {
              policy,
              ...(body.handshake_id ? { handshake_id: body.handshake_id } : {}),
              ...(body.resource_ref ? { resource_ref: body.resource_ref } : {}),
            },
            context: {
              gate_decision: decision,
              delegation_verified: delegationVerified,
              handshake_verified: handshakeVerified,
            },
          },
        });
        commit_ref = commitResult?.commit_id || null;

        // Consume handshake binding after commit issuance
        if (body.handshake_id && commit_ref) {
          await protocolWrite({
            type: COMMAND_TYPES.CONSUME_HANDSHAKE_BINDING,
            actor: auth.entity || 'system',
            input: {
              handshake_id: body.handshake_id,
              consumed_by: entity_id,
              consumed_for: `commit:${commit_ref}`,
            },
          });
        }
      } catch {
        // Commit issuance failure should not block the gate response
        warnings.push('Commit issuance failed');
      }
    }

    if (commit_ref) extensions.commit_ref = commit_ref;

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
