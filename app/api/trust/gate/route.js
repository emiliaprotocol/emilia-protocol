// SPDX-License-Identifier: Apache-2.0
// EMILIA Protocol — POST /api/trust/gate
// Trust gate: pre-action check. Returns allow/review/deny before executing a high-stakes action.

import { NextResponse } from 'next/server';
import { randomUUID } from 'node:crypto';
import { verifyDelegation } from '@/lib/delegation';
import { canonicalEvaluate } from '@/lib/canonical-evaluator';
import { EP_ERRORS } from '@/lib/errors';
import { buildTrustDecision } from '@/lib/trust-decision';
import { authenticateRequest } from '@/lib/supabase';
import { authEntityId, authEntityActor } from '@/lib/auth-projections.js';
import { getGuardedClient } from '@/lib/write-guard';
import { protocolWrite, COMMAND_TYPES } from '@/lib/protocol-write';
import { canonicalize } from '@/lib/canonical-json';
import { sha256 } from '@/lib/handshake/invariants';
import { authorizeHandshakeVerify } from '@/lib/handshake-auth';
import { consumeHandshake } from '@/lib/handshake/consume';
import { readLimitedJson } from '@/lib/http/body-limit';
import {
  buildGateCommitBindingFromGateRequest,
  GATE_COMMIT_BINDING_VERSION,
  GateCommitBindingError,
  hashGateCommitBinding,
} from '@/lib/gate-commit-binding';
import { logger } from '../../../../lib/logger.js';

const MAX_TRUST_GATE_BYTES = 256 * 1024;

const GATE_POLICIES = {
  strict:     { min_ee: 40,  max_dispute_rate: 0.02, require_established: true },
  standard:   { min_ee: 15,  max_dispute_rate: 0.05, require_established: false },
  permissive: { min_ee: 5,   max_dispute_rate: 0.15, require_established: false },
};

export async function POST(request) {
  try {
    const parsed = await readLimitedJson(request, MAX_TRUST_GATE_BYTES, { invalidValue: {} });
    if (!parsed.ok) {
      return NextResponse.json({ error: parsed.detail || 'Request body too large', code: parsed.code }, { status: parsed.status });
    }
    const body = parsed.value;

    const auth = await authenticateRequest(request);
    if (auth.error) return EP_ERRORS.UNAUTHORIZED();
    const actor = authEntityActor(auth);
    const callerEntityId = authEntityId(auth);
    const handshakeActor = { entity_id: callerEntityId };

    const { entity_id, action, policy = 'standard', value_usd, delegation_id, handshake_id, resource_ref, intent_ref } = body;

    if (!entity_id || !action) {
      return EP_ERRORS.BAD_REQUEST('entity_id and action are required');
    }
    if (entity_id !== callerEntityId && !delegation_id) {
      return NextResponse.json({
        error: 'entity_id must match the authenticated entity unless a delegation is supplied',
        code: 'cross_entity_authorization_required',
      }, { status: 403 });
    }

    let gateBindingHash;
    try {
      gateBindingHash = hashGateCommitBinding(buildGateCommitBindingFromGateRequest(body));
    } catch (error) {
      if (error instanceof GateCommitBindingError) {
        return EP_ERRORS.BAD_REQUEST(error.message);
      }
      throw error;
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
        // A valid action scope alone is not enough. The authenticated caller
        // must be the delegated agent and the requested entity must be the
        // delegation principal; otherwise a caller can mint a commit for an
        // unrelated entity by presenting any in-scope delegation id.
        const delegationBindingMatches = dlg.agent_entity_id === callerEntityId
          && dlg.principal_id === entity_id;
        delegationVerified = dlg.valid
          && (dlg.action_permitted !== false)
          && delegationBindingMatches;
        if (!delegationVerified) {
          reasons.push(!delegationBindingMatches
            ? 'Delegation principal/agent does not match the authenticated request'
            : (dlg.reason || 'Delegation is invalid or action not in scope'));
        }
      } catch {
        delegationVerified = false;
        reasons.push('Could not verify delegation');
      }
    }

    // Verify handshake if provided. The caller must be an initiator, responder,
    // or policy-designated verifier; knowing a handshake UUID is not authority.
    let handshakeVerified = null;
    let handshakeBinding = null;
    if (body.handshake_id) {
      try {
        const hsReadClient = getGuardedClient();
        await authorizeHandshakeVerify(hsReadClient, authEntityId(auth), body.handshake_id);

        const { data: hs, error: hsError } = await hsReadClient
          .from('handshakes')
          .select('handshake_id, status, action_type, resource_ref, action_hash, policy_hash')
          .eq('handshake_id', body.handshake_id)
          .maybeSingle();

        if (hsError) {
          reasons.push('Could not verify handshake');
          handshakeVerified = false;
        } else if (!hs) {
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
            const currentActionHash = sha256(canonicalize(actionIntent));
            if (currentActionHash !== hs.action_hash) {
              reasons.push('Handshake action_hash mismatch — action intent tampered');
              handshakeVerified = false;
            }
          }

          if (handshakeVerified !== false) {
            // Check binding not consumed
            const { data: binding, error: bindingError } = await hsReadClient
              .from('handshake_bindings')
              .select('binding_hash, consumed_at, expires_at')
              .eq('handshake_id', body.handshake_id)
              .maybeSingle();

            const expiryMs = Date.parse(binding?.expires_at || '');
            if (bindingError) {
              reasons.push('Could not verify handshake binding');
              handshakeVerified = false;
            } else if (!binding?.binding_hash) {
              reasons.push('Handshake binding not found');
              handshakeVerified = false;
            } else if (binding.consumed_at) {
              reasons.push('Handshake binding already consumed');
              handshakeVerified = false;
            } else if (!Number.isFinite(expiryMs) || expiryMs <= Date.now()) {
              reasons.push('Handshake binding expired');
              handshakeVerified = false;
            } else {
              handshakeBinding = binding;
              handshakeVerified = true;
            }
          }
        }
      } catch {
        handshakeVerified = false;
        reasons.push('Could not verify handshake');
      }
    }

    /** @type {'allow'|'review'|'deny'} */
    let decision = reasons.length === 0 ? 'allow' : 'deny';

    // A gate decision is usable only when backed by a durable allow commit.
    // For a handshake-backed decision, atomically consume the handshake first.
    // This deliberately burns the approval if later commit issuance is uncertain:
    // availability loss is safer than executing the same approval twice.
    let commit_ref = null;
    if (decision === 'allow') {
      try {
        if (body.handshake_id) {
          await consumeHandshake({
            handshake_id: body.handshake_id,
            binding_hash: handshakeBinding.binding_hash,
            consumed_by_type: 'trust_gate',
            consumed_by_id: randomUUID(),
            actor: handshakeActor,
            consumed_by_action: action,
          });
        }

        const commitResult = await protocolWrite({
          type: COMMAND_TYPES.ISSUE_COMMIT,
          actor,
          input: {
            entity_id,
            action_type: action,
            ...(delegation_id ? { delegation_id } : {}),
            scope: {
              policy,
              gate_binding_version: GATE_COMMIT_BINDING_VERSION,
              gate_binding_hash: gateBindingHash,
              ...(body.handshake_id ? { handshake_id: body.handshake_id } : {}),
              ...(body.resource_ref ? { resource_ref: body.resource_ref } : {}),
              ...(body.intent_ref ? { intent_ref: body.intent_ref } : {}),
            },
            context: {
              gate_decision: 'allow',
              delegation_verified: delegationVerified,
              handshake_verified: handshakeVerified,
            },
            policy,
          },
        });

        if (commitResult?.decision !== 'allow' || !commitResult?.commit_id) {
          reasons.push('Pre-authorization did not authorize this action');
          decision = 'deny';
        } else {
          commit_ref = commitResult.commit_id;
        }
      } catch {
        reasons.push('Pre-authorization could not be issued');
        decision = 'deny';
      }
    }

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

    if (commit_ref) extensions.commit_ref = commit_ref;

    return NextResponse.json(buildTrustDecision({
      decision,
      entityId: result.entity_id,
      policyUsed: policy,
      confidence: conf,
      reasons,
      warnings,
      appealPath: 'https://emiliaprotocol.ai/appeal',
      contextUsed: undefined,
      profileSummary: {
        confidence: conf,
        evidence_level: ee,
        dispute_rate: disputeRate,
      },
      extensions,
    }));
  } catch (err) {
    logger.error('[trust/gate] error:', err);
    return EP_ERRORS.INTERNAL();
  }
}
