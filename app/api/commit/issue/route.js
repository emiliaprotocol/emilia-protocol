import { NextResponse } from 'next/server';
import { authenticateRequest } from '@/lib/supabase';
import { getGuardedClient } from '@/lib/write-guard';
import { CommitError } from '@/lib/commit';
import { authorizeCommitIssuance } from '@/lib/commit-auth';
import { protocolWrite, COMMAND_TYPES, ProtocolWriteError } from '@/lib/protocol-write';
import { epProblem } from '@/lib/errors';
import { logger } from '../../../../lib/logger.js';

// High-stakes action types MUST be routed through /api/trust/gate.
// Direct issuance is only permitted for lower-risk actions.
const GATE_REQUIRED_ACTIONS = new Set(['transact', 'connect']);

/**
 * POST /api/commit/issue
 *
 * Issue a new EP Commit — a signed, auditable pre-authorization that records
 * EP's trust decision on whether an action should proceed.
 *
 * High-stakes actions (transact, connect) require a gate_ref — a commit_id
 * from a prior /api/trust/gate 'allow' decision — to prevent bypass.
 */
export async function POST(request) {
  try {
    const auth = await authenticateRequest(request);
    if (auth.error) {
      return epProblem(401, 'unauthorized', auth.error);
    }

    const body = await request.json();

    // === INPUT VALIDATION (route responsibility) ===
    if (!body.action_type) {
      return epProblem(400, 'missing_action_type', 'action_type is required');
    }

    const validActionTypes = ['install', 'connect', 'delegate', 'transact'];
    if (!validActionTypes.includes(body.action_type)) {
      return epProblem(400, 'invalid_action_type', `action_type must be one of: ${validActionTypes.join(', ')}`);
    }

    if (!body.entity_id) {
      return epProblem(400, 'missing_entity_id', 'entity_id is required');
    }

    // === GATE ENFORCEMENT: high-stakes actions must go through /api/trust/gate ===
    if (GATE_REQUIRED_ACTIONS.has(body.action_type)) {
      if (!body.gate_ref) {
        return epProblem(403, 'gate_required',
          `Action "${body.action_type}" requires a gate_ref from a prior /api/trust/gate 'allow' decision. ` +
          `Direct commit issuance is not permitted for high-stakes actions.`);
      }

      // Verify gate_ref is a valid, unconsumed commit for this entity + action
      const supabase = getGuardedClient();
      const { data: gateCommit } = await supabase
        .from('commits')
        .select('commit_id, entity_id, action_type, decision, scope, policy_snapshot')
        .eq('commit_id', body.gate_ref)
        .maybeSingle();

      if (!gateCommit) {
        return epProblem(403, 'invalid_gate_ref', 'gate_ref does not reference a valid commit');
      }
      if (gateCommit.decision !== 'allow') {
        return epProblem(403, 'gate_denied', 'gate_ref references a denied commit');
      }
      if (gateCommit.entity_id !== body.entity_id) {
        return epProblem(403, 'gate_entity_mismatch', 'gate_ref was issued for a different entity');
      }
      if (gateCommit.action_type !== body.action_type) {
        return epProblem(403, 'gate_action_mismatch', 'gate_ref was issued for a different action type');
      }

      // Policy crossover guard: gate commit and issuing commit must share the same policy.
      // A gate evaluated under policy='permissive' MUST NOT satisfy a commit that requires
      // policy='strict'. Without this check, a low-bar gate_ref can bypass tighter policies.
      const issuingPolicyId = body.policy?.id ?? body.policy?.policy_id ?? null;
      const gatePolicyId = gateCommit.policy_snapshot?.id ?? gateCommit.policy_snapshot?.policy_id ?? null;
      if (issuingPolicyId && gatePolicyId && issuingPolicyId !== gatePolicyId) {
        return epProblem(403, 'gate_policy_mismatch',
          'gate_ref was issued under a different policy than the commit being issued');
      }
    }

    // === AUTHORIZATION: caller must own entity_id or hold a verified delegation ===
    const authz = await authorizeCommitIssuance(auth, body.entity_id, body.delegation_id, body.action_type);
    if (!authz.authorized) {
      return epProblem(403, 'not_authorized', authz.reason);
    }

    // === ISSUE COMMIT (via protocolWrite) ===
    const commit = await protocolWrite({
      type: COMMAND_TYPES.ISSUE_COMMIT,
      actor: auth,
      input: {
        action_type: body.action_type,
        entity_id: body.entity_id,
        principal_id: body.principal_id,
        counterparty_entity_id: body.counterparty_entity_id,
        delegation_id: body.delegation_id,
        scope: body.scope,
        max_value_usd: body.max_value_usd,
        context: {
          ...body.context,
          ...(body.gate_ref ? { gate_ref: body.gate_ref } : {}),
        },
        policy: body.policy,
      },
    });

    return NextResponse.json({
      decision: commit.decision,
      commit,
    }, { status: 201 });
  } catch (err) {
    if (err instanceof ProtocolWriteError) {
      return epProblem(err.status, err.code.toLowerCase(), err.message);
    }
    if (err instanceof CommitError) {
      return epProblem(err.status, err.code.toLowerCase(), err.message);
    }
    logger.error('Commit issue error:', err);
    return epProblem(500, 'internal_error', 'Internal server error');
  }
}
