import { NextResponse } from 'next/server';
import { authenticateRequest } from '@/lib/supabase';
import { getGuardedClient } from '@/lib/write-guard';
import { CommitError, verifyCommit } from '@/lib/commit';
import { authorizeCommitIssuance } from '@/lib/commit-auth';
import { protocolWrite, COMMAND_TYPES, ProtocolWriteError } from '@/lib/protocol-write';
import { epProblem } from '@/lib/errors';
import { readEpJson } from '@/lib/http/route-body';
import {
  buildGateCommitBindingFromIssueRequest,
  GATE_COMMIT_BINDING_VERSION,
  GateCommitBindingError,
  hashGateCommitBinding,
} from '@/lib/gate-commit-binding';
import { logger } from '../../../../lib/logger.js';

// High-stakes action types MUST be routed through /api/trust/gate.
// Direct issuance is only permitted for lower-risk actions.
const GATE_REQUIRED_ACTIONS = new Set(['transact', 'connect']);
const MAX_BODY_BYTES = 256 * 1024;

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

    const parsed = await readEpJson(request, MAX_BODY_BYTES);
    if (!parsed.ok) return parsed.response;
    const body = parsed.value;

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

      let requestedBindingHash;
      try {
        requestedBindingHash = hashGateCommitBinding(buildGateCommitBindingFromIssueRequest(body));
      } catch (error) {
        if (error instanceof GateCommitBindingError) {
          return epProblem(400, 'invalid_gate_binding', error.message);
        }
        throw error;
      }

      // Verify the signed gate commit before trusting any of its database fields.
      // A row that merely says decision=allow is not authorization.
      let gateVerification;
      try {
        gateVerification = await verifyCommit(body.gate_ref);
      } catch (error) {
        logger.error('gate_ref verification failed', { code: error?.code, name: error?.name });
        return epProblem(503, 'gate_verify_unavailable', 'gate_ref could not be verified');
      }
      if (!gateVerification?.valid || gateVerification.status !== 'active' || gateVerification.decision !== 'allow') {
        return epProblem(403, 'invalid_gate_ref', 'gate_ref is not an active, verified allow commit');
      }

      // Read the immutable signed row for exact action-binding checks. The
      // atomic RPC below rechecks all live state under a row lock before use.
      const supabase = getGuardedClient();
      const { data: gateCommit, error: gateReadError } = await supabase
        .from('commits')
        .select('commit_id, entity_id, action_type, decision, status, expires_at, kid, scope, policy_snapshot')
        .eq('commit_id', body.gate_ref)
        .maybeSingle();

      if (gateReadError) {
        logger.error('gate_ref read failed', { code: gateReadError.code, message: gateReadError.message });
        return epProblem(503, 'gate_verify_unavailable', 'gate_ref could not be verified');
      }
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
      if (gateCommit.scope?.gate_binding_version !== GATE_COMMIT_BINDING_VERSION ||
          typeof gateCommit.scope?.gate_binding_hash !== 'string') {
        return epProblem(403, 'gate_binding_missing',
          'gate_ref predates exact action binding; obtain a fresh /api/trust/gate decision');
      }
      if (gateCommit.scope.gate_binding_hash !== requestedBindingHash) {
        return epProblem(403, 'gate_action_mismatch',
          'gate_ref was issued for different action details');
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

    // === GATE CONSUMPTION: a gate_ref authorizes at most ONE high-stakes issuance ===
    // Claim the gate atomically AFTER authorization so an unauthorized caller
    // cannot burn a victim's gate. The RPC locks and rechecks the gate row,
    // binding, expiry, status, decision, and signing-key revocation before the
    // one-time insert. This closes status/revocation TOCTOU and replay races.
    if (GATE_REQUIRED_ACTIONS.has(body.action_type) && body.gate_ref) {
      const guarded = getGuardedClient();
      const requestedBindingHash = hashGateCommitBinding(buildGateCommitBindingFromIssueRequest(body));
      const { error: consumeErr } = await guarded.rpc('consume_gate_ref_atomic', {
        p_gate_ref: body.gate_ref,
        p_entity_id: body.entity_id,
        p_action_type: body.action_type,
        p_binding_version: GATE_COMMIT_BINDING_VERSION,
        p_binding_hash: requestedBindingHash,
      });
      if (consumeErr) {
        const message = consumeErr.message || '';
        if (consumeErr.code === '23505' || message.includes('GATE_ALREADY_CONSUMED')) {
          return epProblem(403, 'gate_already_consumed',
            'gate_ref has already been used to issue a commit; obtain a fresh /api/trust/gate decision');
        }
        if (consumeErr.code?.startsWith('P000') || message.includes('GATE_')) {
          return epProblem(403, 'invalid_gate_ref',
            'gate_ref is no longer valid for this action; obtain a fresh /api/trust/gate decision');
        }
        logger.error('gate_ref consumption failed', { code: consumeErr.code, message: consumeErr.message });
        return epProblem(503, 'gate_consume_failed', 'could not record gate consumption');
      }
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
      logger.error('Commit protocol operation failed', { code: err.code, status: err.status });
      return epProblem(err.status, err.code.toLowerCase(), 'Commit operation failed');
    }
    if (err instanceof CommitError) {
      return epProblem(err.status, err.code.toLowerCase(), err.message);
    }
    logger.error('Commit issue error:', err);
    return epProblem(500, 'internal_error', 'Internal server error');
  }
}
