import { NextResponse } from 'next/server';
import { authenticateCloudRequest } from '@/lib/cloud/auth';
import { requirePermission } from '@/lib/cloud/authorize';
import { getGuardedClient } from '@/lib/write-guard';
import { epProblem, EP_ERRORS, epDbError } from '@/lib/errors';
import { loadPolicyById } from '@/lib/handshake/policy';
import { readEpJson } from '@/lib/http/route-body';
import {
  buildPolicyRolloutAfterState,
  buildPolicyRolloutBeforeState,
  buildPolicyRolloutQuorumPolicy,
  buildPolicyRolloutReceiptRequest,
  validatePolicyRolloutInput,
  verifyPolicyRolloutAuthorization,
} from '@/lib/cloud/policy-rollout-authorization.js';
import { resolveOrgQuorumTemplate } from '@/lib/guard-quorum-template.js';
import { logger } from '../../../../../../lib/logger.js';

const MAX_BODY_BYTES = 64 * 1024;

/**
 * POST /api/cloud/policies/[policyId]/rollout
 *
 * Initiate a rollout of a policy version to the specified environment.
 * Requires: admin permission (deployment-level action).
 *
 * Body:
 *   version     {number}  — policy version number (must exist in handshake_policies
 *                           for this policy's policy_key)
 *   environment {string}  — target environment (e.g. "production", "staging")
 *   strategy    {'immediate'|'canary'}  — default: 'immediate'
 *   canary_pct  {number}  — traffic % for canary rollouts (1–99, required if canary)
 *   metadata    {object}  — optional operator-supplied context
 *   authorization {object} — approved, unconsumed Class-A Trust Receipt:
 *     receipt_id {string}  — tr_<32-hex>
 *
 * Omit authorization to receive HTTP 428 plus the exact Trust Receipt creation
 * request that must be approved. Re-submit the unchanged rollout body with the
 * approved receipt_id. Consumption and activation then happen atomically.
 *
 * Versions live in handshake_policies (UNIQUE(policy_key, version)); each version
 * is its own row with its own policy_id. The rollout's policy_id FK points at the
 * specific version row being rolled out so the FK to handshake_policies is satisfied.
 *
 * Immediate rollouts supersede any prior active rollout for the same
 * (policy_key, environment) pair. Canary rollouts coexist with the active rollout.
 */
export async function POST(request, { params }) {
  try {
    /** @type {{ tenantId: string, environment: string, permissions: string[], keyId: string, operatorId?: string, principalId?: string } | null} */
    const auth = await authenticateCloudRequest(request);
    if (!auth) return EP_ERRORS.UNAUTHORIZED();
    requirePermission(auth, 'policy_rollout');
    if (!auth.keyId) {
      return epProblem(403, 'cloud_key_identity_required', 'Policy rollout requires an attributable cloud API key');
    }

    const { policyId } = await params;
    const parsed = await readEpJson(request, MAX_BODY_BYTES);
    if (!parsed.ok) return parsed.response;
    const body = parsed.value;

    const strategy = body?.strategy || 'immediate';
    const inputError = validatePolicyRolloutInput({ ...body, strategy });
    if (inputError) return epProblem(inputError.status, inputError.code, inputError.detail);

    // ── Environment-scope enforcement (Sentrix HIGH finding a) ─────────────────
    // An API key can be scoped to a single environment: tenant_api_keys.environment,
    // surfaced as auth.environment by authenticateCloudRequest(). A key scoped to
    // environment X MUST NOT initiate — or supersede — a rollout targeting a different
    // environment (e.g. a staging-scoped key POSTing {environment:'production'} to flip
    // a production rollout active). When the key carries an environment scope, the
    // request's target environment MUST equal it. Keys with no scope (auth.environment
    // falsy) are unrestricted here and fall through to the permission check above.
    if (auth.environment && body.environment !== auth.environment) {
      return epProblem(
        403,
        'environment_scope_mismatch',
        `This API key is scoped to environment "${auth.environment}" and cannot roll out to "${body.environment}".`,
      );
    }

    if (!['immediate', 'canary'].includes(strategy)) {
      return epProblem(400, 'invalid_strategy', 'strategy must be "immediate" or "canary"');
    }

    if (strategy === 'canary') {
      const pct = body.canary_pct;
      if (!Number.isSafeInteger(pct) || pct < 1 || pct > 99) {
        return epProblem(400, 'invalid_canary_pct', 'canary_pct must be an integer between 1 and 99');
      }
    }

    const supabase = getGuardedClient();

    // Resolve the route policyId to its policy_key; the version to roll out is
    // the handshake_policies row with this key and body.version.
    const policy = await loadPolicyById(supabase, policyId, { tenantId: auth.tenantId });
    if (!policy) {
      return EP_ERRORS.NOT_FOUND('Policy');
    }

    const { data: versionRow, error: vErr } = await supabase
      .from('handshake_policies')
      .select('policy_id, policy_key, version, mode, status, rules')
      .eq('tenant_id', auth.tenantId)
      .eq('policy_key', policy.policy_key)
      .eq('version', body.version)
      .maybeSingle();

    if (vErr) {
      logger.error('[cloud/policies/rollout] Version query error:', vErr);
      return epDbError(500, 'rollout_query_failed', vErr, 'cloud/policies/rollout');
    }

    if (!versionRow) {
      return epProblem(404, 'version_not_found', `Policy version ${body.version} not found`);
    }
    if (versionRow.status !== 'active') {
      return epProblem(
        409,
        'policy_version_inactive',
        `Policy version ${body.version} is ${versionRow.status || 'not active'} and cannot be rolled out`,
      );
    }

    const { data: keyVersions, error: keyErr } = await supabase
      .from('handshake_policies')
      .select('policy_id')
      .eq('tenant_id', auth.tenantId)
      .eq('policy_key', policy.policy_key);
    if (keyErr) {
      logger.error('[cloud/policies/rollout] Policy family query error:', keyErr);
      return epDbError(500, 'rollout_query_failed', keyErr, 'cloud/policies/rollout');
    }

    const policyIds = (keyVersions || []).map((row) => row.policy_id);
    let activeRollouts = [];
    if (policyIds.length > 0) {
      const { data: activeRows, error: activeErr } = await supabase
        .from('policy_rollouts')
        .select('rollout_id, policy_id, version, environment, strategy, canary_pct, metadata, authorization_receipt_id')
        .eq('tenant_id', auth.tenantId)
        .in('policy_id', policyIds)
        .eq('environment', body.environment)
        .eq('status', 'active');
      if (activeErr) {
        logger.error('[cloud/policies/rollout] Active rollout query error:', activeErr);
        return epDbError(500, 'rollout_query_failed', activeErr, 'cloud/policies/rollout');
      }
      activeRollouts = activeRows || [];
    }

    const beforeState = buildPolicyRolloutBeforeState(activeRollouts);
    const afterState = buildPolicyRolloutAfterState({
      policyId: versionRow.policy_id,
      policyKey: policy.policy_key,
      version: body.version,
      policyRules: versionRow.rules,
      policyMode: versionRow.mode,
      policyStatus: versionRow.status,
      environment: body.environment,
      strategy,
      canaryPct: body.canary_pct,
      metadata: body.metadata,
    });
    const quorumTemplate = await resolveOrgQuorumTemplate(supabase, {
      organizationId: auth.tenantId,
      actionType: 'policy_rollout',
    });
    if (quorumTemplate.error || quorumTemplate.tableMissing) {
      return epProblem(
        503,
        'rollout_quorum_template_unavailable',
        'The tenant policy-rollout quorum template could not be verified',
      );
    }
    const rolloutQuorum = buildPolicyRolloutQuorumPolicy(quorumTemplate.template);
    if ('ok' in rolloutQuorum) {
      return epProblem(rolloutQuorum.status, rolloutQuorum.code, rolloutQuorum.detail);
    }
    const quorumPolicy = rolloutQuorum.policy;
    const receiptRequest = buildPolicyRolloutReceiptRequest({
      tenantId: auth.tenantId,
      executingKeyId: auth.keyId,
      policyId: versionRow.policy_id,
      policyKey: policy.policy_key,
      version: body.version,
      policyRules: versionRow.rules,
      policyMode: versionRow.mode,
      policyStatus: versionRow.status,
      environment: body.environment,
      strategy,
      canaryPct: body.canary_pct,
      metadata: body.metadata,
      beforeState,
      afterState,
      quorumPolicy,
    });

    if (!body.authorization) {
      return epProblem(
        428,
        'accountable_signoff_required',
        'Approve the returned Class-A Trust Receipt request, then re-submit this rollout with authorization.receipt_id',
        {
          authorization_request: receiptRequest,
          authorization_flow: {
            create: 'POST /api/v1/trust-receipts',
            request_signoff: 'POST /api/v1/signoffs/request',
            approve: 'POST /api/v1/signoffs/{signoffId}/approve-webauthn',
            activate: `POST /api/cloud/policies/${policyId}/rollout`,
          },
        },
      );
    }

    const receiptId = body.authorization.receipt_id;
    const { data: authorizationEvents, error: authorizationErr } = await supabase
      .from('audit_events')
      .select('event_type, actor_id, after_state, created_at')
      .eq('target_type', 'trust_receipt')
      .eq('target_id', receiptId)
      .order('created_at', { ascending: true });

    if (authorizationErr) {
      logger.error('[cloud/policies/rollout] Authorization evidence query error:', authorizationErr);
      return epDbError(
        500,
        'rollout_authorization_query_failed',
        authorizationErr,
        'cloud/policies/rollout',
      );
    }

    const authorization = await verifyPolicyRolloutAuthorization({
      supabase,
      events: authorizationEvents,
      expected: {
        tenantId: auth.tenantId,
        executingKeyId: auth.keyId,
        policyId: versionRow.policy_id,
        policyKey: policy.policy_key,
        version: body.version,
        policyRules: versionRow.rules,
        policyMode: versionRow.mode,
        policyStatus: versionRow.status,
        environment: body.environment,
        strategy,
        canaryPct: body.canary_pct,
        metadata: body.metadata,
        beforeState,
        afterState,
        receiptId,
        quorumPolicy,
      },
    });
    if ('status' in authorization) {
      return epProblem(authorization.status, authorization.code, authorization.detail);
    }

    // The RPC re-locks and reconstructs before/after state, consumes the
    // approved receipt, supersedes any prior immediate rollout, and inserts the
    // new rollout in one transaction. Any failure rolls back every step.
    const { data: rollout, error: insertErr } = await supabase
      .rpc('activate_policy_rollout_authorized', {
        p_tenant_id: auth.tenantId,
        p_policy_id: versionRow.policy_id,
        p_policy_key: policy.policy_key,
        p_version: body.version,
        p_environment: body.environment,
        p_strategy: strategy,
        p_canary_pct: strategy === 'canary' ? body.canary_pct : null,
        p_initiated_by: auth.keyId ? `key:${auth.keyId}` : 'unknown',
        p_metadata: body.metadata || {},
        p_receipt_id: receiptId,
        p_action_hash: authorization.actionHash,
        p_signed_before_state: beforeState,
        p_signed_after_state: afterState,
        p_authority_ids: authorization.authorityIds,
        p_quorum_policy: quorumPolicy,
      })
      .single();

    if (insertErr) {
      const insertContext = `${insertErr.message || ''} ${insertErr.details || ''} ${insertErr.hint || ''}`;
      if (insertErr.code === '23505'
          && (insertContext.includes('policy_rollouts_authorization_receipt_once')
            || insertContext.includes('guard_receipt_consume_once'))) {
        return epProblem(
          409,
          'rollout_authorization_replayed',
          'The Accountable Signoff receipt has already authorized a rollout',
        );
      }
      if (insertContext.includes('policy_rollout_receipt_unavailable')) {
        return epProblem(
          409,
          'rollout_authorization_replayed',
          'The Accountable Signoff receipt is unavailable or has already been consumed',
        );
      }
      if (insertContext.includes('policy_rollout_signed_state_stale')) {
        return epProblem(
          409,
          'rollout_authorization_stale',
          'The active rollout state changed after this Accountable Signoff was approved',
        );
      }
      if (insertContext.includes('policy_rollout_version_mismatch')) {
        return epProblem(
          409,
          'rollout_version_changed',
          'The approved policy version no longer matches the stored policy version',
        );
      }
      if (insertContext.includes('policy_rollout_authorization_expired')) {
        return epProblem(
          410,
          'rollout_authorization_expired',
          'The Accountable Signoff receipt expired before policy activation completed',
        );
      }
      if (insertContext.includes('policy_rollout_authorization_mismatch')
          || insertContext.includes('policy_rollout_signoff_rejected')
          || insertContext.includes('accountable_signoff_required')
          || insertContext.includes('policy_rollout_quorum_required')
          || insertContext.includes('policy_rollout_quorum_policy_invalid')
          || insertContext.includes('policy_rollout_quorum_requests_invalid')
          || insertContext.includes('policy_rollout_quorum_not_satisfied')
          || insertContext.includes('policy_rollout_authority_invalid')) {
        return epProblem(
          403,
          'rollout_authorization_invalid',
          'The Accountable Signoff or approver authority could not be re-verified in the activation transaction',
        );
      }
      if (insertContext.includes('invalid_policy_rollout_activation')) {
        return epProblem(
          400,
          'invalid_rollout_activation',
          'The policy rollout activation parameters are invalid',
        );
      }
      logger.error('[cloud/policies/rollout] Activation error:', insertErr);
      return epDbError(500, 'rollout_activation_failed', insertErr, 'cloud/policies/rollout');
    }

    return NextResponse.json({
      rollout_id: rollout.rollout_id,
      policy_id: versionRow.policy_id,
      policy_key: policy.policy_key,
      version: body.version,
      environment: body.environment,
      strategy,
      status: 'active',
      canary_pct: rollout.canary_pct ?? null,
      initiated_at: rollout.initiated_at,
      tenant_id: auth.tenantId,
      authorization_receipt_id: receiptId,
      authorization_action_hash: authorization.actionHash,
      authorization_execution_reference_id: rollout.authorization_execution_reference_id,
    });
  } catch (err) {
    if (err.name === 'CloudAuthorizationError') {
      return epProblem(403, 'forbidden', err.message);
    }
    logger.error('[cloud/policies/rollout] Error:', err);
    return EP_ERRORS.INTERNAL();
  }
}
