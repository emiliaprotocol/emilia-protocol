// SPDX-License-Identifier: Apache-2.0
import crypto from 'node:crypto';
import { authenticateRequest, authEntityId } from '@/lib/supabase.js';
import { requirePermission } from '@/lib/cloud/authorize.js';
import { getGuardedClient } from '@/lib/write-guard.js';
import { readLimitedJson } from '@/lib/http/body-limit.js';
import { checkRateLimit } from '@/lib/rate-limit.js';
import { logger } from '@/lib/logger.js';
import { APPROVER_ID_PATTERN } from '@/lib/webauthn.js';
import { mobileJson, mobileProblem } from '@/lib/mobile/response.js';
import { createGraceMobileActionGroup } from '@/lib/mobile/store.js';
import {
  buildCurtailmentControlledAction,
  buildCurtailmentPresentation,
  createCurtailmentAction,
  graceDigest,
} from '@/lib/grace/mobile-grid.js';

const MAX_BODY_BYTES = 32 * 1024;
const MEMBERS = new Set([
  'action_id', 'facility', 'target_delta_kw', 'not_before', 'not_after',
  'baseline_method_hash', 'envelope_id', 'initiator_id', 'approver_ids',
  'required_approvals', 'control_mode',
]);

function hardCutThreshold() {
  const configured = Number(process.env.GRACE_HARD_CUT_KW || 25000);
  return Number.isSafeInteger(configured) && configured > 0 ? configured : 25000;
}

export async function POST(request) {
  try {
    if (request.headers.get('content-type')?.split(';', 1)[0].trim().toLowerCase() !== 'application/json') {
      return mobileProblem(415, 'invalid_content_type', 'GRACE action requests require application/json');
    }
    const auth = await authenticateRequest(request);
    if (auth.error) return mobileProblem(auth.status || 401, auth.code || 'unauthorized', auth.error);
    try { requirePermission(auth, 'write'); } catch {
      return mobileProblem(403, 'insufficient_permission', 'A write-capable organization key is required');
    }
    const limited = await checkRateLimit(authEntityId(auth), 'protocol_write');
    if (!limited.allowed) return mobileProblem(429, 'rate_limited', 'Too many GRACE action requests');
    const parsed = await readLimitedJson(request, MAX_BODY_BYTES, { invalidValue: {} });
    if (!parsed.ok) return mobileProblem(parsed.status, parsed.code, parsed.detail);
    const body = parsed.value;
    if (!body || typeof body !== 'object' || Array.isArray(body)
        || !Object.keys(body).every((key) => MEMBERS.has(key))
        || !Array.isArray(body.approver_ids) || body.approver_ids.length < 1
        || body.approver_ids.length > 16
        || !body.approver_ids.every((value) => APPROVER_ID_PATTERN.test(value || ''))
        || new Set(body.approver_ids).size !== body.approver_ids.length
        || !Number.isSafeInteger(body.required_approvals)
        || body.required_approvals < 1 || body.required_approvals > body.approver_ids.length) {
      return mobileProblem(400, 'invalid_curtailment_action', 'GRACE action request is malformed');
    }
    const targetKw = Number(body.target_delta_kw);
    if (!Number.isFinite(targetKw)
        || (targetKw >= hardCutThreshold() && body.required_approvals < 2)) {
      return mobileProblem(400, 'quorum_required', 'Hard curtailment requires at least two distinct mobile approvers');
    }
    const issuedAt = new Date().toISOString();
    let action;
    try {
      action = createCurtailmentAction({
        actionId: body.action_id,
        facility: body.facility,
        targetDeltaKw: body.target_delta_kw,
        notBefore: body.not_before,
        notAfter: body.not_after,
        issuedAt,
        baselineMethodHash: body.baseline_method_hash,
        controlMode: body.control_mode,
        envelopeId: body.envelope_id,
        requestedBy: body.initiator_id,
      });
    } catch {
      return mobileProblem(400, 'invalid_curtailment_action', 'GRACE action fields are invalid or outside the canonical profile');
    }
    const controlledAction = buildCurtailmentControlledAction(action);
    const presentation = buildCurtailmentPresentation(action);
    const policy = {
      policy_id: 'ep:grace:mobile-curtailment:v1',
      action_family: 'grid.curtailment',
      human_approval: 'class_a',
      required_approvals: body.required_approvals,
      approvers: [...body.approver_ids],
      hard_cut_threshold_kw: String(hardCutThreshold()),
    };
    const assignments = body.approver_ids.map((approverId) => ({
      action_reference: `mobact_${crypto.randomBytes(16).toString('hex')}`,
      approver_id: approverId,
    }));
    await createGraceMobileActionGroup(getGuardedClient(), {
      assignments,
      entityRef: authEntityId(auth),
      initiatorId: body.initiator_id,
      action: controlledAction,
      presentation,
      policy,
      policyId: policy.policy_id,
      expiresAt: action.expires_at,
    });
    return mobileJson({
      action_id: action.action_id,
      action_hash: graceDigest(controlledAction),
      source_action_hash: graceDigest(action),
      required_approvals: body.required_approvals,
      assignments,
      expires_at: action.expires_at,
    }, { status: 201, headers: { 'cache-control': 'no-store' } });
  } catch (error) {
    logger.error('[grace] mobile curtailment action creation failed', error);
    return mobileProblem(503, 'grace_action_unavailable', 'GRACE mobile action service unavailable');
  }
}
