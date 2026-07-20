// SPDX-License-Identifier: Apache-2.0
// EP Health Program Integrity adapter — POST /api/v1/adapters/health/hospice-claim/precheck
//
// This route is deliberately a thin, fail-closed façade over the planned
// lib/health/program-integrity.js engine. It authenticates and binds the tenant
// before handing the action to the engine, and it never reflects the action,
// authorization, or engine internals back to the caller.

import { NextResponse } from 'next/server';
import { authenticateRequest } from '@/lib/supabase';
import { resolveAuthorizedOrg } from '@/lib/tenant-binding';
import { readLimitedJson } from '@/lib/http/body-limit';
import { epProblem } from '@/lib/errors';
import { logger } from '@/lib/logger.js';
import { createProgramIntegrityEngine } from '../../../../../../lib/health/program-integrity.js';

const MAX_BODY_BYTES = 256 * 1024;
const PROFILE_ID = 'medi-cal.hospice-integrity.v1';
const ACTION_TYPE = 'health.medi_cal.hospice_claim_payment.1';

const REQUIRED_ACTION_FIELDS = Object.freeze([
  'profile_id',
  'action_type',
  'organization_id',
  'provider_npi',
  'member_ref',
  'service_period_start',
  'service_period_end',
  'authorization_form_digest',
  'amount',
  'currency',
  'payment_destination_digest',
  'reviewer_id',
  'authority_proof_digest',
  'policy_id',
  'policy_version',
  'policy_hash',
]);

const DEFAULT_REQUIREMENTS = Object.freeze([
  'profile_and_action_type_pinned',
  'exact_action_caid',
  'provider_member_service_period_binding',
  'authorization_form_digest',
  'amount_currency_destination_binding',
  'named_reviewer_authority',
  'policy_and_revocation_freshness',
  'single_use_consumption',
]);

const SAFE_DECISIONS = new Set([
  'READY',
  'REFUSED',
  'INDETERMINATE',
  'EXECUTED',
  'RECONCILED_EXECUTED',
  'RECONCILED_FAILED',
]);

const PROHIBITED_PHI_FIELDS = new Set([
  'member_name',
  'date_of_birth',
  'address',
  'telephone',
  'phone',
  'email',
  'ssn',
  'medicare_beneficiary_identifier',
  'diagnosis',
  'clinical_note',
  'authorization_form',
]);

const ENGINE_KEY = Symbol.for('emilia.health.medi-cal.hospice-integrity.engine');

function getProgramIntegrityEngine() {
  if (!globalThis[ENGINE_KEY]) {
    // The engine owns the durable state, provider trust pins, and deployment
    // configuration. The route supplies only the immutable profile boundary.
    globalThis[ENGINE_KEY] = createProgramIntegrityEngine({
      profile_id: PROFILE_ID,
      action_type: ACTION_TYPE,
    });
  }
  return globalThis[ENGINE_KEY];
}

function noStore(response) {
  response.headers.set('cache-control', 'no-store');
  return response;
}

function json(body, status) {
  return noStore(NextResponse.json(body, { status }));
}

function problem(status, code, detail, extras = {}) {
  return noStore(epProblem(status, code, detail, extras));
}

function isObject(value) {
  return value !== null && typeof value === 'object' && !Array.isArray(value);
}

function safeToken(value) {
  if (typeof value !== 'string' || value.length === 0 || value.length > 96) return null;
  return /^[a-zA-Z0-9_.:-]+$/.test(value) ? value : null;
}

function safeDecision(value, fallback = 'REFUSED') {
  return SAFE_DECISIONS.has(value) ? value : fallback;
}

function safeStatus(value) {
  const token = safeToken(value);
  return token ? token.toLowerCase() : undefined;
}

function safeReason(value) {
  return safeToken(value)?.toLowerCase() || 'program_integrity_refused';
}

function safeRequirements(...candidates) {
  const candidate = candidates.find((value) => Array.isArray(value));
  if (!candidate) return [...DEFAULT_REQUIREMENTS];
  const values = candidate
    .filter((value) => safeToken(value))
    .map((value) => value.toLowerCase())
    .slice(0, 32);
  return values.length ? values : [...DEFAULT_REQUIREMENTS];
}

/**
 * Project only coarse, allowlisted evidence state. In particular, never copy
 * an engine-provided object wholesale: a source adapter must not be able to
 * smuggle a patient name, clinical note, raw form, or provider response into
 * an API response.
 */
function safeEvidenceSummary(summary, { authorizationPresent = false } = {}) {
  const source = isObject(summary) ? summary : {};
  const result = {
    profile_id: PROFILE_ID,
    authorization_present: authorizationPresent,
    raw_evidence_included: false,
    phi_free_projection: true,
  };

  for (const field of [
    'status',
    'authorization_status',
    'authority_status',
    'provider_snapshot_status',
    'policy_status',
    'revocation_status',
    'consumption_status',
    'execution_binding_status',
    'reconciliation_status',
  ]) {
    const value = safeStatus(source[field]);
    if (value) result[field] = value;
  }

  const checks = {};
  for (const field of [
    'authorization',
    'authority',
    'provider_snapshot',
    'policy',
    'revocation',
    'consumption',
    'execution_binding',
    'provider_evidence',
  ]) {
    if (typeof source[field] === 'boolean') checks[field] = source[field];
  }
  if (Object.keys(checks).length) result.checks = checks;
  return result;
}

function refusalStatus(result) {
  const reason = safeReason(result?.reason);
  if (reason.includes('unavailable') || reason.includes('storage') || reason.includes('indeterminate')) {
    return 503;
  }
  if (reason.includes('replay') || reason.includes('conflict') || reason.includes('mismatch')) {
    return 409;
  }
  return 422;
}

function actionFromBody(body) {
  if (Object.prototype.hasOwnProperty.call(body, 'action')) return body.action;
  const action = { ...body };
  delete action.authorization;
  delete action.provider_evidence;
  delete action.evidence;
  delete action.operation_id;
  return action;
}

function containsProhibitedPhi(action) {
  return Object.keys(action).find((key) => PROHIBITED_PHI_FIELDS.has(key)) || null;
}

function validateActionShape(action) {
  if (!isObject(action)) return { code: 'invalid_action', detail: 'action must be a JSON object' };
  const prohibited = containsProhibitedPhi(action);
  if (prohibited) return { code: 'prohibited_phi', detail: `action contains prohibited field: ${prohibited}` };

  for (const field of REQUIRED_ACTION_FIELDS) {
    if (action[field] === undefined || action[field] === null || action[field] === '') {
      return { code: `missing_action_${field}`, detail: `action.${field} is required` };
    }
  }
  if (action.profile_id !== PROFILE_ID || action.action_type !== ACTION_TYPE) {
    return { code: 'unsupported_action_profile', detail: 'action profile or action type is not supported' };
  }
  if (action.currency !== 'USD') return { code: 'invalid_currency', detail: 'action.currency must be USD' };
  if (typeof action.provider_npi !== 'string' || !/^\d{10}$/.test(action.provider_npi)) {
    return { code: 'invalid_provider_npi', detail: 'action.provider_npi must be a ten-digit string' };
  }
  if (typeof action.amount !== 'string' || !/^\d+(?:\.\d{1,2})?$/.test(action.amount)) {
    return { code: 'invalid_amount', detail: 'action.amount must be a canonical decimal string' };
  }
  if (typeof action.policy_version !== 'number' || !Number.isSafeInteger(action.policy_version) || action.policy_version < 1) {
    return { code: 'invalid_policy_version', detail: 'action.policy_version must be a positive integer' };
  }
  return null;
}

function tenantBoundAction(auth, body, action) {
  const bodyOrganization = body.organization_id;
  const actionOrganization = action.organization_id;
  if (bodyOrganization && actionOrganization && bodyOrganization !== actionOrganization) {
    return { error: { status: 403, code: 'organization_mismatch', detail: 'organization_id values do not match' } };
  }

  const orgResolution = resolveAuthorizedOrg(
    auth,
    bodyOrganization || actionOrganization,
    { requireBound: true },
  );
  if (orgResolution.error) return { error: orgResolution.error };
  return { action: { ...action, organization_id: orgResolution.organizationId } };
}

function engineContractFailure() {
  return problem(503, 'program_integrity_engine_unavailable', 'Program integrity decision service is unavailable');
}

function responseForPrecheck(prepared, checked, authorization) {
  if (!isObject(prepared) || typeof prepared.ok !== 'boolean') return engineContractFailure();
  if (!isObject(checked) || typeof checked.ok !== 'boolean') return engineContractFailure();

  const caid = safeToken(checked.action_caid) || safeToken(prepared.action_caid);
  const decision = safeDecision(checked.decision, checked.ok ? null : 'REFUSED');
  if (!caid || !decision) return engineContractFailure();

  const payload = {
    ok: checked.ok === true && decision === 'READY',
    decision,
    caid,
    action_caid: caid,
    requirements: safeRequirements(checked.requirements, prepared.requirements),
    evidence_summary: safeEvidenceSummary(
      checked.evidence_summary || prepared.evidence_summary,
      { authorizationPresent: Boolean(authorization) },
    ),
  };

  if (checked.operation_id !== undefined) {
    const operationId = safeToken(checked.operation_id);
    if (!operationId) return engineContractFailure();
    payload.operation_id = operationId;
  }
  if (checked.idempotency_key !== undefined) {
    const idempotencyKey = safeToken(checked.idempotency_key);
    if (!idempotencyKey) return engineContractFailure();
    payload.idempotency_key = idempotencyKey;
  }
  if (!checked.ok) {
    payload.reason = safeReason(checked.reason);
    payload.reconciliation_required = decision === 'INDETERMINATE';
    return json(payload, 201);
  }
  if (decision !== 'READY') return engineContractFailure();
  return json(payload, 201);
}

export async function POST(request) {
  try {
    const auth = await authenticateRequest(request);
    if (auth?.error) return problem(auth.status || 401, auth.code || 'unauthorized', 'Authentication is required');

    const parsed = await readLimitedJson(request, MAX_BODY_BYTES);
    if (!parsed.ok) return problem(parsed.status, parsed.code, parsed.detail);
    if (!isObject(parsed.value)) return problem(400, 'invalid_body', 'request body must be a JSON object');

    const body = parsed.value;
    const unboundAction = actionFromBody(body);
    const action = isObject(unboundAction) && !unboundAction.organization_id && body.organization_id
      ? { ...unboundAction, organization_id: body.organization_id }
      : unboundAction;
    const actionError = validateActionShape(action);
    if (actionError) return problem(400, actionError.code, actionError.detail);
    if (!isObject(body.authorization)) {
      return problem(400, 'missing_authorization', 'authorization is required');
    }
    if (action.fail_open === true || action.bypass_checks === true || action.enforcement_mode !== undefined) {
      return problem(422, 'runtime_downgrade_refused', 'runtime fail-open controls are not accepted');
    }

    const bound = tenantBoundAction(auth, body, action);
    if (bound.error) return problem(bound.error.status, bound.error.code, bound.error.detail);

    const programEngine = getProgramIntegrityEngine();
    const prepared = await programEngine.prepare({ action: bound.action });
    if (!prepared?.ok) return responseForPrecheck(prepared, prepared, body.authorization);

    const checked = await programEngine.precheck({
      action: bound.action,
      authorization: body.authorization,
    });
    return responseForPrecheck(prepared, checked, body.authorization);
  } catch {
    logger.error('[adapter:health.medi_cal.hospice_claim_payment.precheck] failed');
    return engineContractFailure();
  }
}
