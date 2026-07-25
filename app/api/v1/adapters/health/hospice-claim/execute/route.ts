// SPDX-License-Identifier: Apache-2.0
/**
 * Synthetic hospice administrative consequence-control adapter.
 *
 * This is a transport and authentication boundary only. Proposal-to-Effect
 * owns reservation, one-time consumption, provider-entry custody, and
 * reconciliation. A deployment must inject a configured control instance with
 * durable stores and provider trust pins under HEALTHCARE_CONTROL_KEY.
 */

import { NextRequest, NextResponse } from 'next/server';
import { authEntityId } from '@/lib/auth-projections.js';
import { epProblem } from '@/lib/errors.js';
import type { HealthcareConsequenceControl } from '@/lib/health/proposal-to-effect-profile.js';
import { readLimitedJson } from '@/lib/http/body-limit.js';
import { logger } from '@/lib/logger.js';
import { authenticateRequest } from '@/lib/supabase.js';
import { resolveAuthorizedOrg } from '@/lib/tenant-binding.js';

const MAX_BODY_BYTES = 512 * 1024;
const IDENTIFIER_RE = /^[A-Za-z0-9][A-Za-z0-9:_.@/-]{2,255}$/;
const PROHIBITED_PHI_FIELD_ALIASES = new Set([
  'accountnumber',
  'address',
  'authorizationform',
  'bankaccount',
  'beneficiaryid',
  'bic',
  'cin',
  'clinicalnote',
  'dateofbirth',
  'diagnosis',
  'diagnosistext',
  'dob',
  'email',
  'medicarebeneficiaryidentifier',
  'membername',
  'patientname',
  'phone',
  'routingnumber',
  'ssn',
  'telephone',
  'freetext',
  'freeformtext',
  'freetextnote',
]);

export const HEALTHCARE_CONTROL_KEY = Symbol.for(
  'emilia.health.hospice-claim.proposal-to-effect-control.v1',
);

type Authenticator = (request: NextRequest) => Promise<any>;
type ControlResolver =
  () => HealthcareConsequenceControl | null | Promise<HealthcareConsequenceControl | null>;

export interface HospiceClaimExecuteDependencies {
  authenticate?: Authenticator;
  resolve_control?: ControlResolver;
}

function isObject(value: unknown): value is Record<string, any> {
  return value !== null && typeof value === 'object' && !Array.isArray(value);
}

function identifier(value: unknown): value is string {
  return typeof value === 'string' && IDENTIFIER_RE.test(value);
}

function normalizedFieldAlias(value: string): string {
  return value.normalize('NFKC').toLowerCase().replace(/[^a-z0-9]/g, '');
}

function prohibitedPhi(
  value: unknown,
  depth = 0,
  budget: { entries: number } = { entries: 0 },
): string | null {
  if (depth > 10 || budget.entries > 4096) return 'input_complexity_limit';
  if (Array.isArray(value)) {
    for (const entry of value) {
      budget.entries += 1;
      const found = prohibitedPhi(entry, depth + 1, budget);
      if (found) return found;
    }
    return null;
  }
  if (!isObject(value)) return null;
  for (const [key, entry] of Object.entries(value)) {
    budget.entries += 1;
    if (PROHIBITED_PHI_FIELD_ALIASES.has(normalizedFieldAlias(key))) return key;
    const found = prohibitedPhi(entry, depth + 1, budget);
    if (found) return found;
  }
  return null;
}

function noStore(response: NextResponse): NextResponse {
  response.headers.set('cache-control', 'no-store');
  return response;
}

function json(body: unknown, status: number): NextResponse {
  return noStore(NextResponse.json(body, { status }));
}

function problem(status: number, code: string, detail: string): NextResponse {
  return noStore(epProblem(status, code, detail));
}

function defaultControlResolver(): HealthcareConsequenceControl | null {
  const runtime = globalThis as typeof globalThis & {
    [HEALTHCARE_CONTROL_KEY]?: HealthcareConsequenceControl;
  };
  return runtime[HEALTHCARE_CONTROL_KEY] ?? null;
}

function resultStatus(result: Record<string, any>): number {
  if (result.decision === 'INDETERMINATE') return 202;
  const reason = typeof result.reason === 'string' ? result.reason : '';
  if (/(mismatch|replay|consum|already|operation)/.test(reason)) return 409;
  if (/(unavailable|store|clock)/.test(reason)) return 503;
  return 422;
}

function executionProjection(result: Record<string, any>): Record<string, unknown> {
  return {
    ok: result.ok === true,
    decision: typeof result.decision === 'string' ? result.decision : 'REFUSED',
    ...(identifier(result.reason) ? { reason: result.reason } : {}),
    ...(identifier(result.operation_id) ? { operation_id: result.operation_id } : {}),
    ...(identifier(result.action_caid) ? { action_caid: result.action_caid } : {}),
    ...(isObject(result.attempt) ? { attempt: structuredClone(result.attempt) } : {}),
    ...(typeof result.reconciliation_required === 'boolean'
      ? { reconciliation_required: result.reconciliation_required }
      : {}),
    ...(typeof result.retry_safe === 'boolean'
      ? { retry_safe: result.retry_safe }
      : {}),
    ...(typeof result.authenticated_provider_evidence === 'boolean'
      ? { authenticated_provider_evidence: result.authenticated_provider_evidence }
      : {}),
    ...(typeof result.provider_evidence_digest === 'string'
      ? { provider_evidence_digest: result.provider_evidence_digest }
      : {}),
  };
}

function preparationProjection(result: Record<string, any>): Record<string, unknown> {
  if (result.ok !== true) return executionProjection(result);
  if (!isObject(result.finding)
      || !isObject(result.control_package)
      || !isObject(result.proposal)
      || !isObject(result.authorization)
      || !isObject(result.challenge)) {
    return { ok: false, decision: 'REFUSED', reason: 'healthcare_control_invalid_result' };
  }
  return {
    ok: true,
    decision: 'APPROVAL_REQUIRED',
    finding: structuredClone(result.finding),
    control_package: structuredClone(result.control_package),
    proposal: structuredClone(result.proposal),
    authorization: structuredClone(result.authorization),
    challenge: structuredClone(result.challenge),
  };
}

export function createHospiceClaimExecuteHandler(
  dependencies: HospiceClaimExecuteDependencies = {},
) {
  const authenticate = dependencies.authenticate ?? authenticateRequest;
  const resolveControl = dependencies.resolve_control ?? defaultControlResolver;

  return async function hospiceClaimExecute(request: NextRequest): Promise<NextResponse> {
    try {
      const auth = await authenticate(request);
      if (auth?.error) {
        return problem(
          auth.status || 401,
          auth.code || 'unauthorized',
          'Authentication is required',
        );
      }
      const initiatorId = authEntityId(auth);
      if (!identifier(initiatorId)) {
        return problem(401, 'authenticated_entity_required', 'Authenticated entity is required');
      }

      const parsed = await readLimitedJson(request, MAX_BODY_BYTES);
      if (!parsed.ok) return problem(parsed.status, parsed.code, parsed.detail);
      if (!isObject(parsed.value)) {
        return problem(400, 'invalid_body', 'request body must be a JSON object');
      }
      const body = parsed.value;
      const phi = prohibitedPhi(body);
      if (phi) return problem(400, 'prohibited_phi', 'Raw healthcare data is not accepted');
      if (!identifier(body.organization_id)) {
        return problem(400, 'missing_organization_id', 'organization_id is required');
      }
      const organization = resolveAuthorizedOrg(
        auth,
        body.organization_id,
        { requireBound: true },
      );
      if (organization.error) {
        return problem(
          organization.error.status,
          organization.error.code,
          organization.error.detail,
        );
      }
      const control = await resolveControl();
      if (!control) {
        return problem(
          503,
          'healthcare_control_unavailable',
          'Healthcare consequence control is not configured',
        );
      }

      let result: Record<string, any>;
      if (body.operation === 'prepare') {
        if (!identifier(body.proposal_id)
            || !identifier(body.operation_id)
            || !isObject(body.prospective_control_package)) {
          return problem(
            400,
            'incomplete_prepare_request',
            'proposal_id, operation_id, and prospective_control_package are required',
          );
        }
        result = await control.prepare({
          tenant_id: organization.organizationId!,
          initiator_id: initiatorId,
          proposal_id: body.proposal_id,
          operation_id: body.operation_id,
          prospective_control_package: body.prospective_control_package,
        });
        const projected = preparationProjection(result);
        if (projected.ok !== true) return json(projected, resultStatus(result));
        return json(projected, 201);
      }

      if (body.operation === 'execute') {
        if (!isObject(body.proposal)
            || !isObject(body.approval_evidence)
            || !isObject(body.evaluation)
            || !isObject(body.observed_action)) {
          return problem(
            400,
            'incomplete_execute_request',
            'proposal, approval_evidence, evaluation, and observed_action are required',
          );
        }
        result = await control.execute({
          tenant_id: organization.organizationId!,
          proposal: body.proposal,
          approval_evidence: body.approval_evidence,
          evaluation: body.evaluation,
          observed_action: body.observed_action,
        });
        return json(executionProjection(result), result.ok === true ? 200 : resultStatus(result));
      }

      if (body.operation === 'reconcile') {
        if (!identifier(body.operation_id)
            || !isObject(body.proposal)
            || !isObject(body.evaluation)
            || !isObject(body.provider_evidence)) {
          return problem(
            400,
            'incomplete_reconciliation_request',
            'operation_id, proposal, evaluation, and provider_evidence are required',
          );
        }
        result = await control.reconcile({
          tenant_id: organization.organizationId!,
          operation_id: body.operation_id,
          proposal: body.proposal,
          evaluation: body.evaluation,
          provider_evidence: body.provider_evidence,
        });
        return json(executionProjection(result), result.ok === true ? 200 : resultStatus(result));
      }

      return problem(
        400,
        'unsupported_healthcare_operation',
        'operation must be prepare, execute, or reconcile',
      );
    } catch {
      logger.error('[adapter:health.hospice-claim.proposal-to-effect.execute] failed');
      return problem(
        503,
        'healthcare_control_unavailable',
        'Healthcare consequence control is unavailable',
      );
    }
  };
}

export const POST = createHospiceClaimExecuteHandler();
