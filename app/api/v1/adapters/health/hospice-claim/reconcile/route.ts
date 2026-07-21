// SPDX-License-Identifier: Apache-2.0
// EP Health Program Integrity adapter — POST /api/v1/adapters/health/hospice-claim/reconcile
//
// Reconciliation is not a retry endpoint. It accepts only authenticated,
// action-bound provider evidence for an operation already marked indeterminate
// by the program-integrity engine.

import { NextRequest, NextResponse } from 'next/server';
import { authenticateRequest } from '@/lib/supabase';
import { resolveAuthorizedOrg } from '@/lib/tenant-binding';
import { readLimitedJson } from '@/lib/http/body-limit';
import { epProblem } from '@/lib/errors';
import { logger } from '@/lib/logger.js';
import { createProgramIntegrityEngine } from '@/lib/health/program-integrity.js';

const MAX_BODY_BYTES = 256 * 1024;
const PROFILE_ID = 'medi-cal.hospice-integrity.v1';
const ACTION_TYPE = 'health.medi-cal.hospice-claim-payment.1';
const PROVIDER_EVIDENCE_VERSION = 'EP-HEALTH-PROGRAM-INTEGRITY-PROVIDER-EVIDENCE-v1';
const SAFE_TERMINAL_DECISIONS = new Set<string>(['RECONCILED_EXECUTED', 'RECONCILED_FAILED']);
const SAFE_DECISIONS = new Set<string>(['REFUSED', 'INDETERMINATE', ...SAFE_TERMINAL_DECISIONS]);
const PROHIBITED_PHI_FIELDS = new Set<string>([
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

type ProgramIntegrityEngine = ReturnType<typeof createProgramIntegrityEngine>;

function getProgramIntegrityEngine(): ProgramIntegrityEngine {
  const globalWithEngine = globalThis as typeof globalThis & {
    [ENGINE_KEY]?: ProgramIntegrityEngine;
  };
  if (!globalWithEngine[ENGINE_KEY]) {
    globalWithEngine[ENGINE_KEY] = createProgramIntegrityEngine({
      profile_id: PROFILE_ID,
      action_type: ACTION_TYPE,
    });
  }
  return globalWithEngine[ENGINE_KEY] as ProgramIntegrityEngine;
}

function noStore(response: NextResponse): NextResponse {
  response.headers.set('cache-control', 'no-store');
  return response;
}

function json(body: unknown, status: number): NextResponse {
  return noStore(NextResponse.json(body, { status }));
}

function problem(
  status: number,
  code: string,
  detail: string,
  extras: Record<string, unknown> = {},
): NextResponse {
  return noStore(epProblem(status, code, detail, extras));
}

function isObject(value: unknown): value is Record<string, any> {
  return value !== null && typeof value === 'object' && !Array.isArray(value);
}

function safeToken(value: unknown): string | null {
  if (typeof value !== 'string' || value.length === 0 || value.length > 128) return null;
  return /^[a-zA-Z0-9_.:-]+$/.test(value) ? value : null;
}

function safeReason(value: unknown): string {
  return safeToken(value)?.toLowerCase() || 'provider_evidence_invalid';
}

function safeDecision(value: unknown, fallback: string | null = 'REFUSED'): string | null {
  return typeof value === 'string' && SAFE_DECISIONS.has(value) ? value : fallback;
}

function safeStatus(value: unknown): string | undefined {
  const token = safeToken(value);
  return token ? token.toLowerCase() : undefined;
}

function safeEvidenceSummary(
  summary: unknown,
  { authorizationPresent = false }: { authorizationPresent?: boolean } = {},
): Record<string, unknown> {
  const source: Record<string, unknown> = isObject(summary) ? summary : {};
  const result: Record<string, unknown> = {
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
  const checks: Record<string, boolean> = {};
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
    if (typeof source[field] === 'boolean') checks[field] = source[field] as boolean;
  }
  if (Object.keys(checks).length) result.checks = checks;
  return result;
}

function refusalStatus(result: any): number {
  const reason = safeReason(result?.reason);
  if (reason.includes('unavailable') || reason.includes('storage')) return 503;
  if (reason.includes('replay') || reason.includes('conflict') || reason.includes('mismatch')) return 409;
  return 422;
}

function hasProhibitedPhi(
  value: unknown,
  depth = 0,
  budget: { entries: number } = { entries: 0 },
): string | null {
  if (depth > 8 || budget.entries > 2048) return null;
  if (Array.isArray(value)) {
    for (const nested of value) {
      budget.entries += 1;
      if (budget.entries > 2048) return null;
      const found = hasProhibitedPhi(nested, depth + 1, budget);
      if (found) return found;
    }
    return null;
  }
  if (!isObject(value)) return null;
  for (const [key, nested] of Object.entries(value)) {
    budget.entries += 1;
    if (budget.entries > 2048) return null;
    if (PROHIBITED_PHI_FIELDS.has(key)) return key;
    const found = hasProhibitedPhi(nested, depth + 1, budget);
    if (found) return found;
  }
  return null;
}

// operationId/evidence come from the parsed (untrusted) request body — typed
// `any` deliberately, exactly like the precheck adapter's action handling.
function validateProviderEvidence(operationId: string, evidence: any): { code: string; detail: string } | null {
  if (!isObject(evidence)) {
    return { code: 'missing_provider_evidence', detail: 'authenticated provider evidence is required' };
  }
  const prohibited = hasProhibitedPhi(evidence);
  if (prohibited) return { code: 'prohibited_phi', detail: `provider evidence contains prohibited field: ${prohibited}` };
  if (evidence['@version'] !== PROVIDER_EVIDENCE_VERSION) {
    return { code: 'invalid_provider_evidence', detail: 'provider evidence version is unsupported' };
  }
  for (const field of ['provider_id', 'environment', 'operation_id', 'action_caid', 'idempotency_key', 'outcome']) {
    if (!safeToken(evidence[field])) {
      return { code: 'invalid_provider_evidence', detail: `provider evidence field ${field} is required` };
    }
  }
  if (evidence.operation_id !== operationId) {
    return { code: 'provider_evidence_mismatch', detail: 'provider evidence operation does not match the request' };
  }
  if (!isObject(evidence.signature)
      || evidence.signature.algorithm !== 'Ed25519'
      || !safeToken(evidence.signature.key_id)
      || !safeToken(evidence.signature.value)) {
    return { code: 'provider_evidence_unauthenticated', detail: 'provider evidence must contain a verifiable signature' };
  }
  if (evidence.authenticated === false || evidence.signature.verified === false) {
    return { code: 'provider_evidence_unauthenticated', detail: 'provider evidence authentication failed' };
  }
  return null;
}

function responseForReconciliation(result: any, operationId: string): NextResponse {
  if (!isObject(result) || typeof result.ok !== 'boolean') {
    return problem(503, 'program_integrity_engine_unavailable', 'Program integrity decision service is unavailable');
  }

  const decision = safeDecision(result.decision, result.ok ? null : 'REFUSED');
  if (!decision) {
    return problem(503, 'program_integrity_engine_invalid_result', 'Program integrity returned an invalid reconciliation result');
  }

  const actionCaid = safeToken(result.action_caid);
  const summary = safeEvidenceSummary(result.evidence_summary, { authorizationPresent: true });
  const base: {
    ok: boolean;
    decision: string;
    operation_id: string;
    evidence_summary: Record<string, unknown>;
    action_caid?: string;
    reason?: string;
    previous_decision?: string | null;
    reconciliation_required?: boolean;
    provider_evidence_verified?: boolean;
    idempotent?: boolean;
  } = {
    ok: result.ok === true && SAFE_TERMINAL_DECISIONS.has(decision),
    decision,
    operation_id: operationId,
    evidence_summary: summary,
  };
  if (actionCaid) base.action_caid = actionCaid;

  if (!result.ok) {
    base.reason = safeReason(result.reason);
    base.previous_decision = safeDecision(result.previous_decision, 'INDETERMINATE');
    base.reconciliation_required = true;
    base.provider_evidence_verified = false;
    return json(base, refusalStatus(result));
  }

  // The engine's terminal success is meaningful only if it performed the
  // provider authentication itself. An explicit negative marker is a hard
  // refusal; absence is allowed for the agreed engine contract.
  if (!SAFE_TERMINAL_DECISIONS.has(decision)
      || result.authenticated_provider_evidence === false
      || result.provider_evidence_verified === false) {
    return problem(503, 'program_integrity_engine_invalid_result', 'Provider reconciliation did not produce an authenticated terminal result');
  }

  base.reconciliation_required = false;
  base.provider_evidence_verified = true;
  if (typeof result.idempotent === 'boolean') base.idempotent = result.idempotent;
  return json(base, 200);
}

export async function POST(request: NextRequest): Promise<NextResponse> {
  try {
    const auth = await authenticateRequest(request);
    if (auth?.error) return problem(auth.status || 401, auth.code || 'unauthorized', 'Authentication is required');

    const parsed = await readLimitedJson(request, MAX_BODY_BYTES);
    if (!parsed.ok) return problem(parsed.status, parsed.code, parsed.detail);
    if (!isObject(parsed.value)) return problem(400, 'invalid_body', 'request body must be a JSON object');

    const body = parsed.value;
    if (typeof body.organization_id !== 'string' || body.organization_id.length === 0) {
      return problem(400, 'missing_organization_id', 'organization_id is required for reconciliation');
    }
    const orgResolution = resolveAuthorizedOrg(auth, body.organization_id, { requireBound: true });
    if (orgResolution.error) return problem(orgResolution.error.status, orgResolution.error.code, orgResolution.error.detail);

    const operationId = safeToken(body.operation_id);
    if (!operationId) return problem(400, 'invalid_operation_id', 'operation_id is required');
    const evidenceError = validateProviderEvidence(operationId, body.evidence);
    if (evidenceError) return problem(400, evidenceError.code, evidenceError.detail);

    const result = await getProgramIntegrityEngine().reconcile({
      operation_id: operationId,
      evidence: body.evidence,
      organization_id: orgResolution.organizationId,
    });
    return responseForReconciliation(result, operationId);
  } catch {
    logger.error('[adapter:health.medi-cal.hospice-claim-payment.1.reconcile] failed');
    return problem(503, 'program_integrity_engine_unavailable', 'Program integrity decision service is unavailable');
  }
}
