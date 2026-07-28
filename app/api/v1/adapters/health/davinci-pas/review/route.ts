// SPDX-License-Identifier: Apache-2.0
/**
 * Authenticated Da Vinci PAS consequence-control boundary.
 *
 * Callers present only a server-side PAS context reference. Raw Claim and
 * ClaimResponse resources are loaded by the relying party after tenant binding
 * and never accepted from the agent-facing request body.
 */

import crypto from 'node:crypto';
import { NextRequest, NextResponse } from 'next/server';
import { authEntityId } from '@/lib/auth-projections.js';
import { epProblem } from '@/lib/errors.js';
import type { DavinciPasConsequenceControl } from '@/lib/health/davinci-pas-consequence-control.js';
import { readLimitedJson } from '@/lib/http/body-limit.js';
import { logger } from '@/lib/logger.js';
import { authenticateRequest } from '@/lib/supabase.js';
import { resolveAuthorizedOrg } from '@/lib/tenant-binding.js';

const MAX_BODY_BYTES = 512 * 1024;
const DIGEST_RE = /^sha256:[a-f0-9]{64}$/;
const DAVINCI_PAS_ROUTE_PROGRAM_DIGEST = `sha256:${crypto
  .createHash('sha256')
  .update('EMILIA-DAVINCI-PAS-CONSEQUENCE-HTTP-BOUNDARY-v1')
  .digest('hex')}`;
const IDENTIFIER_RE = /^[A-Za-z0-9][A-Za-z0-9:_.@/-]{2,255}$/;
const RAW_PAS_ALIASES = new Set([
  'claim',
  'claimresponse',
  'patient',
  'diagnosis',
  'supportinginfo',
  'procedure',
  'clinicalnote',
]);
const TOP_LEVEL_REQUEST_FIELDS = new Set([
  'organization_id',
  'operation',
  'proposal_id',
  'operation_id',
  'pas_context_ref',
  'proposal',
  'approval_evidence',
  'evaluation',
  'provider_evidence',
]);

export const DAVINCI_PAS_CONTROL_KEY = Symbol.for(
  'emilia.health.davinci-pas.proposal-to-effect-control.v1',
);

type Authenticator = (request: NextRequest) => Promise<any>;
type ControlResolver =
  () => DavinciPasConsequenceControl | null | Promise<DavinciPasConsequenceControl | null>;
type PasContextLoader = (input: {
  tenant_id: string;
  operation_id: string;
  pas_context_ref: string;
}) => Promise<unknown> | unknown;

export interface DavinciPasReviewDependencies {
  authenticate?: Authenticator;
  resolve_control?: ControlResolver;
  load_pas_context?: PasContextLoader;
}

function isObject(value: unknown): value is Record<string, any> {
  return value !== null && typeof value === 'object' && !Array.isArray(value);
}

function identifier(value: unknown): value is string {
  return typeof value === 'string' && IDENTIFIER_RE.test(value);
}

function rawPasField(value: unknown, depth = 0): string | null {
  if (depth > 12) return 'input_complexity_limit';
  if (Array.isArray(value)) {
    for (const entry of value) {
      const found = rawPasField(entry, depth + 1);
      if (found) return found;
    }
    return null;
  }
  if (!isObject(value)) return null;
  for (const [key, entry] of Object.entries(value)) {
    const alias = key.normalize('NFKC').toLowerCase().replace(/[^a-z0-9]/g, '');
    if (RAW_PAS_ALIASES.has(alias)) return key;
    const found = rawPasField(entry, depth + 1);
    if (found) return found;
  }
  return null;
}

function noStore(response: NextResponse): NextResponse {
  response.headers.set('cache-control', 'no-store');
  return response;
}

function problem(status: number, code: string, detail: string): NextResponse {
  return noStore(epProblem(status, code, detail));
}

function json(body: unknown, status: number): NextResponse {
  return noStore(NextResponse.json(body, { status }));
}

function defaultControlResolver(): DavinciPasConsequenceControl | null {
  const runtime = globalThis as typeof globalThis & {
    [DAVINCI_PAS_CONTROL_KEY]?: DavinciPasConsequenceControl;
  };
  return runtime[DAVINCI_PAS_CONTROL_KEY] ?? null;
}

function defaultContextLoader(): never {
  throw new Error('pas_context_loader_unavailable');
}

function resultStatus(result: Record<string, any>): number {
  if (result.decision === 'INDETERMINATE') return 202;
  const reason = typeof result.reason === 'string' ? result.reason : '';
  if (/(mismatch|replay|consum|already|operation)/.test(reason)) return 409;
  if (/(unavailable|store|clock)/.test(reason)) return 503;
  return 422;
}

function project(result: Record<string, any>): Record<string, unknown> {
  const allowed = [
    'ok',
    'decision',
    'reason',
    'operation_id',
    'action_caid',
    'attempt',
    'reconciliation_required',
    'retry_safe',
    'authenticated_provider_evidence',
    'provider_evidence_digest',
    'binding',
    'proposal',
    'authorization',
    'challenge',
    'program_digest',
  ];
  const projected = Object.fromEntries(
    allowed
      .filter((field) => Object.hasOwn(result, field))
      .map((field) => [field, structuredClone(result[field])]),
  );
  if (projected.decision === 'REFUSED') {
    projected.program_digest = typeof projected.program_digest === 'string'
        && DIGEST_RE.test(projected.program_digest)
      ? projected.program_digest
      : DAVINCI_PAS_ROUTE_PROGRAM_DIGEST;
  }
  return projected;
}

export function createDavinciPasReviewHandler(
  dependencies: DavinciPasReviewDependencies = {},
) {
  const authenticate = dependencies.authenticate ?? authenticateRequest;
  const resolveControl = dependencies.resolve_control ?? defaultControlResolver;
  const loadPasContext = dependencies.load_pas_context ?? defaultContextLoader;

  return async function davinciPasReview(request: NextRequest): Promise<NextResponse> {
    try {
      const auth = await authenticate(request);
      if (auth?.error) {
        return problem(auth.status || 401, auth.code || 'unauthorized', 'Authentication is required');
      }
      const initiatorId = authEntityId(auth);
      if (!identifier(initiatorId)) {
        return problem(401, 'authenticated_entity_required', 'Authenticated entity is required');
      }
      const parsed = await readLimitedJson(request, MAX_BODY_BYTES);
      if (!parsed.ok) return problem(parsed.status, parsed.code, parsed.detail);
      if (!isObject(parsed.value)) return problem(400, 'invalid_body', 'request body must be a JSON object');
      const body = parsed.value;
      if (rawPasField(body)) {
        return problem(
          400,
          'raw_pas_resources_refused',
          'Raw PAS and clinical resources must be loaded from the authenticated system of record',
        );
      }
      if (Object.keys(body).some((field) => !TOP_LEVEL_REQUEST_FIELDS.has(field))) {
        return problem(
          400,
          'unknown_request_field',
          'request body contains a field outside the Da Vinci PAS review contract',
        );
      }
      if (!identifier(body.organization_id)) {
        return problem(400, 'missing_organization_id', 'organization_id is required');
      }
      const organization = resolveAuthorizedOrg(auth, body.organization_id, { requireBound: true });
      if (organization.error) {
        return problem(
          organization.error.status,
          organization.error.code,
          organization.error.detail,
        );
      }
      const control = await resolveControl();
      if (!control) {
        return problem(503, 'pas_control_unavailable', 'PAS consequence control is not configured');
      }
      let result: Record<string, any>;
      if (body.operation === 'prepare' || body.operation === 'execute') {
        if (!identifier(body.operation_id) || !identifier(body.pas_context_ref)) {
          return problem(
            400,
            'pas_context_reference_required',
            'operation_id and pas_context_ref are required',
          );
        }
        let serverObservedPas: unknown;
        try {
          serverObservedPas = await loadPasContext({
            tenant_id: organization.organizationId!,
            operation_id: body.operation_id,
            pas_context_ref: body.pas_context_ref,
          });
        } catch {
          return problem(503, 'pas_context_unavailable', 'PAS system-of-record context is unavailable');
        }
        if (body.operation === 'prepare') {
          if (!identifier(body.proposal_id)) {
            return problem(400, 'proposal_id_required', 'proposal_id is required');
          }
          result = await control.prepare({
            tenant_id: organization.organizationId!,
            initiator_id: initiatorId,
            proposal_id: body.proposal_id,
            operation_id: body.operation_id,
            server_observed_pas: serverObservedPas,
          });
          return json(project(result), result.ok === true ? 201 : resultStatus(result));
        }
        if (!isObject(body.proposal)
            || !isObject(body.approval_evidence)
            || !isObject(body.evaluation)) {
          return problem(
            400,
            'incomplete_execute_request',
            'proposal, approval_evidence, and evaluation are required',
          );
        }
        result = await control.execute({
          tenant_id: organization.organizationId!,
          proposal: body.proposal,
          approval_evidence: body.approval_evidence,
          evaluation: body.evaluation,
          server_observed_pas: serverObservedPas,
        });
        return json(project(result), result.ok === true ? 200 : resultStatus(result));
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
        return json(project(result), result.ok === true ? 200 : resultStatus(result));
      }
      return problem(400, 'unsupported_operation', 'operation must be prepare, execute, or reconcile');
    } catch {
      logger.error('[adapter:health.davinci-pas.consequence-control] failed');
      return problem(503, 'pas_control_unavailable', 'PAS consequence control is unavailable');
    }
  };
}

export const POST = createDavinciPasReviewHandler();
