// SPDX-License-Identifier: Apache-2.0
/**
 * Authenticated export for a tenant-bound, PHI-free healthcare assurance
 * packet assembled from the append-only consequence-control evidence store.
 */

import { NextRequest, NextResponse } from 'next/server';
import { epProblem } from '@/lib/errors.js';
import type { HealthcareConsequenceControl } from '@/lib/health/proposal-to-effect-profile.js';
import { logger } from '@/lib/logger.js';
import { authenticateRequest } from '@/lib/supabase.js';
import { resolveAuthorizedOrg } from '@/lib/tenant-binding.js';

const IDENTIFIER_RE = /^[A-Za-z0-9][A-Za-z0-9:_.@/-]{2,255}$/;
const HEALTHCARE_CONTROL_KEY = Symbol.for(
  'emilia.health.hospice-claim.proposal-to-effect-control.v1',
);

type Authenticator = (request: NextRequest) => Promise<any>;
type ControlResolver =
  () => HealthcareConsequenceControl | null | Promise<HealthcareConsequenceControl | null>;

export interface HospiceClaimExportDependencies {
  authenticate?: Authenticator;
  resolve_control?: ControlResolver;
}

function identifier(value: unknown): value is string {
  return typeof value === 'string' && IDENTIFIER_RE.test(value);
}

function noStore(response: NextResponse): NextResponse {
  response.headers.set('cache-control', 'no-store');
  return response;
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

export function createHospiceClaimExportHandler(
  dependencies: HospiceClaimExportDependencies = {},
) {
  const authenticate = dependencies.authenticate ?? authenticateRequest;
  const resolveControl = dependencies.resolve_control ?? defaultControlResolver;

  return async function hospiceClaimExport(request: NextRequest): Promise<NextResponse> {
    try {
      const auth = await authenticate(request);
      if (auth?.error) {
        return problem(
          auth.status || 401,
          auth.code || 'unauthorized',
          'Authentication is required',
        );
      }
      const url = new URL(request.url);
      const organizationId = url.searchParams.get('organization_id') ?? undefined;
      const operationId = url.searchParams.get('operation_id');
      if (!identifier(organizationId) || !identifier(operationId)) {
        return problem(
          400,
          'incomplete_assurance_export_request',
          'organization_id and operation_id are required',
        );
      }
      const organization = resolveAuthorizedOrg(
        auth,
        organizationId,
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
      const packet = await control.exportAssurancePacket({
        tenant_id: organization.organizationId!,
        operation_id: operationId,
      });
      if (packet?.ok === false) {
        const reason = typeof packet.reason === 'string'
          ? packet.reason
          : 'healthcare_assurance_packet_not_available';
        const status = reason.includes('unavailable') ? 503 : 404;
        return problem(status, reason, 'Healthcare assurance packet is not available');
      }
      const response = NextResponse.json(packet, { status: 200 });
      response.headers.set(
        'content-disposition',
        `attachment; filename="healthcare-assurance-${encodeURIComponent(operationId)}.json"`,
      );
      return noStore(response);
    } catch {
      logger.error('[adapter:health.hospice-claim.proposal-to-effect.export] failed');
      return problem(
        503,
        'healthcare_assurance_export_unavailable',
        'Healthcare assurance export is unavailable',
      );
    }
  };
}

export const GET = createHospiceClaimExportHandler();
