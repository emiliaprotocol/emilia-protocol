// SPDX-License-Identifier: Apache-2.0

import { NextRequest, NextResponse } from 'next/server';
import { epProblem } from '@/lib/errors.js';
import type { DavinciPasConsequenceControl } from '@/lib/health/davinci-pas-consequence-control.js';
import { logger } from '@/lib/logger.js';
import { authenticateRequest } from '@/lib/supabase.js';
import { resolveAuthorizedOrg } from '@/lib/tenant-binding.js';
import { DAVINCI_PAS_CONTROL_KEY } from '../review/route.js';

const IDENTIFIER_RE = /^[A-Za-z0-9][A-Za-z0-9:_.@/-]{2,255}$/;
type Authenticator = (request: NextRequest) => Promise<any>;
type ControlResolver =
  () => DavinciPasConsequenceControl | null | Promise<DavinciPasConsequenceControl | null>;

export interface DavinciPasExportDependencies {
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

function defaultControlResolver(): DavinciPasConsequenceControl | null {
  const runtime = globalThis as typeof globalThis & {
    [DAVINCI_PAS_CONTROL_KEY]?: DavinciPasConsequenceControl;
  };
  return runtime[DAVINCI_PAS_CONTROL_KEY] ?? null;
}

export function createDavinciPasExportHandler(
  dependencies: DavinciPasExportDependencies = {},
) {
  const authenticate = dependencies.authenticate ?? authenticateRequest;
  const resolveControl = dependencies.resolve_control ?? defaultControlResolver;
  return async function davinciPasExport(request: NextRequest): Promise<NextResponse> {
    try {
      const auth = await authenticate(request);
      if (auth?.error) {
        return problem(auth.status || 401, auth.code || 'unauthorized', 'Authentication is required');
      }
      const url = new URL(request.url);
      const organizationId = url.searchParams.get('organization_id') ?? undefined;
      const operationId = url.searchParams.get('operation_id');
      if (!identifier(organizationId) || !identifier(operationId)) {
        return problem(
          400,
          'incomplete_pas_export_request',
          'organization_id and operation_id are required',
        );
      }
      const organization = resolveAuthorizedOrg(auth, organizationId, { requireBound: true });
      if (organization.error) {
        return problem(
          organization.error.status,
          organization.error.code,
          organization.error.detail,
        );
      }
      const control = await resolveControl();
      if (!control) return problem(503, 'pas_control_unavailable', 'PAS consequence control is not configured');
      const packet = await control.exportReliancePacket({
        tenant_id: organization.organizationId!,
        operation_id: operationId,
      });
      if (packet?.ok === false) {
        const reason = typeof packet.reason === 'string'
          ? packet.reason
          : 'pas_export_unavailable';
        if (reason === 'pas_reliance_packet_not_available') {
          return problem(404, reason, 'PAS reliance packet is not available');
        }
        return problem(503, reason, 'PAS reliance packet export is unavailable');
      }
      const response = NextResponse.json(packet, { status: 200 });
      response.headers.set(
        'content-disposition',
        `attachment; filename="pas-consequence-${encodeURIComponent(operationId)}.json"`,
      );
      return noStore(response);
    } catch {
      logger.error('[adapter:health.davinci-pas.consequence-control.export] failed');
      return problem(503, 'pas_export_unavailable', 'PAS reliance packet export is unavailable');
    }
  };
}

export const GET = createDavinciPasExportHandler();
