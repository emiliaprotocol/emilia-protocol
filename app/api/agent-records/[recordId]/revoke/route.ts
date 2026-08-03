// SPDX-License-Identifier: Apache-2.0
import { NextResponse } from 'next/server';

import { AgentRecordServiceError, revokeAgentRecord } from '@/lib/agent-record/service';
import { getAgentRecordRuntimeReadiness } from '@/lib/agent-record/runtime-readiness';
import { epProblem } from '@/lib/errors';
import { logger } from '@/lib/logger.js';

export const dynamic = 'force-dynamic';
const OWNER_TOKEN = /^ear1_[0-9a-f]{64}$/;

const NO_STORE_HEADERS = Object.freeze({
  'Cache-Control': 'no-store, max-age=0',
  Pragma: 'no-cache',
  'X-Content-Type-Options': 'nosniff',
  'Referrer-Policy': 'no-referrer',
});

function notFound() {
  const response = epProblem(404, 'agent_record_not_found', 'Agent Record not found.');
  for (const [key, value] of Object.entries(NO_STORE_HEADERS)) response.headers.set(key, value);
  return response;
}

export async function POST(
  request: Request,
  context: { params: Promise<{ recordId: string }> | { recordId: string } },
) {
  let expectedOrigin = '';
  try {
    expectedOrigin = new URL(request.url).origin;
  } catch {
    expectedOrigin = '';
  }
  if (!expectedOrigin || request.headers.get('origin') !== expectedOrigin) {
    const response = epProblem(403, 'agent_record_origin_denied', 'Agent Record revocation requires an exact same-origin request.');
    for (const [key, value] of Object.entries(NO_STORE_HEADERS)) response.headers.set(key, value);
    return response;
  }

  const header = request.headers.get('authorization') ?? '';
  const ownerToken = header.startsWith('Bearer ') ? header.slice(7) : '';
  if (!OWNER_TOKEN.test(ownerToken)) return notFound();

  try {
    const readiness = await getAgentRecordRuntimeReadiness();
    if (!readiness.ready) {
      const response = epProblem(503, 'agent_record_unavailable', 'Agent Record is temporarily unavailable.');
      for (const [key, value] of Object.entries(NO_STORE_HEADERS)) response.headers.set(key, value);
      return response;
    }
    const { recordId } = await context.params;
    const result = await revokeAgentRecord({ recordId, ownerToken });
    return NextResponse.json(result, { headers: NO_STORE_HEADERS });
  } catch (error) {
    if (error instanceof AgentRecordServiceError && error.status < 500) return notFound();
    logger.error('[agent-record] revocation failed', { kind: 'agent_record_revocation_failed' });
    const response = epProblem(503, 'agent_record_unavailable', 'Agent Record is temporarily unavailable.');
    for (const [key, value] of Object.entries(NO_STORE_HEADERS)) response.headers.set(key, value);
    return response;
  }
}
