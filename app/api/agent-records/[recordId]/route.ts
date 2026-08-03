// SPDX-License-Identifier: Apache-2.0
import { NextResponse } from 'next/server';

import { AgentRecordServiceError, loadPublicAgentRecord } from '@/lib/agent-record/service';
import { getAgentRecordRuntimeReadiness } from '@/lib/agent-record/runtime-readiness';
import { epProblem } from '@/lib/errors';
import { logger } from '@/lib/logger.js';

export const dynamic = 'force-dynamic';

const PUBLIC_HEADERS = Object.freeze({
  'Cache-Control': 'no-store, max-age=0',
  Pragma: 'no-cache',
  'Content-Security-Policy': "default-src 'none'; frame-ancestors 'none'",
  'X-Content-Type-Options': 'nosniff',
  'Referrer-Policy': 'no-referrer',
});

function notFound() {
  const response = epProblem(404, 'agent_record_not_found', 'Agent Record not found.');
  for (const [key, value] of Object.entries(PUBLIC_HEADERS)) response.headers.set(key, value);
  return response;
}

export async function GET(
  _request: Request,
  context: { params: Promise<{ recordId: string }> | { recordId: string } },
) {
  try {
    const readiness = await getAgentRecordRuntimeReadiness();
    if (!readiness.ready) {
      const response = epProblem(503, 'agent_record_unavailable', 'Agent Record is temporarily unavailable.');
      for (const [key, value] of Object.entries(PUBLIC_HEADERS)) response.headers.set(key, value);
      return response;
    }
    const { recordId } = await context.params;
    const record = await loadPublicAgentRecord({ recordId });
    if (!record) return notFound();
    return NextResponse.json(record, { headers: PUBLIC_HEADERS });
  } catch (error) {
    if (error instanceof AgentRecordServiceError && error.status === 404) return notFound();
    logger.error('[agent-record] public read failed', { kind: 'agent_record_public_read_failed' });
    const response = epProblem(503, 'agent_record_unavailable', 'Agent Record is temporarily unavailable.');
    for (const [key, value] of Object.entries(PUBLIC_HEADERS)) response.headers.set(key, value);
    return response;
  }
}
