import { NextResponse } from 'next/server';

import { getAgentRecordRuntimeReadiness } from '@/lib/agent-record/runtime-readiness';

export const dynamic = 'force-dynamic';

const NO_STORE_HEADERS = Object.freeze({
  'Cache-Control': 'no-store, no-cache, must-revalidate',
});

/**
 * GET /api/health
 *
 * Public application-readiness endpoint. It proves the operated Agent Record
 * dependencies and database RPC contract without disclosing which check failed.
 */
export async function GET(): Promise<NextResponse> {
  let ready = false;
  try {
    ready = (await getAgentRecordRuntimeReadiness()).ready === true;
  } catch {
    ready = false;
  }

  return NextResponse.json(
    { status: ready ? 'ready' : 'not_ready' },
    {
      status: ready ? 200 : 503,
      headers: NO_STORE_HEADERS,
    },
  );
}
