import { NextResponse } from 'next/server';

/**
 * GET /api/health
 *
 * Public liveness endpoint. Deliberately returns no route inventory,
 * infrastructure names, queue depths, schema versions, or usage counts.
 */
export async function GET() {
  return NextResponse.json({ status: 'ok' });
}
