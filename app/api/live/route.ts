// SPDX-License-Identifier: Apache-2.0
import { NextResponse } from 'next/server';

export const dynamic = 'force-dynamic';

/** Process-only liveness. Dependency and schema readiness belongs to /api/health. */
export async function GET(): Promise<NextResponse> {
  return NextResponse.json(
    { status: 'live' },
    {
      headers: {
        'Cache-Control': 'no-store, no-cache, must-revalidate',
      },
    },
  );
}
