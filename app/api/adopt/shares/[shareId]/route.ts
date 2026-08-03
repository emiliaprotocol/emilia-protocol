// SPDX-License-Identifier: Apache-2.0
import { NextResponse } from 'next/server';

import { epProblem } from '@/lib/errors';
import { adoptionError } from '@/lib/agent-adoption/http';
import { loadPublicAgentAdoptionBond } from '@/lib/agent-adoption/service';

export const dynamic = 'force-dynamic';

export async function GET(
  _request: Request,
  context: { params: Promise<{ shareId: string }> | { shareId: string } },
) {
  try {
    const { shareId } = await context.params;
    const result = await loadPublicAgentAdoptionBond({ shareId });
    if (!result) return epProblem(404, 'agent_adoption_share_not_found', 'Operating Bond not found.');
    return NextResponse.json(result, {
      headers: {
        'Cache-Control': 'no-store, max-age=0',
        Pragma: 'no-cache',
        'Content-Security-Policy': "default-src 'none'; frame-ancestors 'none'",
        'X-Content-Type-Options': 'nosniff',
        'Referrer-Policy': 'no-referrer',
      },
    });
  } catch (error) {
    return adoptionError(error, 'share_read');
  }
}
