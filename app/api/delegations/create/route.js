// SPDX-License-Identifier: Apache-2.0
// EMILIA Protocol — POST /api/delegations/create

import { NextResponse } from 'next/server';
import { createDelegation, EPError } from '@/lib/delegation';
import { checkRateLimit, getClientIP } from '@/lib/rate-limit';
import { EP_ERRORS } from '@/lib/errors';

export async function POST(request) {
  try {
    const ip = getClientIP(request);
    const rl = await checkRateLimit(ip, 'write');
    if (!rl.allowed) {
      return EP_ERRORS.RATE_LIMITED();
    }

    // Auth: require API key (Bearer token)
    const authHeader = request.headers.get('authorization') || '';
    if (!authHeader.startsWith('Bearer ')) {
      return EP_ERRORS.UNAUTHORIZED();
    }

    const body = await request.json().catch(() => ({}));
    const { principal_id, agent_entity_id, scope, max_value_usd, expires_at, constraints } = body;

    const delegation = await createDelegation({
      principalId: principal_id,
      agentEntityId: agent_entity_id,
      scope,
      maxValueUsd: max_value_usd || null,
      expiresAt: expires_at || null,
      constraints: constraints || null,
    });

    return NextResponse.json(delegation, { status: 201 });
  } catch (err) {
    if (err instanceof EPError) {
      return NextResponse.json({ error: err.message, code: err.code }, { status: err.status || 400 });
    }
    console.error('[delegations/create] error:', err);
    return EP_ERRORS.INTERNAL();
  }
}
