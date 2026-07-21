// SPDX-License-Identifier: Apache-2.0
// EMILIA Protocol — POST /api/delegations/create

import { NextResponse, NextRequest } from 'next/server';
import { authenticateRequest } from '@/lib/supabase';
import { authEntityId } from '@/lib/auth-projections.js';
import { createDelegation, EPError } from '@/lib/delegation';
import { checkRateLimit, getClientIP } from '@/lib/rate-limit';
import { EP_ERRORS, epProblem } from '@/lib/errors';
import { readEpJson } from '@/lib/http/route-body';
import { logger } from '../../../../lib/logger.js';

const MAX_BODY_BYTES = 64 * 1024;

export async function POST(request: NextRequest) {
  try {
    const ip = getClientIP(request);
    const rl = await checkRateLimit(ip, 'protocol_write');
    if (!rl.allowed) {
      return EP_ERRORS.RATE_LIMITED();
    }

    // Canonical authentication — not just Bearer prefix check
    const auth = await authenticateRequest(request);
    if (auth.error) return EP_ERRORS.UNAUTHORIZED();

    const parsed = await readEpJson(request, MAX_BODY_BYTES, { invalidValue: {} });
    if (!parsed.ok) return parsed.response;
    const body = parsed.value;
    const { principal_id, agent_entity_id, scope, max_value_usd, expires_at, constraints } = body;

    // Principal must match authenticated entity (no forgery)
    const callerEntityId = authEntityId(auth);

    if (principal_id && callerEntityId && principal_id !== callerEntityId) {
      return epProblem(403, 'not_authorized', 'principal_id must match authenticated entity');
    }

    // Use authenticated entity as principal if not explicitly provided
    const resolvedPrincipalId = principal_id || authEntityId;

    const delegation = await createDelegation({
      principalId: resolvedPrincipalId,
      agentEntityId: agent_entity_id,
      scope,
      maxValueUsd: max_value_usd || null,
      expiresAt: expires_at || null,
      constraints: constraints || null,
    });

    return NextResponse.json(delegation, { status: 201 });
  } catch (err) {
    if (err instanceof EPError) {
      return epProblem(err.status || 400, err.code?.toLowerCase() || 'delegation_error', err.message);
    }
    logger.error('[delegations/create] error:', err);
    return EP_ERRORS.INTERNAL();
  }
}
