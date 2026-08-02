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
    const { agent_entity_id, scope, max_value_usd, expires_at, constraints } = body;
    // Narrowed off `body` (which is `any`) before use. Leaving it untyped is
    // what let `authEntityId` — the FUNCTION — flow into a `principalId: string`
    // parameter below without a compile error.
    const principal_id: string = typeof body?.principal_id === 'string' ? body.principal_id : '';

    // Principal must match authenticated entity (no forgery)
    const callerEntityId = authEntityId(auth);

    if (principal_id && callerEntityId && principal_id !== callerEntityId) {
      return epProblem(403, 'not_authorized', 'principal_id must match authenticated entity');
    }

    // An authenticated request with no resolvable entity identity cannot name a
    // principal, and must not fall through to a delegation with an empty one.
    if (!principal_id && !callerEntityId) {
      return epProblem(403, 'not_authorized', 'authenticated entity has no resolvable identity to act as principal');
    }

    // Use authenticated entity as principal if not explicitly provided.
    // This read the bare identifier `authEntityId` rather than calling it, so
    // the omitted-principal path passed the FUNCTION as principalId. Downstream
    // that (a) made the re-delegation containment query filter
    // `agent_entity_id=eq.function authEntityId(auth){...}`, which matches
    // nothing, so the SCOPE_ESCALATION guard silently found no held scopes to
    // check against, and (b) dropped principal_id from the insert body entirely
    // (JSON.stringify omits function-valued keys), leaving a NOT NULL column
    // constraint as the only thing standing between a caller and a delegation
    // with no principal. An authority boundary does not belong in a DDL check.
    const resolvedPrincipalId = principal_id || callerEntityId;

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
