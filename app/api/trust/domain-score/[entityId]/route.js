// SPDX-License-Identifier: Apache-2.0
// EMILIA Protocol — GET /api/trust/domain-score/[entityId]

import { NextResponse } from 'next/server';
import { getDomainScores, KNOWN_DOMAINS } from '@/lib/domain-scoring';
import { EP_ERRORS, epProblem } from '@/lib/errors';
import { authenticateRequest, authEntityId } from '@/lib/supabase';
import { logger } from '../../../../../lib/logger.js';

export async function GET(request, { params }) {
  try {
    const auth = await authenticateRequest(request);
    if (auth.error) return epProblem(auth.status || 401, auth.code || 'unauthorized', auth.error);

    const { entityId } = await params;
    const actorId = authEntityId(auth);
    if (actorId !== entityId) {
      return EP_ERRORS.FORBIDDEN('Domain scores require authorization for the requested entity');
    }

    const url = new URL(request.url);
    const domainsParam = url.searchParams.get('domains');
    const domains = domainsParam ? domainsParam.split(',').map(d => d.trim()).filter(Boolean) : null;

    // Constrain `domains` to the known taxonomy — an arbitrary value would let a
    // caller probe for non-standard task_type buckets that exist in the data but
    // aren't part of the public domain set.
    if (domains && !domains.every(d => KNOWN_DOMAINS.includes(d))) {
      return epProblem(400, 'invalid_domain', `domains must be a subset of: ${KNOWN_DOMAINS.join(', ')}`);
    }

    const result = await getDomainScores(entityId, domains);
    return NextResponse.json(result);
  } catch (err) {
    logger.error('[trust/domain-score] error:', err);
    return EP_ERRORS.INTERNAL();
  }
}
