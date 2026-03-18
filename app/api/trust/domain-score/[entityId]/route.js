// SPDX-License-Identifier: Apache-2.0
// EMILIA Protocol — GET /api/trust/domain-score/[entityId]

import { NextResponse } from 'next/server';
import { getDomainScores } from '@/lib/domain-scoring';
import { EP_ERRORS } from '@/lib/errors';

export async function GET(request, { params }) {
  try {
    const { entityId } = params;
    const url = new URL(request.url);
    const domainsParam = url.searchParams.get('domains');
    const domains = domainsParam ? domainsParam.split(',').map(d => d.trim()).filter(Boolean) : null;

    const result = await getDomainScores(entityId, domains);
    return NextResponse.json(result);
  } catch (err) {
    console.error('[trust/domain-score] error:', err);
    return EP_ERRORS.INTERNAL();
  }
}
