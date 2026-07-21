// SPDX-License-Identifier: Apache-2.0
// EP GovGuard adapter — POST /api/v1/adapters/gov/eligibility-override/precheck

import { NextRequest, NextResponse } from 'next/server';
import { runGuardPrecheck } from '@/lib/guard-adapter';
import { GUARD_ACTION_TYPES } from '@/lib/guard-policies';

export async function POST(request: NextRequest): Promise<NextResponse> {
  return runGuardPrecheck(request, {
    adapterName: 'gov.eligibility-override',
    actionType: GUARD_ACTION_TYPES.GOV_ELIGIBILITY_OVERRIDE,
    policyId: 'policy_gov_eligibility_override_v1',
    targetResourceField: 'case_id',
    defaultChangedFields: ['eligibility_status', 'benefit_amount'],
    actorRole: 'caseworker',
  });
}
