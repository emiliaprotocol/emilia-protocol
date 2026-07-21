// SPDX-License-Identifier: Apache-2.0
// EP GovGuard adapter — POST /api/v1/adapters/gov/disbursement-release/precheck

import { NextRequest, NextResponse } from 'next/server';
import { runGuardPrecheck } from '@/lib/guard-adapter';
import { GUARD_ACTION_TYPES } from '@/lib/guard-policies';

export async function POST(request: NextRequest): Promise<NextResponse> {
  return runGuardPrecheck(request, {
    adapterName: 'gov.disbursement-release',
    actionType: GUARD_ACTION_TYPES.GOV_DISBURSEMENT_RELEASE,
    policyId: 'policy_gov_disbursement_release_v1',
    targetResourceField: 'payment_instruction_id',
    defaultChangedFields: [],
    actorRole: 'treasury',
  });
}
