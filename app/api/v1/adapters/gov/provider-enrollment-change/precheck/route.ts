// SPDX-License-Identifier: Apache-2.0
// EP GovGuard adapter — POST /api/v1/adapters/gov/provider-enrollment-change/precheck

import { NextRequest, NextResponse } from 'next/server';
import { runGuardPrecheck } from '@/lib/guard-adapter';
import { GUARD_ACTION_TYPES } from '@/lib/guard-policies';

export async function POST(request: NextRequest): Promise<NextResponse> {
  return runGuardPrecheck(request, {
    adapterName: 'gov.provider-enrollment-change',
    actionType: GUARD_ACTION_TYPES.GOV_PROVIDER_ENROLLMENT_CHANGE,
    policyId: 'policy_gov_provider_enrollment_change_v1',
    targetResourceField: 'provider_id',
    defaultChangedFields: ['provider_status', 'payment_address'],
    actorRole: 'program_integrity',
  });
}
