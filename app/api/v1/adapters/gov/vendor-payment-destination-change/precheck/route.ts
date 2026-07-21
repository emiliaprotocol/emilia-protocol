// SPDX-License-Identifier: Apache-2.0
// EP GovGuard adapter — POST /api/v1/adapters/gov/vendor-payment-destination-change/precheck

import { NextRequest, NextResponse } from 'next/server';
import { runGuardPrecheck } from '@/lib/guard-adapter';
import { GUARD_ACTION_TYPES } from '@/lib/guard-policies';

export async function POST(request: NextRequest): Promise<NextResponse> {
  return runGuardPrecheck(request, {
    adapterName: 'gov.vendor-payment-destination-change',
    actionType: GUARD_ACTION_TYPES.GOV_VENDOR_PAYMENT_DESTINATION_CHANGE,
    policyId: 'policy_gov_vendor_payment_destination_change_v1',
    targetResourceField: 'vendor_id',
    defaultChangedFields: ['bank_account', 'routing_number'],
    actorRole: 'ap',
  });
}
