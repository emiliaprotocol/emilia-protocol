// SPDX-License-Identifier: Apache-2.0
// EP GovGuard adapter — POST /api/v1/adapters/gov/benefit-address-change/precheck

import { runGuardPrecheck } from '@/lib/guard-adapter';
import { GUARD_ACTION_TYPES } from '@/lib/guard-policies';

export async function POST(request) {
  return runGuardPrecheck(request, {
    adapterName: 'gov.benefit-address-change',
    actionType: GUARD_ACTION_TYPES.BENEFIT_ADDRESS_CHANGE,
    policyId: 'policy_gov_benefit_address_change_v1',
    targetResourceField: 'recipient_id',
    defaultChangedFields: ['mailing_address'],
    actorRole: 'caseworker',
  });
}
