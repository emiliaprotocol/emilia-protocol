// SPDX-License-Identifier: Apache-2.0
// EP GovGuard adapter — POST /api/v1/adapters/gov/grant-disbursement/precheck

import { runGuardPrecheck } from '@/lib/guard-adapter';
import { GUARD_ACTION_TYPES } from '@/lib/guard-policies';

export async function POST(request) {
  return runGuardPrecheck(request, {
    adapterName: 'gov.grant-disbursement',
    actionType: GUARD_ACTION_TYPES.GOV_GRANT_DISBURSEMENT,
    policyId: 'policy_gov_grant_disbursement_v1',
    targetResourceField: 'grant_id',
    defaultChangedFields: [],
    actorRole: 'program_officer',
  });
}
