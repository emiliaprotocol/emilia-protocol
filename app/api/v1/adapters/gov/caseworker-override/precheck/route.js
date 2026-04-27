// SPDX-License-Identifier: Apache-2.0
// EP GovGuard demo adapter — POST /api/v1/adapters/gov/caseworker-override/precheck
//
// Pre-filled for the caseworker-override scenario (operator overrides
// auto-disqualification on a benefit case). The policy engine routes
// caseworker_override unconditionally to ALLOW_WITH_SIGNOFF.

import { runGuardPrecheck } from '@/lib/guard-adapter';
import { GUARD_ACTION_TYPES } from '@/lib/guard-policies';

export async function POST(request) {
  return runGuardPrecheck(request, {
    adapterName: 'gov.caseworker-override',
    actionType: GUARD_ACTION_TYPES.CASEWORKER_OVERRIDE,
    policyId: 'policy_gov_caseworker_override_v1',
    targetResourceField: 'case_id',
    defaultChangedFields: [],
    actorRole: 'caseworker',
  });
}
