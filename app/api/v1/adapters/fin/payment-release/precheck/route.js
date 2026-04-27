// SPDX-License-Identifier: Apache-2.0
// EP FinGuard demo adapter — POST /api/v1/adapters/fin/payment-release/precheck
//
// Pre-filled for the large-payment-release scenario. The threshold-based
// signoff requirement comes from the policy engine, not the adapter:
// passing `amount >= 50000` in the body trips the LARGE_PAYMENT_RELEASE
// signoff branch in lib/guard-policies.js.

import { runGuardPrecheck } from '@/lib/guard-adapter';
import { GUARD_ACTION_TYPES } from '@/lib/guard-policies';

export async function POST(request) {
  return runGuardPrecheck(request, {
    adapterName: 'fin.payment-release',
    actionType: GUARD_ACTION_TYPES.LARGE_PAYMENT_RELEASE,
    policyId: 'policy_fin_payment_release_v1',
    targetResourceField: 'payment_instruction_id',
    defaultChangedFields: [],
    actorRole: 'treasury',
  });
}
