// SPDX-License-Identifier: Apache-2.0
// EP FinGuard demo adapter — POST /api/v1/adapters/fin/vendor-bank-change/precheck
//
// Pre-filled for the vendor-bank-account-change scenario (AP user
// changes a vendor's bank account before a payment release).

import { runGuardPrecheck } from '@/lib/guard-adapter';
import { GUARD_ACTION_TYPES } from '@/lib/guard-policies';

export async function POST(request) {
  return runGuardPrecheck(request, {
    adapterName: 'fin.vendor-bank-change',
    actionType: GUARD_ACTION_TYPES.VENDOR_BANK_ACCOUNT_CHANGE,
    policyId: 'policy_fin_vendor_bank_change_v1',
    targetResourceField: 'vendor_id',
    defaultChangedFields: ['bank_account', 'routing_number'],
    actorRole: 'ap',
  });
}
