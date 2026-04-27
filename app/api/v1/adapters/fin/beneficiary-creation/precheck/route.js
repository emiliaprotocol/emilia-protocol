// SPDX-License-Identifier: Apache-2.0
// EP FinGuard demo adapter — POST /api/v1/adapters/fin/beneficiary-creation/precheck
//
// Pre-filled for the beneficiary-creation scenario (a new SWIFT-eligible
// counterparty is added to the treasury system). Defaults the changed
// fields to bank_account + iban + swift_bic so any of those trip the
// money-destination guard.

import { runGuardPrecheck } from '@/lib/guard-adapter';
import { GUARD_ACTION_TYPES } from '@/lib/guard-policies';

export async function POST(request) {
  return runGuardPrecheck(request, {
    adapterName: 'fin.beneficiary-creation',
    actionType: GUARD_ACTION_TYPES.BENEFICIARY_CREATION,
    policyId: 'policy_fin_beneficiary_creation_v1',
    targetResourceField: 'beneficiary_id',
    defaultChangedFields: ['bank_account', 'iban', 'swift_bic', 'beneficiary_name'],
    actorRole: 'treasury',
  });
}
