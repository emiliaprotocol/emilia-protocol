// SPDX-License-Identifier: Apache-2.0
// EP GovGuard demo adapter — POST /api/v1/adapters/gov/benefit-bank-change/precheck
//
// Thin façade over /api/v1/trust-receipts pre-filled for the
// benefit-bank-account-change scenario. All real logic lives in
// lib/guard-adapter.js. Adding a new adapter is a 10-line file: pick
// action_type + policy_id + the body field that names the target
// resource, and the shared helper handles auth, hashing, policy eval,
// audit emission, and response shape.

import { runGuardPrecheck } from '@/lib/guard-adapter';
import { GUARD_ACTION_TYPES } from '@/lib/guard-policies';

export async function POST(request) {
  return runGuardPrecheck(request, {
    adapterName: 'gov.benefit-bank-change',
    actionType: GUARD_ACTION_TYPES.BENEFIT_BANK_ACCOUNT_CHANGE,
    policyId: 'policy_gov_benefit_bank_change_v1',
    targetResourceField: 'recipient_id',
    defaultChangedFields: ['bank_account', 'routing_number'],
    actorRole: 'caseworker',
  });
}
