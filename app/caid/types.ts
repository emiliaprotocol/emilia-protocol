// SPDX-License-Identifier: Apache-2.0

export type CaidDemoInput = {
  amount: string;
  destinationReference: string;
};

export type CaidDemoAction = {
  action_type: 'payment.release.1';
  amount: string;
  currency: 'USD';
  beneficiary_account: string;
  payment_instruction_id: 'pi-demo-1042';
};

export type CaidComparison = {
  approvedCaid: string;
  proposedCaid: string;
  recomputedCaid: string;
  matchesApprovedAction: boolean;
  changedFields: Array<'amount' | 'destination'>;
  canonicalAction: CaidDemoAction;
};

export const BASELINE_CAID_INPUT: Readonly<CaidDemoInput> = Object.freeze({
  amount: '82000.00',
  destinationReference: 'Acme Supply / settlement / account 7834',
});
