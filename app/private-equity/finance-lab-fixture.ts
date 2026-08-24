// SPDX-License-Identifier: Apache-2.0

export type FinanceLabScenario = Readonly<{
  id: 'single_signoff' | 'dual_signoff' | 'hard_refusal';
  title: string;
  subtitle: string;
  amountLabel: string;
  expectedObservation: string;
  path: string;
  body: (organizationId: string) => Record<string, unknown>;
}>;

export const FINANCE_LAB_COMPANY = 'Northstar Components (fictional, consenting sandbox company)';
export const FINANCE_LAB_BOUNDARY = 'Payment release at the finance provider';
export const FINANCE_LAB_PATH = '/api/v1/adapters/fin/payment-release/precheck';

export const FINANCE_LAB_SCENARIOS: readonly FinanceLabScenario[] = [
  {
    id: 'single_signoff',
    title: 'Standard high-value release',
    subtitle: 'Treasury proposes one fictional $82,000 payment release.',
    amountLabel: '$82,000',
    expectedObservation: 'One accountable signoff required',
    path: FINANCE_LAB_PATH,
    body: (organizationId) => ({
      organization_id: organizationId,
      enforcement_mode: 'observe',
      payment_instruction_id: 'pi_northstar_082',
      counterparty_name: 'Northstar Demo Vendor',
      amount: 82_000,
      currency: 'USD',
      before_state: { status: 'pending' },
      after_state: { status: 'released' },
    }),
  },
  {
    id: 'dual_signoff',
    title: 'Seven-figure release',
    subtitle: 'Treasury proposes one fictional $1.25 million payment release.',
    amountLabel: '$1,250,000',
    expectedObservation: 'Dual accountable signoff required',
    path: FINANCE_LAB_PATH,
    body: (organizationId) => ({
      organization_id: organizationId,
      enforcement_mode: 'observe',
      payment_instruction_id: 'pi_northstar_1250',
      counterparty_name: 'Northstar Demo Vendor',
      amount: 1_250_000,
      currency: 'USD',
      before_state: { status: 'pending' },
      after_state: { status: 'released' },
    }),
  },
  {
    id: 'hard_refusal',
    title: 'Compromised-device signal',
    subtitle: 'The same fictional $82,000 release carries a hard-deny risk flag.',
    amountLabel: '$82,000',
    expectedObservation: 'Rule refuses the action',
    path: FINANCE_LAB_PATH,
    body: (organizationId) => ({
      organization_id: organizationId,
      enforcement_mode: 'observe',
      payment_instruction_id: 'pi_northstar_refuse',
      counterparty_name: 'Northstar Demo Vendor',
      amount: 82_000,
      currency: 'USD',
      risk_flags: ['known_compromised_device'],
      before_state: { status: 'pending' },
      after_state: { status: 'released' },
    }),
  },
] as const;
