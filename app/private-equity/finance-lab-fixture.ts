// SPDX-License-Identifier: Apache-2.0

export type FinanceLabAction = Readonly<{
  id: 'vendor-change' | 'payment-release';
  title: string;
  subtitle: string;
  path: string;
  body: (organizationId: string) => Record<string, unknown>;
}>;

export const FINANCE_LAB_COMPANY = 'Northstar Components (fictional, consenting sandbox company)';

export const FINANCE_LAB_ACTIONS: readonly FinanceLabAction[] = [
  {
    id: 'vendor-change',
    title: 'Vendor bank-detail change',
    subtitle: 'AP proposes new masked routing data for vendor_014.',
    path: '/api/v1/adapters/fin/vendor-bank-change/precheck',
    body: (organizationId) => ({
      organization_id: organizationId,
      enforcement_mode: 'observe',
      vendor_id: 'vendor_014',
      target_changed_fields: ['bank_account', 'routing_number'],
      before_state: { bank_account: '****1111', routing_number: '*****021' },
      after_state: { bank_account: '****4021', routing_number: '*****110' },
    }),
  },
  {
    id: 'payment-release',
    title: '$82,000 payment release',
    subtitle: 'Treasury proposes release of a fictional pending instruction.',
    path: '/api/v1/adapters/fin/payment-release/precheck',
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
] as const;
