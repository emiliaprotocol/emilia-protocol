import type { Metadata } from 'next';

export const metadata: Metadata = {
  title: 'Approver Apps — Exact-Action Human Decisions',
  description:
    'Open iOS, Android, Swift, and Kotlin reference clients for CAID-locked exact-action '
    + 'decisions, quorum progress, safe indeterminate outcomes, and portable decision passports.',
  alternates: { canonical: '/product/accountable-signoff' },
  openGraph: {
    title: 'EMILIA Approver Apps',
    description:
      'Gate creates a CAID-locked exact-action challenge. The Approver app captures '
      + 'the device-bound decision and follows its consequence without blind replay.',
    url: 'https://www.emiliaprotocol.ai/product/accountable-signoff',
    type: 'article',
  },
  keywords: [
    'accountable signoff',
    'named human approval',
    'AI action signoff',
    'cryptographic signoff',
    'segregation of duties AI',
    'AI approval app',
    'mobile human authorization',
    'CAID action fingerprint',
    'indeterminate action reconciliation',
  ],
};

export default function AccountableSignoffLayout({ children }: { children: React.ReactNode }) {
  return children;
}
