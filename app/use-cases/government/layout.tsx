import type { Metadata } from 'next';

export const metadata: Metadata = {
  title: 'Government — Pre-Payment Fraud Control',
  description:
    'GovGuard pre-execution control for vendor payment destinations, disbursement ' +
    'releases, benefit routing, provider enrollment, and eligibility overrides. ' +
    'Start with an observe-mode fire drill.',
  alternates: { canonical: '/use-cases/government' },
  openGraph: {
    title: 'EMILIA GovGuard for Government Fraud Control',
    description:
      'Run a government fraud-control fire drill before money or regulated state moves. '
      + 'Evidence packets for controllers, Inspectors General, and auditors.',
    url: 'https://www.emiliaprotocol.ai/use-cases/government',
    type: 'article',
  },
  keywords: [
    'benefit redirection fraud',
    'SNAP fraud prevention',
    'Medicaid fraud prevention',
    'caseworker override control',
    'government fraud control fire drill',
    'provider enrollment fraud control',
    'grant disbursement approval',
    'government AI controls',
    'NIST AI RMF compliance',
    'federal AI executive order',
  ],
};

export default function GovUseCaseLayout({ children }: { children: React.ReactNode }) {
  return children;
}
