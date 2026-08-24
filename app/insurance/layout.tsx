import type { Metadata } from 'next';

export const metadata: Metadata = {
  title: 'Reliance Risk Evidence for Insurers',
  description:
    'Gate 0.20 adds customer-owned loss terms, open-exposure custody, exact-action '
    + 'refusals, bounded population reconciliation, receipt census, and external '
    + 'loss-feed evidence without making insurance or coverage decisions.',
  alternates: { canonical: '/insurance' },
  openGraph: {
    title: 'EMILIA Reliance Risk Plane — technical evidence for insurers',
    description:
      'Re-perform customer-owned responsibility terms, open exposure, technical '
      + 'refusals, population reconciliation, receipt census, and loss provenance. '
      + 'EMILIA does not insure, adjudicate, prove coverage, or move money.',
    url: 'https://www.emiliaprotocol.ai/insurance',
    type: 'article',
  },
  keywords: [
    'reliance risk evidence',
    'open exposure ledger',
    'loss allocation schedule',
    'exact action refusal statement',
    'receipt census',
    'loss experience provenance',
    'insurance control evidence',
    'AI agent consequence control',
  ],
};

export default function InsuranceLayout({ children }: { children: React.ReactNode }) {
  return children;
}
