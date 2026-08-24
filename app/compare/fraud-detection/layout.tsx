import type { Metadata } from 'next';

export const metadata: Metadata = {
  title: 'Exact-Action Authority and Fraud Detection',
  description:
    'Fraud controls may score, hold, reject, or investigate activity. EMILIA adds ' +
    'a separate exact-action authority condition at a completely mediated executor boundary.',
  alternates: { canonical: '/compare/fraud-detection' },
  openGraph: {
    title: 'Exact-Action Authority and Fraud Detection',
    description:
      'How fraud controls and a separate exact-action authority boundary compose for consequential actions.',
    url: 'https://www.emiliaprotocol.ai/compare/fraud-detection',
    type: 'article',
  },
  keywords: [
    'fraud detection vs prevention',
    'pre-action authorization',
    'fraud detection and authorization',
    'wire fraud prevention',
    'BEC defense',
    'AI agent authority control',
    'transaction monitoring vs authorization',
  ],
};

export default function CompareFraudLayout({ children }: { children: React.ReactNode }) {
  return children;
}
