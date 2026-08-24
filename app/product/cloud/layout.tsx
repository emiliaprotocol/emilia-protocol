import type { Metadata } from 'next';

export const metadata: Metadata = {
  title: 'Gate Cloud Operations Profile | EMILIA',
  description:
    'Review the implemented Gate operations surfaces, the fixed nonproduction pilot, '
    + 'and the separate path to a buyer-accepted production implementation.',
  alternates: { canonical: '/product/cloud' },
  robots: { index: true, follow: true },
  openGraph: {
    title: 'EMILIA Gate Cloud Operations Profile',
    description:
      'Implemented reference operations surfaces, an evidence-bound pilot, and an honest '
      + 'production boundary. Not a generally available managed service.',
    url: 'https://www.emiliaprotocol.ai/product/cloud',
    type: 'website',
  },
  twitter: {
    card: 'summary',
    title: 'EMILIA Gate Cloud Operations Profile',
    description: 'Reference operations surfaces and the path from nonproduction pilot to Gate Implementation.',
  },
  keywords: [
    'AI agent authority control plane',
    'Gate operations reference profile',
    'customer-owned AI authorization',
    'exact-action evidence operations',
  ],
};

export default function CloudProductLayout({ children }: { children: React.ReactNode }) {
  return children;
}
