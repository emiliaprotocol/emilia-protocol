import type { Metadata } from 'next';

export const metadata: Metadata = {
  title: 'Financial — Wire Fraud + AI-Voice Defense',
  description:
    'Pre-execution authorization for wire transfers, vendor-bank-change, ' +
    'beneficiary updates, and high-value payment release. On completely mediated ' +
    'covered paths, refuse provider entry without accepted exact-action authority ' +
    'and required evidence.',
  alternates: { canonical: '/use-cases/financial' },
  openGraph: {
    images: ['/opengraph-image'],
    title: 'EMILIA FinGuard — AI-Era Fraud Defense',
    description:
      'Action-bound authority for vendor-bank changes and payment releases at ' +
      'buyer-configured treasury boundaries.',
    url: 'https://www.emiliaprotocol.ai/use-cases/financial',
    type: 'article',
  },
  keywords: [
    'wire transfer fraud prevention',
    'vendor bank change fraud',
    'beneficiary swap fraud',
    'AI voice fraud defense',
    'BEC prevention',
    'SOX AI controls',
    'community bank fraud defense',
    'treasury action authorization',
  ],
};

export default function FinUseCaseLayout({ children }: { children: React.ReactNode }) {
  return children;
}
