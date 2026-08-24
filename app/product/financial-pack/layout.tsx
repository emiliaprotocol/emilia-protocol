import type { Metadata } from 'next';

export const metadata: Metadata = {
  title: 'Finance Authority Reference Profile | EMILIA',
  description:
    'A reference solution profile for exact-action authority at vendor bank-detail '
    + 'changes and payment releases, starting with one fixed nonproduction pilot.',
  alternates: { canonical: '/product/financial-pack' },
  robots: { index: true, follow: true },
  openGraph: {
    title: 'EMILIA Finance Authority Reference Profile',
    description:
      'Map one finance executor boundary, test exact-action authority without production '
      + 'access, and decide whether to proceed to Gate Implementation.',
    url: 'https://www.emiliaprotocol.ai/product/financial-pack',
    type: 'website',
  },
  twitter: {
    card: 'summary',
    title: 'EMILIA Finance Authority Reference Profile',
    description: 'One finance boundary, one fixed pilot, and a separate production implementation decision.',
  },
  keywords: [
    'AI payment authorization control',
    'vendor bank detail change approval',
    'payment release authority',
    'finance agent exact action control',
  ],
};

export default function FinancialPackLayout({ children }: { children: React.ReactNode }) {
  return children;
}
