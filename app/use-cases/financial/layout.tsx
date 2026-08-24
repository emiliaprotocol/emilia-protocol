import type { Metadata } from 'next';

export const metadata: Metadata = {
  title: 'Financial — Protected-Workflow Solution Profile',
  description:
    'A bounded EMILIA solution profile for vendor bank-detail changes, beneficiary updates, ' +
    'and payment releases on completely mediated covered paths.',
  alternates: { canonical: '/use-cases/financial' },
  openGraph: {
    title: 'EMILIA Financial Protected-Workflow Profile',
    description:
      'Exact-action authority and evidence checks for one completely mediated treasury workflow.',
    url: 'https://www.emiliaprotocol.ai/use-cases/financial',
    type: 'article',
  },
  keywords: [
    'wire transfer action control',
    'vendor bank change fraud',
    'beneficiary swap fraud',
    'AI voice fraud defense',
    'BEC control evidence',
    'SOX control-testing evidence',
    'community bank fraud defense',
    'treasury action authorization',
  ],
};

export default function FinUseCaseLayout({ children }: { children: React.ReactNode }) {
  return children;
}
