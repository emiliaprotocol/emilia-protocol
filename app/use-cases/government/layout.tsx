import type { Metadata } from 'next';

export const metadata: Metadata = {
  title: 'Government — Bounded Action-Control Profile',
  description:
    'A bounded EMILIA solution profile for vendor payment destinations, disbursement ' +
    'releases, benefit routing, provider enrollment, and administrative overrides.',
  alternates: { canonical: '/use-cases/government' },
  openGraph: {
    title: 'EMILIA Government Action-Control Profile',
    description:
      'Assess one public-sector consequence boundary with nonproduction evidence before any separate implementation decision.',
    url: 'https://www.emiliaprotocol.ai/use-cases/government',
    type: 'article',
  },
  keywords: [
    'benefit redirection fraud',
    'benefit routing action control',
    'public program payment control',
    'caseworker override control',
    'government action-control assessment',
    'provider enrollment fraud control',
    'grant disbursement approval',
    'government AI controls',
    'NIST AI RMF evidence support',
    'government AI oversight evidence',
  ],
};

export default function GovUseCaseLayout({ children }: { children: React.ReactNode }) {
  return children;
}
