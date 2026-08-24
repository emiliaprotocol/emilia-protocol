import type { Metadata } from 'next';

export const metadata: Metadata = {
  title: 'Terms of Service — EMILIA Protocol',
  description:
    'Terms governing use of the emiliaprotocol.ai website, public prototypes, ' +
    'documentation, and inquiry interfaces.',
  alternates: { canonical: '/legal/terms' },
  openGraph: {
    title: 'EMILIA Protocol Terms of Service',
    description: 'Terms for the website, public prototypes, documentation, and inquiry interfaces.',
    url: 'https://www.emiliaprotocol.ai/legal/terms',
    type: 'article',
  },
};

export default function TermsLayout({ children }: { children: React.ReactNode }) {
  return children;
}
