import type { Metadata } from 'next';

export const metadata: Metadata = {
  title: 'Government Authority Reference Profile | EMILIA',
  description:
    'Implemented GovGuard reference adapters and evidence boundaries for consequential '
    + 'public-sector actions, without deployment or compliance claims.',
  alternates: { canonical: '/product/government-pack' },
  robots: { index: true, follow: true },
  openGraph: {
    title: 'EMILIA Government Authority Reference Profile',
    description:
      'See what GovGuard implements, what remains designed, and what a real '
      + 'government Gate boundary would still require.',
    url: 'https://www.emiliaprotocol.ai/product/government-pack',
    type: 'website',
  },
  twitter: {
    card: 'summary',
    title: 'EMILIA Government Authority Reference Profile',
    description: 'Reference adapters and explicit boundaries for consequential government actions.',
  },
  keywords: [
    'government AI action authorization',
    'public sector agent authority control',
    'government payment destination control',
    'GovGuard reference profile',
  ],
};

export default function GovernmentPackLayout({ children }: { children: React.ReactNode }) {
  return children;
}
