import type { Metadata } from 'next';

export const metadata: Metadata = {
  title: 'Experimental Public Registry and Receipt Exploration',
  description:
    'A nonproduction surface for exploring reference registry records and supported '
    + 'authorization-receipt verification. It is not a verified-entity or adoption claim.',
  alternates: { canonical: '/network' },
  robots: { index: false, follow: false, nocache: true },
  openGraph: {
    title: 'Experimental EMILIA Registry and Receipt Exploration',
    description: 'Inspect nonproduction reference records and the precise verification boundary of supported receipt artifacts.',
    url: 'https://www.emiliaprotocol.ai/network',
    type: 'website',
  },
  keywords: ['experimental agent registry', 'authorization receipt verification', 'EMILIA sandbox'],
};

export default function NetworkLayout({ children }: { children: React.ReactNode }) {
  return children;
}
