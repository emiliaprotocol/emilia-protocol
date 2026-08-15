import type { Metadata } from 'next';
import HomePageClient from './HomePageClient';

export const metadata: Metadata = {
  title: { absolute: 'Authority System for Autonomous Work | EMILIA' },
  description:
    'AI gave software intelligence. On covered paths, EMILIA puts customer authority in force before '
    + 'autonomous intent changes money, code, permissions, records, or infrastructure.',
  alternates: { canonical: '/' },
  openGraph: {
    title: 'Authority System for Autonomous Work | EMILIA',
    description:
      'Models decide what to do. Humans and institutions decide what may be done. EMILIA Gate enforces the separation.',
    url: 'https://www.emiliaprotocol.ai/',
    type: 'website',
    images: ['/og-sequence.jpg'],
  },
  twitter: {
    card: 'summary_large_image',
    title: 'Authority System for Autonomous Work | EMILIA',
    description:
      'AI gave software intelligence. EMILIA puts authority in force.',
    images: ['/og-sequence.jpg'],
  },
};

export default function HomePage(): React.ReactElement {
  return <HomePageClient />;
}
