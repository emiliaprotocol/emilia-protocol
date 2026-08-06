import type { Metadata } from 'next';
import HomePageClient from './HomePageClient';

export const metadata: Metadata = {
  title: 'EMILIA Authority Brain — See and Control Consequential AI Actions',
  description:
    'Run a local Authority Map of visible AI-agent actions, review where exact authority is missing, '
    + 'and place EMILIA Gate in front of one consequential workflow.',
  alternates: { canonical: '/' },
  openGraph: {
    title: 'EMILIA Authority Brain — See Where Your AI Can Act',
    description:
      'Discover visible consequential actions locally, name the blind spots, and protect one workflow with exact-action authority.',
    url: 'https://www.emiliaprotocol.ai/',
    type: 'website',
  },
  twitter: {
    card: 'summary_large_image',
    title: 'EMILIA Authority Brain — See Where Your AI Can Act',
    description:
      'The scanner proposes. The owner reviews. Gate enforces.',
  },
};

export default function HomePage(): React.ReactElement {
  return <HomePageClient />;
}
