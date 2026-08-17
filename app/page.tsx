import type { Metadata } from 'next';
import HomePageClient from './HomePageClient';

export const metadata: Metadata = {
  title: { absolute: 'Authority Toll Booth for Autonomous Work | EMILIA' },
  description:
    'At protected boundaries, every consequential agent action enters with customer authority and exits with an action-bound receipt.',
  alternates: { canonical: '/' },
  openGraph: {
    title: 'Authority Toll Booth for Autonomous Work | EMILIA',
    description:
      'Humans define authority. Agents exercise it. EMILIA ensures the agent cannot quietly widen it.',
    url: 'https://www.emiliaprotocol.ai/',
    type: 'website',
    images: ['/emilia-authority-tollbooth-v1.png'],
  },
  twitter: {
    card: 'summary_large_image',
    title: 'Authority Toll Booth for Autonomous Work | EMILIA',
    description:
      'Every consequential agent action enters with authority and exits with a receipt.',
    images: ['/emilia-authority-tollbooth-v1.png'],
  },
};

export default function HomePage(): React.ReactElement {
  return <HomePageClient />;
}
