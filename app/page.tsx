import type { Metadata } from 'next';
import HomePageClient from './HomePageClient';

export const metadata: Metadata = {
  title: { absolute: 'Authority Toll Booth for Autonomous Work | EMILIA' },
  description:
    'At configured protected boundaries, consequential agent actions must present customer authority before provider entry, and the result leaves an action-bound record.',
  alternates: { canonical: '/' },
  openGraph: {
    title: 'Authority Toll Booth for Autonomous Work | EMILIA',
    description:
      'At configured protected boundaries, EMILIA prevents agents from quietly widening authority.',
    url: 'https://www.emiliaprotocol.ai/',
    type: 'website',
    images: [
      {
        url: '/emilia-authority-tollbooth-v1.png',
        width: 1717,
        height: 916,
        alt: 'Agent-intent paths cross a customer-owned authority checkpoint and leave with action-bound receipts',
      },
    ],
  },
  twitter: {
    card: 'summary_large_image',
    title: 'Authority Toll Booth for Autonomous Work | EMILIA',
    description:
      'Protected crossings require authority before action, then preserve what happened.',
    images: ['/emilia-authority-tollbooth-v1.png'],
  },
};

export default function HomePage(): React.ReactElement {
  return <HomePageClient />;
}
