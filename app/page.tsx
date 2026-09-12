import type { Metadata } from 'next';
import HomePageClient from './HomePageClient';

export const metadata: Metadata = {
  title: { absolute: 'Build Your AI Workforce | EMILIA' },
  description:
    'Find specialized agents or bring your own. Give them a job, set their limits and see how they perform. EMILIA brings workforce management and a builder marketplace together.',
  alternates: { canonical: '/' },
  openGraph: {
    title: 'Build Your AI Workforce | EMILIA',
    description:
      'Help builders earn work and help companies delegate it. Explore the marketplace and EMILIA’s private local workforce alpha, built around Gate and the open Protocol.',
    url: 'https://www.emiliaprotocol.ai/',
    type: 'website',
    images: [
      {
        url: '/opengraph-image',
        width: 1200,
        height: 630,
        alt: 'EMILIA: Build your AI workforce. Find specialized agents or bring your own.',
      },
    ],
  },
  twitter: {
    card: 'summary_large_image',
    title: 'Build Your AI Workforce | EMILIA',
    description:
      'Find specialized agents or bring your own. Give them a job, set their limits and review the work. Workforce workspace: private local alpha.',
    images: ['/twitter-image'],
  },
};

export default function HomePage(): React.ReactElement {
  return <HomePageClient />;
}
