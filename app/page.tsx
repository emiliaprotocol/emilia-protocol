import type { Metadata } from 'next';
import HomePageClient from './HomePageClient';

export const metadata: Metadata = {
  title: { absolute: 'Your AI Workforce Needs Management | EMILIA' },
  description:
    'Give every agent a job, set its authority, and know what happened. EMILIA is building a workforce workspace with Gate enforcing limits on connected tools.',
  alternates: { canonical: '/' },
  openGraph: {
    title: 'Your AI Workforce Needs Management | EMILIA',
    description:
      'Manage jobs, authority and work reviews for AI agents. Explore the private local alpha, built around EMILIA Gate and the open Protocol.',
    url: 'https://www.emiliaprotocol.ai/',
    type: 'website',
    images: [
      {
        url: '/opengraph-image',
        width: 1200,
        height: 630,
        alt: 'EMILIA: Your AI workforce needs management. Give every agent a job, set its authority, and know what happened.',
      },
    ],
  },
  twitter: {
    card: 'summary_large_image',
    title: 'Your AI Workforce Needs Management | EMILIA',
    description:
      'Give every agent a job, set its authority, and know what happened. Private local alpha.',
    images: ['/twitter-image'],
  },
};

export default function HomePage(): React.ReactElement {
  return <HomePageClient />;
}
