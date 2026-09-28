import type { Metadata } from 'next';
import HomePageClient from './HomePageClient';

const TITLE = 'Hire the AI. Keep Your Rules. | EMILIA';
const DESCRIPTION =
  'EMILIA gives AI the rules every new hire gets, and checks them at a gate the AI can’t go around. Every payment it allows gets a signed receipt your accountant can check offline, without asking the AI company.';

export const metadata: Metadata = {
  title: { absolute: TITLE },
  description: DESCRIPTION,
  alternates: { canonical: '/' },
  openGraph: {
    title: TITLE,
    description: DESCRIPTION,
    url: 'https://www.emiliaprotocol.ai/',
    type: 'website',
    images: [
      {
        url: '/opengraph-image',
        width: 1200,
        height: 630,
        alt: 'EMILIA: Hire the AI. Keep your rules. The gate checks every payment against your rules before any money moves.',
      },
    ],
  },
  twitter: {
    card: 'summary_large_image',
    title: TITLE,
    description: DESCRIPTION,
    images: ['/twitter-image'],
  },
};

export default function HomePage(): React.ReactElement {
  return <HomePageClient />;
}
