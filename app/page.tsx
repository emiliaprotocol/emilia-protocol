import type { Metadata } from 'next';
import HomePageClient from './HomePageClient';

export const metadata: Metadata = {
  title: { absolute: 'Authority Control Plane for Autonomous Work | EMILIA' },
  description:
    'Set a finite operating mandate once, let agents work inside it, and enforce each consequential '
    + 'unit of work at the protected executor with EMILIA Gate.',
  alternates: { canonical: '/' },
  openGraph: {
    title: 'Authority Control Plane for Autonomous Work | EMILIA',
    description:
      'AI workers need authority, not constant supervision. Protocol proves. Gate prevents.',
    url: 'https://www.emiliaprotocol.ai/',
    type: 'website',
    images: ['/og-sequence.jpg'],
  },
  twitter: {
    card: 'summary_large_image',
    title: 'Authority Control Plane for Autonomous Work | EMILIA',
    description:
      'Set authority once. Let agents work.',
    images: ['/og-sequence.jpg'],
  },
};

export default function HomePage(): React.ReactElement {
  return <HomePageClient />;
}
