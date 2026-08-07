import type { Metadata } from 'next';
import HomePageClient from './HomePageClient';

export const metadata: Metadata = {
  title: { absolute: 'AI Agent Authorization and Enforcement | EMILIA Gate' },
  description:
    'AI agent authorization and enforcement: block consequential agent actions until the protected '
    + 'executor can verify the exact authority its owner requires. Run the local Authority Map, then protect one workflow with EMILIA Gate.',
  alternates: { canonical: '/' },
  openGraph: {
    title: 'AI Agent Authorization and Enforcement | EMILIA Gate',
    description:
      'The consequence firewall for AI agents. Protocol proves. Gate prevents.',
    url: 'https://www.emiliaprotocol.ai/',
    type: 'website',
    images: ['/og-sequence.jpg'],
  },
  twitter: {
    card: 'summary_large_image',
    title: 'AI Agent Authorization and Enforcement | EMILIA Gate',
    description:
      'Let agents act. Keep authority exact.',
    images: ['/og-sequence.jpg'],
  },
};

export default function HomePage(): React.ReactElement {
  return <HomePageClient />;
}
