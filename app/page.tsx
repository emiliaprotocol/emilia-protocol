import type { Metadata } from 'next';
import HomePageClient from './HomePageClient';

export const metadata: Metadata = {
  title: 'EMILIA Gate — Consequence Firewall for AI Agents',
  description:
    'Block consequential AI-agent actions until the protected executor can verify the exact authority '
    + 'its owner requires. Run the local Authority Map, then protect one workflow with EMILIA Gate.',
  alternates: { canonical: '/' },
  openGraph: {
    title: 'EMILIA Gate — Let Agents Act. Keep Authority Exact.',
    description:
      'The consequence firewall for AI agents. Protocol proves. Gate prevents.',
    url: 'https://www.emiliaprotocol.ai/',
    type: 'website',
  },
  twitter: {
    card: 'summary_large_image',
    title: 'EMILIA Gate — Consequence Firewall for AI Agents',
    description:
      'Let agents act. Keep authority exact.',
  },
};

export default function HomePage(): React.ReactElement {
  return <HomePageClient />;
}
