import type { Metadata } from 'next';
import HomePageClient from './HomePageClient';

export const metadata: Metadata = {
  title: 'EMILIA Gate — Consequence Firewall for AI Agents',
  description:
    'Stop consequential AI-agent actions at the executor boundary until exact-action authority is verified. '
    + 'EMILIA Protocol keeps the evidence open and independently reproducible.',
  alternates: { canonical: '/' },
  openGraph: {
    title: 'EMILIA Gate — The Consequence Firewall for AI Agents',
    description:
      'Protocol proves. Gate prevents. Require verifiable authority before money moves, infrastructure changes, regulated records update, or irreversible state changes.',
    url: 'https://www.emiliaprotocol.ai/',
    type: 'website',
  },
  twitter: {
    card: 'summary_large_image',
    title: 'EMILIA Gate — The Consequence Firewall for AI Agents',
    description:
      'Protocol proves. Gate prevents. Exact-action authority before consequential machine execution.',
  },
};

export default function HomePage(): React.ReactElement {
  return <HomePageClient />;
}
