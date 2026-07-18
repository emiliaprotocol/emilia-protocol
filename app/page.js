import HomePageClient from './HomePageClient';

export const metadata = {
  title: 'EMILIA Gate — Consequence Firewall for AI Agents',
  description:
    'EMILIA Gate blocks consequential AI-agent actions until exact-action authority verifies. '
    + 'EMILIA Protocol keeps the resulting evidence open and independently reproducible.',
  alternates: { canonical: '/' },
  openGraph: {
    title: 'EMILIA Gate — The Consequence Firewall for AI Agents',
    description:
      'Protocol proves. Gate prevents. Require verifiable authority before an AI agent changes money, code, permissions, data, energy, or physical state.',
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

export default function HomePage() {
  return <HomePageClient />;
}
