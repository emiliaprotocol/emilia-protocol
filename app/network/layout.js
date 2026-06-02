export const metadata = {
  title: 'The EMILIA Trust Network — verify any entity, any receipt',
  description:
    'A public, cryptographically verifiable network of entities and Trust Receipts. '
    + 'Verify any receipt offline, embed a live trust badge, and join the network that '
    + 'turns "we say we are safe" into "here is the proof".',
  alternates: { canonical: '/network' },
  openGraph: {
    title: 'The EMILIA Trust Network',
    description: 'Public verification for the AI-agent economy. Verify any receipt. Embed a live badge. Join the network.',
    url: 'https://www.emiliaprotocol.ai/network',
    type: 'website',
  },
  keywords: ['trust network', 'verifiable receipts', 'AI agent trust registry', 'public verification'],
};

export default function NetworkLayout({ children }) {
  return children;
}
