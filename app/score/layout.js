export const metadata = {
  title: 'Trust Profile Explorer — Verifiable Authorization Evidence',
  description:
    'Look up an entity\'s verifiable authorization evidence: confidence ' +
    'tier, established status, effective evidence, and receipts you can ' +
    'verify offline. Portable evidence, not a reputation score.',
  alternates: { canonical: '/explorer' },
  openGraph: {
    title: 'EMILIA Trust Profile Explorer',
    description:
      'Confidence and verifiable receipt evidence for AI agents and ' +
      'entities — portable evidence anyone can check, not a score or ranking.',
    url: 'https://www.emiliaprotocol.ai/explorer',
    type: 'article',
  },
  keywords: [
    'authorization evidence',
    'verifiable receipts',
    'trust profile',
    'agent accountability',
  ],
};

export default function ScoreLayout({ children }) {
  return children;
}
