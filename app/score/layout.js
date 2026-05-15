export const metadata = {
  title: 'Trust Score — Quality-Gated Reputation from Verified Receipts',
  description:
    'EP\'s trust scoring composes quality-gated evidence, behavioral ' +
    'history, and verified receipts into a procurement-grade entity ' +
    'score. Sybil-resistant; conformance-tested.',
  alternates: { canonical: '/score' },
  openGraph: {
    title: 'EMILIA Trust Score',
    description:
      'Quality-gated reputation from cryptographically verified ' +
      'receipts. Sybil-resistant scoring for AI agents and entities.',
    url: 'https://www.emiliaprotocol.ai/score',
    type: 'article',
  },
  keywords: [
    'AI trust score',
    'verified reputation',
    'Sybil-resistant scoring',
    'entity trust profile',
  ],
};

export default function ScoreLayout({ children }) {
  return children;
}
