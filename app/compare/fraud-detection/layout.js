export const metadata = {
  title: 'Pre-Action Authorization vs Post-Action Fraud Detection',
  description:
    'Fraud detection finds bad actions after they execute. Pre-action ' +
    'authorization stops them before they execute. Why detection systems ' +
    'are necessary but insufficient for irreversible actions like wire ' +
    'transfers and benefit redirects.',
  alternates: { canonical: '/compare/fraud-detection' },
  openGraph: {
    title: 'Pre-Action Authorization vs Post-Action Fraud Detection',
    description:
      'Detection finds the breach. Authorization stops it. Why both ' +
      'are required for high-value, irreversible actions.',
    url: 'https://www.emiliaprotocol.ai/compare/fraud-detection',
    type: 'article',
  },
  keywords: [
    'fraud detection vs prevention',
    'pre-action authorization',
    'post-action fraud detection',
    'wire fraud prevention',
    'BEC defense',
    'AI fraud prevention',
    'transaction monitoring vs authorization',
  ],
};

export default function CompareFraudLayout({ children }) {
  return children;
}
