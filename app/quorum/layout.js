export const metadata = {
  title: 'EMILIA Quorum — The Two-Person Rule for AI Actions',
  description:
    'Multi-party approval for the highest-stakes irreversible actions: M-of-N '
    + 'or ordered human signoff, each named approver bound to the exact action, '
    + 'fail-closed and verifiable offline. For defense, national security, and '
    + 'treasury dual-control.',
  alternates: { canonical: '/quorum' },
  openGraph: {
    title: 'EMILIA Quorum — multi-party signoff',
    description:
      'The two-person rule, cryptographically enforced: an ordered or M-of-N '
      + 'quorum of named humans, each bound to the exact action. Try it live.',
    url: 'https://www.emiliaprotocol.ai/quorum',
    type: 'article',
  },
  keywords: [
    'two-person rule',
    'multi-party approval',
    'dual control authorization',
    'M-of-N human approval',
    'quorum authorization AI',
    'defense AI authorization',
    'treasury dual control',
    'separation of duties AI agents',
  ],
};

export default function QuorumLayout({ children }) {
  return children;
}
