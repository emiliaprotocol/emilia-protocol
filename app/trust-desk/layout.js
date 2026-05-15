export const metadata = {
  title: 'Trust Desk — Operator Workflow for Named Signoff',
  description:
    'The operator console for reviewing pending handshakes, signing off ' +
    'on bound action contexts, and tracking accountability across high-' +
    'risk workflows. Built for treasury, fraud-ops, and compliance teams.',
  alternates: { canonical: '/trust-desk' },
  openGraph: {
    title: 'EMILIA Trust Desk',
    description:
      'Operator console for named human signoff on bound action ' +
      'contexts.',
    url: 'https://www.emiliaprotocol.ai/trust-desk',
    type: 'article',
  },
  keywords: [
    'trust desk',
    'signoff console',
    'fraud operator workflow',
    'treasury approval console',
  ],
};

export default function TrustDeskLayout({ children }) {
  return children;
}
