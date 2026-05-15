export const metadata = {
  title: 'Accountable Signoff — Named Human Approval Bound to Action',
  description:
    'Cryptographic named-human signoff bound to the exact action context. ' +
    'Replaces session-level approvals with action-level accountability ' +
    'for high-risk workflows.',
  alternates: { canonical: '/product/accountable-signoff' },
  openGraph: {
    title: 'EMILIA Accountable Signoff',
    description:
      'Named human signoff cryptographically bound to the exact action ' +
      'parameters before execution.',
    url: 'https://www.emiliaprotocol.ai/product/accountable-signoff',
    type: 'article',
  },
  keywords: [
    'accountable signoff',
    'named human approval',
    'AI action signoff',
    'cryptographic signoff',
    'segregation of duties AI',
  ],
};

export default function AccountableSignoffLayout({ children }) {
  return children;
}
