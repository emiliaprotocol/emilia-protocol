export const metadata = {
  title: 'GovGuard - Who Approved the Disbursement?',
  description:
    'When AI drafts or triggers disbursements, vendor bank-account changes, or '
    + 'benefit changes, every irreversible action gets a named human approval and a '
    + 'verifiable audit record - an authorization receipt that proves who approved, '
    + 'provable later even offline. Start in observe mode; nothing is blocked.',
  alternates: { canonical: '/govguard' },
  openGraph: {
    title: 'EMILIA GovGuard',
    description:
      'Authorization receipts for government payment integrity. Observe one workflow, '
      + 'prove which irreversible actions would have required named signoff.',
    url: 'https://www.emiliaprotocol.ai/govguard',
    type: 'article',
  },
  keywords: [
    'county treasurer payment integrity',
    'vendor bank account change control',
    'disbursement approval audit',
    'benefit redirection fraud',
    'SNAP fraud prevention',
    'Medicaid fraud',
    'caseworker override control',
    'government AI controls',
    'NIST AI RMF compliance',
    'IG GAO evidence',
  ],
};

export default function GovGuardLayout({ children }) {
  return children;
}
