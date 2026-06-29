export const metadata = {
  title: 'GovGuard - Pre-Payment Control for Government Fraud',
  description:
    'Run a government fraud-control fire drill for vendor payment destinations, '
    + 'disbursement releases, benefit routing, provider enrollment, and eligibility '
    + 'overrides. Start in observe mode; nothing is blocked.',
  alternates: { canonical: '/govguard' },
  openGraph: {
    title: 'EMILIA GovGuard',
    description:
      'Pre-payment control and authorization receipts for government fraud workflows. '
      + 'Observe one workflow, prove which actions would have required named signoff.',
    url: 'https://www.emiliaprotocol.ai/govguard',
    type: 'article',
  },
  keywords: [
    'county treasurer payment integrity',
    'vendor bank account change control',
    'government fraud control fire drill',
    'disbursement approval audit',
    'grant disbursement approval',
    'provider enrollment fraud control',
    'eligibility override audit',
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
