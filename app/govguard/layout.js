export const metadata = {
  title: 'GovGuard — Pre-Action Authorization for Government Workflows',
  description:
    'Pre-action authorization for benefit disbursements, caseworker overrides, and '
    + 'payment-destination changes. SNAP, Medicaid, and UI fraud prevention with audit proof.',
  alternates: { canonical: '/govguard' },
  openGraph: {
    title: 'EMILIA GovGuard',
    description:
      'Pre-action authorization for government benefit workflows. ' +
      'Stops benefit redirection, payment-destination fraud, and ' +
      'operator overrides before execution.',
    url: 'https://www.emiliaprotocol.ai/govguard',
    type: 'article',
  },
  keywords: [
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
