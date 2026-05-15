export const metadata = {
  title: 'Government Pack — Benefit-Integrity Authorization Bundle',
  description:
    'Packaged authorization controls for SNAP, Medicaid, UI, and benefit ' +
    'disbursement workflows. NIST AI RMF mapping, IG-ready evidence, ' +
    'caseworker override accountability.',
  alternates: { canonical: '/product/government-pack' },
  openGraph: {
    title: 'EMILIA Government Pack',
    description:
      'Authorization controls + compliance mappings + IG-ready evidence ' +
      'for federal and state benefit-integrity workflows.',
    url: 'https://www.emiliaprotocol.ai/product/government-pack',
    type: 'article',
  },
  keywords: [
    'government AI authorization',
    'benefit integrity pack',
    'SNAP authorization',
    'Medicaid AI controls',
    'NIST AI RMF',
    'IG audit evidence',
  ],
};

export default function GovernmentPackLayout({ children }) {
  return children;
}
