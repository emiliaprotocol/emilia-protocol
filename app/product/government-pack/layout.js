export const metadata = {
  title: 'Government Pack — GovGuard Fraud-Control Bundle',
  description:
    'Packaged GovGuard controls for vendor payment destinations, disbursement ' +
    'releases, benefit routing, provider enrollment, eligibility overrides, ' +
    'and caseworker accountability.',
  alternates: { canonical: '/product/government-pack' },
  openGraph: {
    title: 'EMILIA Government Pack',
    description:
      'GovGuard fire drills, GG-1 conformance, and IG-ready evidence for ' +
      'public-sector fraud-control workflows.',
    url: 'https://www.emiliaprotocol.ai/product/government-pack',
    type: 'article',
  },
  keywords: [
    'government AI authorization',
    'benefit integrity pack',
    'government fraud-control fire drill',
    'vendor payment destination control',
    'provider enrollment control',
    'eligibility override audit',
    'SNAP authorization',
    'Medicaid AI controls',
    'NIST AI RMF',
    'IG audit evidence',
  ],
};

export default function GovernmentPackLayout({ children }) {
  return children;
}
