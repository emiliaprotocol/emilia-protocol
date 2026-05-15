export const metadata = {
  title: 'Financial Pack — Wire, Beneficiary, AI-Voice Defense Bundle',
  description:
    'Packaged authorization controls for community banks, credit unions, ' +
    'and fintech treasury teams. Pre-execution gating on wires, vendor-' +
    'bank-change, beneficiary updates, and high-value payment release.',
  alternates: { canonical: '/product/financial-pack' },
  openGraph: {
    title: 'EMILIA Financial Pack',
    description:
      'Authorization controls + SOX-ready evidence + AI-voice defense ' +
      'for community bank, credit union, and treasury fraud.',
    url: 'https://www.emiliaprotocol.ai/product/financial-pack',
    type: 'article',
  },
  keywords: [
    'financial pack',
    'wire transfer authorization',
    'vendor bank change defense',
    'BEC prevention bundle',
    'SOX AI controls',
    'AI voice fraud defense',
  ],
};

export default function FinancialPackLayout({ children }) {
  return children;
}
