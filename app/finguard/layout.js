export const metadata = {
  title: 'FinGuard — Wire Fraud + Bank-Change + AI-Voice Defense',
  description:
    'Pre-execution authorization for wire transfers, vendor-bank changes, and payment '
    + 'release. Stops BEC and AI-voice-cloned fraud before the action executes.',
  alternates: { canonical: '/finguard' },
  openGraph: {
    title: 'EMILIA FinGuard',
    description:
      'Vendor-bank-change, beneficiary-swap, and AI-voice fraud — ' +
      'blocked before the action executes.',
    url: 'https://www.emiliaprotocol.ai/finguard',
    type: 'article',
  },
  keywords: [
    'wire transfer fraud prevention',
    'vendor bank change fraud',
    'beneficiary swap fraud',
    'AI voice fraud defense',
    'BEC prevention',
    'community bank fraud',
    'credit union fraud defense',
    'treasury action authorization',
  ],
};

export default function FinGuardLayout({ children }) {
  return children;
}
