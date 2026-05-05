export const metadata = {
  title: 'Financial Use Case — Wire Fraud, Beneficiary Swap, AI Voice Defense',
  description:
    'Pre-execution authorization for wire transfers, vendor-bank-change, ' +
    'beneficiary updates, and high-value payment release. Stops social ' +
    'engineering and AI-voice-cloned fraud before the action executes. ' +
    'SOX-ready, BEC-prevention.',
  alternates: { canonical: '/use-cases/financial' },
  openGraph: {
    title: 'EMILIA FinGuard — AI-Era Fraud Defense',
    description:
      'Vendor-bank-change, beneficiary-swap, and AI-voice fraud — blocked ' +
      'before the action executes. Action-bound authorization for treasury ops.',
    url: 'https://www.emiliaprotocol.ai/use-cases/financial',
    type: 'article',
  },
  keywords: [
    'wire transfer fraud prevention',
    'vendor bank change fraud',
    'beneficiary swap fraud',
    'AI voice fraud defense',
    'BEC prevention',
    'SOX AI controls',
    'community bank fraud defense',
    'treasury action authorization',
  ],
};

export default function FinUseCaseLayout({ children }) {
  return children;
}
