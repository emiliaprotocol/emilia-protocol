import type { Metadata } from 'next';

export const metadata: Metadata = {
  title: 'FinGuard — EMILIA Gate Financial Profile',
  description:
    'A financial solution profile for EMILIA Gate, applying action-bound evidence to configured treasury, beneficiary-change, and payment-release workflows.',
  alternates: { canonical: '/finguard' },
  openGraph: {
    title: 'FinGuard — EMILIA Gate Financial Profile',
    description:
      'Apply Gate policy and authorization-evidence requirements at configured financial action boundaries.',
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

export default function FinGuardLayout({ children }: { children: React.ReactNode }) {
  return children;
}
