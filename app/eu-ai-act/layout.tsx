import type { Metadata } from 'next';

export const metadata: Metadata = {
  title: 'EU AI Act High-Risk Timeline — Dec 2027 and Aug 2028',
  description:
    'Regulation (EU) 2026/1744 phases high-risk AI obligations to December 2, 2027 for Annex III and August 2, 2028 for product-integrated systems. '
    + 'EMILIA is one technical control that may support selected evidence and oversight duties; it is not a complete compliance program.',
  alternates: { canonical: '/eu-ai-act' },
  openGraph: {
    title: 'EU AI Act: adopted high-risk timeline for 2027 and 2028',
    description:
      'A bounded-model, open protocol for exact-action evidence that may support selected EU AI Act controls.',
    url: 'https://www.emiliaprotocol.ai/eu-ai-act',
    type: 'website',
  },
  keywords: [
    'EU AI Act compliance',
    'EU AI Act Digital Omnibus',
    'EU AI Act December 2027',
    'EU AI Act high-risk postponement',
    'high-risk AI system compliance',
    'AI Act audit logs',
    'AI Act human oversight',
    'NIST AI RMF alignment',
    'AI governance compliance',
  ],
};

export default function EuAiActLayout({ children }: { children: React.ReactNode }) {
  return children;
}
