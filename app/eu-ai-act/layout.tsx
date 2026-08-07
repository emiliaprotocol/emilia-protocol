import type { Metadata } from 'next';

export const metadata: Metadata = {
  title: { absolute: 'EU AI Act Human Oversight (Article 14): Evidence to Build Now' },
  description:
    'EU AI Act high-risk obligations phase in on Dec 2, 2027 (Annex III) and Aug 2, 2028 (product-integrated). The Article 14 human oversight evidence to build now.',
  alternates: { canonical: '/eu-ai-act' },
  openGraph: {
    title: 'EU AI Act Human Oversight (Article 14): Evidence to Build Now',
    description:
      'A bounded-model, open protocol for exact-action evidence that may support selected EU AI Act controls.',
    url: 'https://www.emiliaprotocol.ai/eu-ai-act',
    type: 'website',
    images: ['/og-sequence.jpg'],
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
