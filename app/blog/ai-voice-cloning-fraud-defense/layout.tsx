import type { Metadata } from 'next';

export const metadata: Metadata = {
  title: 'AI Voice Cloning Fraud — Defense by Action Binding',
  description:
    'A convincing synthetic voice can imitate a trusted caller, but voice alone is not transaction authority. ' +
    'Bind the exact action to accepted authority and required evidence. Field guide ' +
    'for community banks, credit unions, and fintech treasury teams.',
  alternates: { canonical: '/blog/ai-voice-cloning-fraud-defense' },
  openGraph: {
    images: ['/opengraph-image'],
    title: 'AI Voice Cloning Fraud — Defense by Action Binding',
    description:
      'Move transaction authority off the voice channel. Exact-action controls ' +
      'for treasury, wire desks, and fraud operations.',
    url: 'https://www.emiliaprotocol.ai/blog/ai-voice-cloning-fraud-defense',
    type: 'article',
    publishedTime: '2026-04-22T00:00:00.000Z',
  },
  keywords: [
    'AI voice cloning fraud',
    'voice deepfake fraud defense',
    'wire fraud AI voice',
    'community bank fraud',
    'credit union fraud',
    'BEC voice fraud',
    'treasury fraud prevention',
    'callback fraud AI',
  ],
};

export default function BlogVoiceFraudLayout({ children }: { children: React.ReactNode }): React.ReactNode {
  return children;
}
