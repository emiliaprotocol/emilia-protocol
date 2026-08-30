import type { Metadata } from 'next';

export const metadata: Metadata = {
  title: 'AI Defenders Need Action Authority, Not Just Credentials',
  description:
    'Cyber-capable AI can help defenders move faster. Before it changes a customer system, the exact remediation action still needs a bounded authority decision.',
  alternates: { canonical: '/blog/ai-defenders-need-action-authority' },
  openGraph: {
    title: 'AI defenders need action authority, not just credentials',
    description:
      'The missing layer between an AI security recommendation and a consequential administrative action.',
    url: 'https://www.emiliaprotocol.ai/blog/ai-defenders-need-action-authority',
    type: 'article',
    publishedTime: '2026-08-29T00:00:00.000Z',
    images: ['/cyber-authority/opengraph-image'],
  },
  twitter: {
    card: 'summary_large_image',
    title: 'AI defenders need action authority, not just credentials',
    description: 'Detection proposes the response. Authority decides whether this exact action may cross.',
    images: ['/cyber-authority/opengraph-image'],
  },
  keywords: [
    'AI cyber defense',
    'automated remediation authorization',
    'AI SOC governance',
    'critical infrastructure AI security',
    'AI agent authority',
  ],
};

export default function AIDefenderAuthorityLayout({ children }: { children: React.ReactNode }): React.ReactNode {
  return children;
}
