import type { Metadata } from 'next';

export const metadata: Metadata = {
  title: 'The Two-Person Rule for AI Agents',
  description:
    'Some actions are too consequential for one signature. The two-person ' +
    'rule — M-of-N or ordered human approval, each signer bound to the exact ' +
    'action — made cryptographic, offline-verifiable, and enforceable before ' +
    'an AI agent executes. A primer for defense, treasury, and benefits.',
  alternates: { canonical: '/blog/the-two-person-rule-for-ai-agents' },
  openGraph: {
    title: 'The Two-Person Rule for AI Agents',
    description:
      'Multi-party approval for high-stakes agent actions: M-of-N / ordered, ' +
      'each named human bound to the exact action, fail-closed, verifiable ' +
      'offline. Try it live in your browser.',
    url: 'https://www.emiliaprotocol.ai/blog/the-two-person-rule-for-ai-agents',
    type: 'article',
    publishedTime: '2026-06-20T00:00:00.000Z',
  },
  keywords: [
    'two-person rule',
    'two-person rule for AI',
    'multi-party approval AI agents',
    'dual control AI',
    'M-of-N human approval',
    'quorum authorization',
    'multi-party authorization protocol',
    'AI agent authorization',
    'separation of duties AI',
  ],
};

export default function BlogTwoPersonRuleLayout({ children }: { children: React.ReactNode }): React.ReactNode {
  return children;
}
