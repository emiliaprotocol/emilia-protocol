import type { Metadata } from 'next';

export const metadata: Metadata = {
  title: 'EMILIA Protocol vs DIY Human-in-the-Loop — Make Agent Approvals Provable',
  description:
    'A Slack or email approval step for your AI agent is a good instinct, but a ' +
    'click and a log line is not accountable. EMILIA binds the signoff to the ' +
    'exact action, makes it one-time consumable, and mints an offline-verifiable ' +
    'authorization receipt.',
  alternates: { canonical: '/compare/human-in-the-loop' },
  openGraph: {
    title: 'EMILIA Protocol vs DIY Human-in-the-Loop',
    description:
      'Keep your Slack approval — make it bound, replay-resistant, and provable ' +
      'offline instead of a click and a log line.',
    url: 'https://www.emiliaprotocol.ai/compare/human-in-the-loop',
    type: 'article',
  },
  keywords: [
    'human in the loop AI agents',
    'agent approval workflow',
    'HumanLayer alternative',
    'Slack approval AI agent',
    'human approval agent actions',
    'verifiable human signoff',
    'agent action accountability',
  ],
};

export default function CompareHumanInTheLoopLayout({ children }: { children: React.ReactNode }) {
  return children;
}
