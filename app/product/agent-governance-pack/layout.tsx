import type { Metadata } from 'next';

export const metadata: Metadata = {
  title: 'Agent Action Authority Reference Profile | EMILIA',
  description:
    'A reference solution profile for binding consequential agent actions to '
    + 'customer-owned authority at a completely mediated executor boundary.',
  alternates: { canonical: '/product/agent-governance-pack' },
  robots: { index: true, follow: true },
  openGraph: {
    title: 'EMILIA Agent Action Authority Reference Profile',
    description:
      'Implemented exact-action building blocks, designed policy profiles, and the '
      + 'boundary between a nonproduction pilot and production Gate Implementation.',
    url: 'https://www.emiliaprotocol.ai/product/agent-governance-pack',
    type: 'website',
  },
  twitter: {
    card: 'summary',
    title: 'EMILIA Agent Action Authority Reference Profile',
    description: 'Exact-action authority building blocks for consequential agent work.',
  },
  keywords: [
    'AI agent action authorization',
    'agent authority control plane',
    'MCP exact action authorization',
    'autonomous agent executor control',
  ],
};

export default function AgentGovernancePackLayout({ children }: { children: React.ReactNode }) {
  return children;
}
