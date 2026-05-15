export const metadata = {
  title: 'Agent Governance Pack — AI Agent Action Authorization Bundle',
  description:
    'Packaged controls for AI agent platforms: pre-action authorization, ' +
    'named human signoff, and self-verifying receipts for every ' +
    'consequential agent action. Three-line SDK integration; Apache 2.0.',
  alternates: { canonical: '/product/agent-governance-pack' },
  openGraph: {
    title: 'EMILIA Agent Governance Pack',
    description:
      'Pre-action authorization + named signoff + verifiable receipts ' +
      'for AI agent platforms.',
    url: 'https://www.emiliaprotocol.ai/product/agent-governance-pack',
    type: 'article',
  },
  keywords: [
    'AI agent governance',
    'agent action authorization',
    'MCP authorization',
    'autonomous agent safety',
    'AI agent compliance pack',
  ],
};

export default function AgentGovernancePackLayout({ children }) {
  return children;
}
