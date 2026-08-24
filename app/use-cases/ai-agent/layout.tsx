import type { Metadata } from 'next';

export const metadata: Metadata = {
  title: 'AI Agents — Bounded Consequence-Control Profile',
  description:
    'A bounded EMILIA solution profile for exact-action authority and evidence checks ' +
    'on completely mediated privileged agent-tool paths.',
  alternates: { canonical: '/use-cases/ai-agent' },
  openGraph: {
    title: 'EMILIA Protocol for AI Agent Action Authorization',
    description:
      'Exact-action authority and evidence checks for completely mediated privileged agent-tool paths.',
    url: 'https://www.emiliaprotocol.ai/use-cases/ai-agent',
    type: 'article',
  },
  keywords: [
    'AI agent authorization',
    'agent action binding',
    'MCP authorization',
    'autonomous agent safety',
    'agent compliance controls',
    'OpenAI agent authorization',
    'Claude Computer Use safety',
    'AI agent governance platform',
  ],
};

export default function AiAgentUseCaseLayout({ children }: { children: React.ReactNode }) {
  return children;
}
