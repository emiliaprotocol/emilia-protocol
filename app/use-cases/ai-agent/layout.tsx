import type { Metadata } from 'next';

export const metadata: Metadata = {
  title: 'AI Agents — Pre-Execution Trust Gate for Autonomy',
  description:
    'Put a customer-owned Gate on one configured agent action path. Verify ' +
    'accepted exact-action authority and required evidence before provider entry, ' +
    'with open adapters and reference integrations for common agent stacks.',
  alternates: { canonical: '/use-cases/ai-agent' },
  openGraph: {
    images: ['/opengraph-image'],
    title: 'EMILIA Protocol for AI Agent Action Authorization',
    description:
      'Customer-owned exact-action admission for consequential agent tools. ' +
      'Finite mandates, optional fresh approval, and portable evidence. Apache 2.0.',
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
