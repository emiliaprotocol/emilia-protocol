export const metadata = {
  title: 'AI Agent Use Case — Pre-Execution Trust Gate for Autonomous Agents',
  description:
    'Gate every consequential AI agent action behind a cryptographic trust ' +
    'ceremony before execution. Works with OpenAI Agents, Claude Computer ' +
    'Use, MCP servers, Devin, Sierra, Lindy, custom agent frameworks. ' +
    'Three-line SDK integration.',
  alternates: { canonical: '/use-cases/ai-agent' },
  openGraph: {
    title: 'EMILIA Protocol for AI Agent Action Authorization',
    description:
      'The trust gate enterprise customers are asking your agent platform ' +
      'for. Three-line SDK integration. Apache 2.0.',
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

export default function AiAgentUseCaseLayout({ children }) {
  return children;
}
