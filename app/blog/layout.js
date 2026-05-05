export const metadata = {
  title: 'EMILIA Protocol Blog — Pre-Action Authorization for AI Agents',
  description:
    'Field notes on AI agent authorization, MCP best practices, formal ' +
    'verification, fraud defense by action binding, and compliance mapping ' +
    'for the EMILIA Protocol open standard.',
  alternates: { canonical: '/blog' },
  openGraph: {
    title: 'EMILIA Protocol Blog',
    description:
      'AI agent authorization, MCP, formal verification, and fraud defense.',
    url: 'https://www.emiliaprotocol.ai/blog',
    type: 'website',
  },
  keywords: [
    'AI agent authorization blog',
    'MCP authorization',
    'pre-action authorization',
    'formal verification AI',
    'AI fraud defense',
  ],
};

export default function BlogLayout({ children }) {
  return children;
}
