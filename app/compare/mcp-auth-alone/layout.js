export const metadata = {
  title: 'MCP Authorization Is Necessary But Not Sufficient — vs EMILIA',
  description:
    'MCP server authorization gates which tools an agent can call. EP gates ' +
    'whether the specific call about to execute was authorized by a named ' +
    'human. Why high-risk MCP tools need pre-action authorization on top of ' +
    'OAuth-style scopes.',
  alternates: { canonical: '/compare/mcp-auth-alone' },
  openGraph: {
    title: 'MCP Authorization vs EMILIA Protocol Pre-Action Authorization',
    description:
      'Scope-level MCP auth lets the agent call a tool. EP authorizes the ' +
      'specific call. Why both layers are required for consequential actions.',
    url: 'https://www.emiliaprotocol.ai/compare/mcp-auth-alone',
    type: 'article',
  },
  keywords: [
    'MCP authorization',
    'MCP server security',
    'Model Context Protocol authorization',
    'MCP tool authorization',
    'pre-action authorization MCP',
    'MCP best practices',
  ],
};

export default function CompareMcpLayout({ children }) {
  return children;
}
