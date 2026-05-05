export const metadata = {
  title: 'MCP Authorization Best Practices in 2026',
  description:
    'A practical guide to authorizing MCP tools beyond OAuth scopes: when ' +
    'tool-level authorization is enough, when you need per-invocation ' +
    'authorization, and how to compose MCP servers with pre-action ' +
    'authorization for high-risk tools.',
  alternates: { canonical: '/blog/mcp-authorization-best-practices' },
  openGraph: {
    title: 'MCP Authorization Best Practices in 2026',
    description:
      'Scope-level OAuth + per-invocation pre-action authorization for ' +
      'MCP tools that touch money, infrastructure, or user data.',
    url: 'https://www.emiliaprotocol.ai/blog/mcp-authorization-best-practices',
    type: 'article',
    publishedTime: '2026-04-15T00:00:00.000Z',
  },
  keywords: [
    'MCP authorization best practices',
    'MCP server authorization',
    'Model Context Protocol authorization',
    'MCP OAuth',
    'MCP tool authorization',
    'high-risk MCP tools',
    'pre-action authorization MCP',
  ],
};

export default function BlogMcpLayout({ children }) {
  return children;
}
