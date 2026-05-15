export const metadata = {
  title: 'Documentation — EMILIA Protocol Reference, Quickstarts, Guides',
  description:
    'Implementer documentation for the EMILIA Protocol: TypeScript and ' +
    'Python SDK quickstarts, MCP server integration, policy authoring, ' +
    'handshake modes, and the receipt schema.',
  alternates: { canonical: '/docs' },
  openGraph: {
    title: 'EMILIA Protocol Documentation',
    description:
      'SDK quickstarts, MCP integration, policy authoring, and the ' +
      'receipt schema.',
    url: 'https://www.emiliaprotocol.ai/docs',
    type: 'website',
  },
  keywords: [
    'EMILIA Protocol docs',
    'EP SDK',
    '@emilia-protocol/sdk',
    'MCP integration',
    'EP receipt schema',
  ],
};

export default function DocsLayout({ children }) {
  return children;
}
