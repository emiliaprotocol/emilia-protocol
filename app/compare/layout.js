export const metadata = {
  title: 'EMILIA Protocol Comparisons — vs OAuth, MCP Auth, Audit Logs',
  description:
    'How EMILIA Protocol compares to OAuth, MCP authorization, audit logs, ' +
    'and post-action fraud detection. Procurement-team reference for ' +
    'evaluating pre-action authorization controls.',
  alternates: { canonical: '/compare' },
  openGraph: {
    title: 'EMILIA Protocol Comparisons',
    description:
      'EP vs OAuth, MCP authorization, audit logs, and fraud detection.',
    url: 'https://www.emiliaprotocol.ai/compare',
    type: 'website',
  },
  keywords: [
    'EMILIA Protocol vs',
    'AI authorization comparison',
    'pre-action authorization vs OAuth',
    'AI agent governance comparison',
  ],
};

export default function CompareLayout({ children }) {
  return children;
}
