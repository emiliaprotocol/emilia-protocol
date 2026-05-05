export const metadata = {
  title: 'EMILIA Protocol vs OAuth — Why Action Binding Matters',
  description:
    'OAuth authorizes sessions and scopes; EP authorizes specific actions. ' +
    'A scoped OAuth token can still execute an unintended payment, deletion, ' +
    'or escalation. EP binds actor, authority, policy, and exact action ' +
    'parameters before execution.',
  alternates: { canonical: '/compare/oauth' },
  openGraph: {
    title: 'EMILIA Protocol vs OAuth — Action Binding for High-Risk Actions',
    description:
      'OAuth grants permission. EP grants permission for THIS exact action. ' +
      'Why scoped tokens are not enough for AI agents and high-value workflows.',
    url: 'https://www.emiliaprotocol.ai/compare/oauth',
    type: 'article',
  },
  keywords: [
    'OAuth vs EMILIA Protocol',
    'OAuth AI agent authorization',
    'action binding vs scoped token',
    'OAuth limitations AI agents',
    'pre-action authorization',
    'OAuth scopes high-risk actions',
  ],
};

export default function CompareOAuthLayout({ children }) {
  return children;
}
