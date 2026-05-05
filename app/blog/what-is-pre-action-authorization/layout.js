export const metadata = {
  title: 'What Is Pre-Action Authorization?',
  description:
    'Sessions and scopes authorize the actor. Pre-action authorization ' +
    'authorizes the action — the exact destination, amount, and parameters, ' +
    'before execution. A category primer for AI agents and high-risk ' +
    'workflows.',
  alternates: { canonical: '/blog/what-is-pre-action-authorization' },
  openGraph: {
    title: 'What Is Pre-Action Authorization?',
    description:
      'A category primer: why session and scope authorization stop short ' +
      'for AI agents, and what action-level authorization adds.',
    url: 'https://www.emiliaprotocol.ai/blog/what-is-pre-action-authorization',
    type: 'article',
    publishedTime: '2026-04-12T00:00:00.000Z',
  },
  keywords: [
    'pre-action authorization',
    'action-level authorization',
    'AI agent authorization',
    'action binding',
    'verifiable AI authorization',
    'session vs action authorization',
  ],
};

export default function BlogPreActionLayout({ children }) {
  return children;
}
