import type { Metadata } from 'next';

export const metadata: Metadata = {
  title: 'Credentials Are Not Action Authorization',
  description:
    'What the OpenAI–Hugging Face incident and Anthropic cyber-evaluation review reveal about agent reachability, bearer credentials, and exact-action authorization.',
  alternates: { canonical: '/blog/credentials-are-not-action-authorization' },
  openGraph: {
    title: 'A credential was all the authority it needed',
    description:
      'Agent containment failed first. At the external boundary, possession of a credential was enough to act. Those are different security problems.',
    url: 'https://www.emiliaprotocol.ai/blog/credentials-are-not-action-authorization',
    type: 'article',
    publishedTime: '2026-07-30T00:00:00.000Z',
  },
  keywords: [
    'AI agent credential security',
    'Hugging Face security incident',
    'AI agent authorization',
    'MCP credential audit',
    'exact action authorization',
    'AI cyber evaluation security',
  ],
};

export default function CredentialsPostLayout({ children }: { children: React.ReactNode }): React.ReactNode {
  return children;
}
