import { headers } from 'next/headers';
import type { Metadata } from 'next';
import { FAQ, PAGE_URL } from './_content';

const description =
  'What an AI agent audit trail must contain to survive review: a signed, offline-verifiable '
  + 'record per action, not logs written by the system under review.';

export const metadata: Metadata = {
  // Layout title template appends "| EMILIA", rendering
  // "AI Agent Audit Trail: The Record That Survives Review | EMILIA".
  title: 'AI Agent Audit Trail: The Record That Survives Review',
  description,
  alternates: { canonical: '/ai-agent-audit-trail' },
  // Page-level openGraph REPLACES the layout default rather than merging into
  // it, so images must be restated here or the social card silently drops.
  openGraph: {
    title: 'AI Agent Audit Trail: The Record That Survives Review',
    description:
      'Signed, offline-verifiable evidence per agent action, including the indeterminate outcome a log cannot express.',
    url: PAGE_URL,
    type: 'article',
    images: ['/og-sequence.jpg'],
  },
  twitter: {
    card: 'summary_large_image',
    title: 'AI Agent Audit Trail: The Record That Survives Review',
    description,
    images: ['/og-sequence.jpg'],
  },
  keywords: [
    'AI agent audit trail',
    'AI agent audit log',
    'agent action evidence',
    'offline-verifiable audit record',
    'tamper-evident agent record',
    'authorization receipt',
    'indeterminate outcome',
  ],
};

const ARTICLE_JSONLD = {
  '@context': 'https://schema.org',
  '@type': 'TechArticle',
  headline: 'What an AI agent audit trail has to contain',
  description,
  about: 'Evidence requirements for autonomous agent actions',
  url: PAGE_URL,
  author: { '@type': 'Organization', name: 'EMILIA Protocol' },
  publisher: { '@type': 'Organization', name: 'EMILIA Protocol', url: 'https://www.emiliaprotocol.ai' },
  license: 'https://www.apache.org/licenses/LICENSE-2.0',
};

const FAQ_JSONLD = {
  '@context': 'https://schema.org',
  '@type': 'FAQPage',
  mainEntity: FAQ.map((f) => ({
    '@type': 'Question',
    name: f.q,
    acceptedAnswer: { '@type': 'Answer', text: f.a },
  })),
};

export default async function AiAgentAuditTrailLayout({ children }: { children: React.ReactNode }) {
  const nonce = (await headers()).get('x-nonce') ?? '';

  return (
    <>
      <script
        type="application/ld+json"
        suppressHydrationWarning
        dangerouslySetInnerHTML={{ __html: JSON.stringify(ARTICLE_JSONLD) }}
        nonce={nonce}
      />
      <script
        type="application/ld+json"
        suppressHydrationWarning
        dangerouslySetInnerHTML={{ __html: JSON.stringify(FAQ_JSONLD) }}
        nonce={nonce}
      />
      {children}
    </>
  );
}
