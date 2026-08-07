import { headers } from 'next/headers';
import type { Metadata } from 'next';
import { FAQ, PAGE_URL } from './_content';

// Kept under 160 characters so search engines render it without truncation.
const description =
  'Design an AI agent approval workflow: run routine work inside policy, escalate the rest to a '
  + 'named human, bind each approval to one exact action, used once.';

export const metadata: Metadata = {
  // Layout title template appends "| EMILIA", rendering
  // "AI Agent Approval Workflow: Escalate, Bind, Consume Once | EMILIA".
  title: 'AI Agent Approval Workflow: Escalate, Bind, Consume Once',
  description,
  alternates: { canonical: '/ai-agent-approvals' },
  // Page-level openGraph REPLACES the layout default rather than merging into
  // it, so images must be restated here or the social card silently drops.
  openGraph: {
    title: 'AI Agent Approval Workflow: Escalate, Bind, Consume Once',
    description:
      'Approve routine work inside policy, escalate the rest to a named human, and never let the agent widen its own authority.',
    url: PAGE_URL,
    type: 'article',
    images: ['/og-sequence.jpg'],
  },
  twitter: {
    card: 'summary_large_image',
    title: 'AI Agent Approval Workflow: Escalate, Bind, Consume Once',
    description,
    images: ['/og-sequence.jpg'],
  },
  keywords: [
    'AI agent approval workflow',
    'agent approval process',
    'human in the loop agent approval',
    'agent escalation policy',
    'exact-action binding',
    'one-time approval consumption',
    'delegated authority containment',
  ],
};

const ARTICLE_JSONLD = {
  '@context': 'https://schema.org',
  '@type': 'TechArticle',
  headline: 'Designing an AI agent approval workflow',
  description,
  about: 'Approval, escalation, and authority containment for autonomous agents',
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

export default async function AiAgentApprovalsLayout({ children }: { children: React.ReactNode }) {
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
