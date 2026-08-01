/**
 * AI Trust Desk — route metadata.
 *
 * @license Apache-2.0
 *
 * The page is a client component and cannot export metadata, so the search
 * surface lives here. Titles target what a vendor actually types when a bank's
 * AI security questionnaire lands on them, not what the product is called
 * internally.
 */

import type { Metadata } from 'next';

export const metadata: Metadata = {
  title: 'AI Security Questionnaire Answers for Vendors Selling into Banks',
  description:
    'Your SOC 2 does not answer prompt injection, model training, RAG subprocessors, or agent tool '
    + 'permissions. We answer the AI-specific questions from a versioned policy corpus, a named '
    + 'reviewer signs off, and your buyer gets a page where every claim carries a content hash.',
  keywords: [
    'AI security questionnaire',
    'AI vendor security review',
    'AI vendor risk assessment',
    'how to answer AI security questionnaire',
    'AI questionnaire for banks',
    'SOC 2 AI questions',
    'prompt injection questionnaire',
    'DORA AI vendor',
    'third party AI risk assessment',
  ],
  alternates: { canonical: '/trust-desk' },
  openGraph: {
    title: 'AI Trust Desk — Answer the AI Security Questionnaire Holding Up Your Deal',
    description:
      'For AI vendors selling into financial services with a deal stuck in security review. '
      + 'Same-day answers from a versioned AI policy corpus, human sign-off before delivery, and a '
      + 'live trust page your buyer can re-check.',
    url: 'https://www.emiliaprotocol.ai/trust-desk',
    type: 'website',
  },
  twitter: {
    card: 'summary_large_image',
    title: 'AI Trust Desk — AI security questionnaires, answered and signed off',
    description:
      'The AI-specific questions your SOC 2 was never built to cover, answered same day and signed '
      + 'off by a named reviewer.',
  },
};

const TRUST_DESK_JSONLD = {
  '@context': 'https://schema.org',
  '@type': 'Service',
  '@id': 'https://www.emiliaprotocol.ai/trust-desk#service',
  name: 'AI Trust Desk',
  url: 'https://www.emiliaprotocol.ai/trust-desk',
  serviceType: 'AI vendor security questionnaire completion',
  description:
    'Completion of AI-specific vendor security questionnaires for AI vendors selling into '
    + 'financial services, drafted from a versioned AI policy corpus with cited sources, signed '
    + 'off by a named human reviewer, and published as a trust page whose claims carry content '
    + 'hashes a buyer can re-check.',
  provider: {
    '@type': 'Organization',
    name: 'EMILIA Protocol, Inc.',
    url: 'https://www.emiliaprotocol.ai',
  },
  audience: {
    '@type': 'BusinessAudience',
    audienceType: 'AI software vendors selling into banks, funds, insurers, and fintechs',
  },
  offers: [
    { '@type': 'Offer', name: 'Gap Scan', price: '3500', priceCurrency: 'USD' },
    { '@type': 'Offer', name: 'Full Completion', price: '18000', priceCurrency: 'USD' },
    { '@type': 'Offer', name: 'AI Trust Packet', price: '35000', priceCurrency: 'USD' },
    { '@type': 'Offer', name: 'Retainer', price: '18000', priceCurrency: 'USD' },
  ],
};

export default function TrustDeskLayout({ children }: { children: React.ReactNode }) {
  return (
    <>
      <script
        type="application/ld+json"
        // eslint-disable-next-line react/no-danger
        dangerouslySetInnerHTML={{ __html: JSON.stringify(TRUST_DESK_JSONLD) }}
      />
      {children}
    </>
  );
}
