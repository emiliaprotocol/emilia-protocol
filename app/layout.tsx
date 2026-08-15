import type { Metadata } from 'next';
import { headers } from 'next/headers';
import EuAiActBanner from '@/components/EuAiActBanner';
import proofStats from '@/lib/proof-stats.json';
import './ep.css';

const TEST_CASES = Number(proofStats.tests.total).toLocaleString('en-US');
const PROOF_SUMMARY = `${proofStats.securityCase.claims} executable security claims, `
  + `${proofStats.tamarin.verifiedObligations} composed Tamarin obligations, `
  + `${proofStats.conformance.vectors} current conformance vectors, and ${TEST_CASES} automated tests`;

// Site-wide SEO metadata. Per-page `export const metadata` overrides the
// fields it sets and inherits the rest. Open Graph + Twitter defaults give
// every share a consistent card; per-page metadata overrides title and
// description for shares of specific routes.
export const metadata: Metadata = {
  metadataBase: new URL('https://www.emiliaprotocol.ai'),
  title: {
    default: 'EMILIA | Authority System for Autonomous Work',
    template: '%s | EMILIA',
  },
  description:
    'AI gave software intelligence. On covered paths, EMILIA puts customer authority in force before '
    + 'autonomous intent becomes an external consequence.',
  applicationName: 'EMILIA Gate',
  keywords: [
    'AI agent authorization',
    'AI agent firewall',
    'consequence firewall',
    'secure agent actions',
    'authorization receipts',
    'receipt required',
    'pre-action authorization',
    'AI agent trust',
    'verifiable AI authorization',
    'AI agent governance',
    'agent action binding',
    'MCP tool authorization',
    'AI agent human approval',
    'cryptographic AI controls',
    'formal verification AI',
    'AI agent fraud prevention',
  ],
  authors: [{ name: 'EMILIA Protocol', url: 'https://www.emiliaprotocol.ai' }],
  creator: 'EMILIA Protocol',
  publisher: 'EMILIA Protocol',
  openGraph: {
    type: 'website',
    locale: 'en_US',
    url: 'https://www.emiliaprotocol.ai',
    siteName: 'EMILIA Protocol',
    title: 'EMILIA | Authority System for Autonomous Work',
    description:
      `Models decide what to do. EMILIA enforces what may be done. Machine-verifiable evidence: ${PROOF_SUMMARY}.`,
    images: [
      {
        url: '/og-sequence.jpg',
        width: 1200,
        height: 630,
        alt: 'EMILIA Gate evaluates configured consequential actions against policy and authorization evidence before execution',
      },
    ],
  },
  twitter: {
    card: 'summary_large_image',
    title: 'EMILIA | Authority System for Autonomous Work',
    description:
      `AI gave software intelligence. EMILIA puts authority in force. ${PROOF_SUMMARY}.`,
    images: ['/og-sequence.jpg'],
  },
  robots: {
    index: true,
    follow: true,
    googleBot: {
      index: true,
      follow: true,
      'max-image-preview': 'large',
      'max-snippet': -1,
      'max-video-preview': -1,
    },
  },
  icons: {
    icon: [
      { url: '/favicon.svg', type: 'image/svg+xml' },
      { url: '/favicon.ico', sizes: '32x32' },
    ],
  },
  category: 'technology',
};

// Site-wide JSON-LD Organization + WebSite schema. Embedded in the root
// layout so every page inherits it. Search engines use this for the
// knowledge-panel "Organization" card and the SiteLinks Search Box.
const ORGANIZATION_JSONLD = {
  '@context': 'https://schema.org',
  '@type': 'Organization',
  name: 'EMILIA Protocol',
  alternateName: ['EP', 'Emilia Protocol'],
  url: 'https://www.emiliaprotocol.ai',
  logo: 'https://www.emiliaprotocol.ai/logo.png',
  description:
    'EMILIA is the independent authority system for autonomous work. The commercial Gate enforcement '
    + 'product runs on the open Apache-2.0 EMILIA Protocol proof substrate.',
  foundingDate: '2026-06-03',
  sameAs: [
    'https://github.com/emiliaprotocol',
    'https://www.npmjs.com/package/@emilia-protocol/mcp-server',
    'https://www.npmjs.com/package/@emilia-protocol/sdk',
    'https://www.npmjs.com/package/@emilia-protocol/verify',
    'https://www.npmjs.com/package/@emilia-protocol/require-receipt',
    'https://www.npmjs.com/package/@emilia-protocol/langchain',
    'https://pypi.org/project/emilia-verify/',
  ],
};

const WEBSITE_JSONLD = {
  '@context': 'https://schema.org',
  '@type': 'WebSite',
  name: 'EMILIA',
  url: 'https://www.emiliaprotocol.ai',
  potentialAction: {
    '@type': 'SearchAction',
    target: {
      '@type': 'EntryPoint',
      urlTemplate: 'https://www.emiliaprotocol.ai/explorer?q={search_term_string}',
    },
    'query-input': 'required name=search_term_string',
  },
};

// Reading headers() forces dynamic rendering per request.
// Next.js detects the x-nonce header and automatically applies it
// as the nonce attribute on every inline <script> it generates
// (flight data chunks, bootstrap scripts, etc.) — satisfying the
// nonce-based CSP set by middleware.js without unsafe-inline.
export default async function RootLayout({ children }: { children: React.ReactNode }) {
  const nonce = (await headers()).get('x-nonce') ?? '';

  // Reference nonce so the lint pass keeps the headers() call (its true
  // purpose is forcing dynamic rendering for CSP nonce injection).
  void nonce;

  return (
    <html lang="en">
      <head>
        <link rel="icon" href="/favicon.svg" type="image/svg+xml" />
        <link rel="icon" href="/favicon.ico" sizes="32x32" />
        <script
          type="application/ld+json"
          suppressHydrationWarning
          // Site-wide Organization schema — see ORGANIZATION_JSONLD const.
          dangerouslySetInnerHTML={{ __html: JSON.stringify(ORGANIZATION_JSONLD) }}
          nonce={nonce}
        />
        <script
          type="application/ld+json"
          suppressHydrationWarning
          // Site-wide WebSite schema with SiteLinks Search Box action.
          dangerouslySetInnerHTML={{ __html: JSON.stringify(WEBSITE_JSONLD) }}
          nonce={nonce}
        />
      </head>
      <body style={{ margin: 0, padding: 0, background: '#FAFAF9', overflowX: 'hidden' }}>
        <a className="ep-skip-link" href="#main-content">Skip to main content</a>
        <EuAiActBanner />
        <div id="main-content" tabIndex={-1}>{children}</div>
      </body>
    </html>
  );
}
