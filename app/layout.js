import { headers } from 'next/headers';
import { IBM_Plex_Sans, IBM_Plex_Mono } from 'next/font/google';
import EuAiActBanner from '@/components/EuAiActBanner';
import './ep.css';

// Self-host IBM Plex via next/font so the browser does not block on the
// Google Fonts CSS request and so we eliminate the @next/next/no-page-custom-font
// lint warning. The font name strings used by ep.css (`IBM Plex Sans`,
// `IBM Plex Mono`) are matched verbatim by next/font's font-family output,
// so existing `font-family: 'IBM Plex Sans'` rules continue to work.
const ibmPlexSans = IBM_Plex_Sans({
  subsets: ['latin'],
  weight: ['300', '400', '500', '600', '700'],
  display: 'swap',
});
const ibmPlexMono = IBM_Plex_Mono({
  subsets: ['latin'],
  weight: ['400', '500'],
  display: 'swap',
});

// Site-wide SEO metadata. Per-page `export const metadata` overrides the
// fields it sets and inherits the rest. Open Graph + Twitter defaults give
// every share a consistent card; per-page metadata overrides title and
// description for shares of specific routes.
export const metadata = {
  metadataBase: new URL('https://www.emiliaprotocol.ai'),
  title: {
    default: 'EMILIA Protocol — The Accountability Layer for AI Agents',
    template: '%s | EMILIA Protocol',
  },
  description:
    'Every AI action needs an owner. Before an agent does anything irreversible, EMILIA '
    + 'assigns a named human who approves the exact action on their own device — so "who '
    + 'approved this?" always has an answer anyone can verify. Formally verified, Apache-2.0.',
  applicationName: 'EMILIA Protocol',
  keywords: [
    'AI agent authorization',
    'pre-action authorization',
    'AI agent trust',
    'verifiable AI authorization',
    'AI agent governance',
    'agent action binding',
    'NIST AI RMF',
    'EU AI Act compliance',
    'cryptographic AI controls',
    'formal verification AI',
    'AI agent fraud prevention',
    'autonomous agent safety',
  ],
  authors: [{ name: 'EMILIA Protocol', url: 'https://www.emiliaprotocol.ai' }],
  creator: 'EMILIA Protocol',
  publisher: 'EMILIA Protocol',
  alternates: {
    canonical: '/',
  },
  openGraph: {
    type: 'website',
    locale: 'en_US',
    url: 'https://www.emiliaprotocol.ai',
    siteName: 'EMILIA Protocol',
    title: 'EMILIA Protocol — The Accountability Layer for AI Agents',
    description:
      'A named human signs the exact action on their own device before an AI agent ' +
      'does anything irreversible. Formally verified, Apache 2.0, production-oriented reference runtime.',
    images: [
      {
        url: '/og-sequence.jpg',
        width: 1200,
        height: 630,
        alt: 'EMILIA — automated control for AI agents: high-risk actions are AUTHORIZED only with a named human authorizer, otherwise DENIED',
      },
    ],
  },
  twitter: {
    card: 'summary_large_image',
    title: 'EMILIA Protocol — The Accountability Layer for AI Agents',
    description:
      'A named human\'s signed yes — on their own device — before an AI agent ' +
      'does anything irreversible. Formally verified.',
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
    'Open protocol and Apache-2.0 reference runtime for verifiable pre-action ' +
    'authorization in AI agent systems.',
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
  name: 'EMILIA Protocol',
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

// EP itself as a SoftwareApplication. Search engines surface this in the
// "Software" knowledge panel and AI search engines (Google AI Overviews,
// Perplexity, ChatGPT browsing) cite it when summarizing what EP is.
const SOFTWARE_APPLICATION_JSONLD = {
  '@context': 'https://schema.org',
  '@type': 'SoftwareApplication',
  name: 'EMILIA Protocol',
  applicationCategory: 'SecurityApplication',
  applicationSubCategory: 'AI Authorization Protocol',
  operatingSystem: 'Cross-platform (Node.js, Python, Go; Cloud)',
  description:
    'Open protocol and Apache-2.0 reference runtime for verifiable ' +
    'pre-action authorization in AI agent systems. Cryptographically binds ' +
    'actor identity, authority, policy, and action context before execution.',
  url: 'https://www.emiliaprotocol.ai',
  downloadUrl: 'https://www.npmjs.com/package/@emilia-protocol/sdk',
  softwareVersion: '1.0',
  releaseNotes: 'https://github.com/emiliaprotocol/emilia-protocol/blob/main/CHANGELOG.md',
  license: 'https://www.apache.org/licenses/LICENSE-2.0',
  author: { '@type': 'Organization', name: 'EMILIA Protocol' },
  offers: {
    '@type': 'Offer',
    price: '0',
    priceCurrency: 'USD',
    availability: 'https://schema.org/InStock',
  },
  featureList: [
    'Named human signoff with device-held WebAuthn keys (Face ID / passkey)',
    'Pre-action authorization for AI agents',
    'Formal verification (26 TLA+ theorems, 35 Alloy facts)',
    'Cross-language conformance: JS, Python, and Go reference verifiers proven interoperable',
    'Cryptographic action binding (Ed25519 + Merkle)',
    'Self-verifying trust receipts (offline verifiable)',
    'NIST AI RMF and EU AI Act compliance mappings',
    'MCP server with 36 trust tools (17 core by default)',
    'LangChain, CrewAI, and AutoGen integrations',
    'Offline receipt verification in JavaScript, Python, and Go',
    'TypeScript and Python SDKs',
  ],
};

// Reading headers() forces dynamic rendering per request.
// Next.js detects the x-nonce header and automatically applies it
// as the nonce attribute on every inline <script> it generates
// (flight data chunks, bootstrap scripts, etc.) — satisfying the
// nonce-based CSP set by middleware.js without unsafe-inline.
export default async function RootLayout({ children }) {
  const nonce = (await headers()).get('x-nonce') ?? '';

  // ibmPlexSans/ibmPlexMono are referenced for their side-effect of
  // injecting the @font-face CSS via next/font; the className string is
  // applied to <html> so font-family lookups in ep.css resolve.
  const fontClass = `${ibmPlexSans.className} ${ibmPlexMono.className}`;
  // Reference nonce so the lint pass keeps the headers() call (its true
  // purpose is forcing dynamic rendering for CSP nonce injection).
  void nonce;

  return (
    <html lang="en" className={fontClass}>
      <head>
        <link rel="icon" href="/favicon.svg" type="image/svg+xml" />
        <link rel="icon" href="/favicon.ico" sizes="32x32" />
        <script
          type="application/ld+json"
          // Site-wide Organization schema — see ORGANIZATION_JSONLD const.
          dangerouslySetInnerHTML={{ __html: JSON.stringify(ORGANIZATION_JSONLD) }}
          nonce={nonce}
        />
        <script
          type="application/ld+json"
          // Site-wide WebSite schema with SiteLinks Search Box action.
          dangerouslySetInnerHTML={{ __html: JSON.stringify(WEBSITE_JSONLD) }}
          nonce={nonce}
        />
        <script
          type="application/ld+json"
          // EP as a SoftwareApplication — surfaced in software knowledge panels.
          dangerouslySetInnerHTML={{ __html: JSON.stringify(SOFTWARE_APPLICATION_JSONLD) }}
          nonce={nonce}
        />
      </head>
      <body style={{ margin: 0, padding: 0, background: '#FAFAF9', overflowX: 'hidden' }}>
        <EuAiActBanner />
        {children}
      </body>
    </html>
  );
}
