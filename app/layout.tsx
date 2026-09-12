import type { Metadata } from 'next';
import { headers } from 'next/headers';
import EuAiActBanner from '@/components/EuAiActBanner';
import { ENTITY } from '@/lib/site-config';
import './ep.css';

// Site-wide SEO metadata. Per-page `export const metadata` overrides the
// fields it sets and inherits the rest. Open Graph + Twitter defaults give
// every share a consistent card; per-page metadata overrides title and
// description for shares of specific routes.
export const metadata: Metadata = {
  metadataBase: new URL('https://www.emiliaprotocol.ai'),
  title: {
    default: 'EMILIA | Build Your AI Workforce',
    template: '%s',
  },
  description:
    'Find specialized agents or bring your own. Give them a job, set their limits and review the work. '
    + 'EMILIA is building the operating home for your AI workforce.',
  applicationName: 'EMILIA',
  authors: [{ name: 'EMILIA', url: 'https://www.emiliaprotocol.ai' }],
  creator: 'EMILIA',
  publisher: 'EMILIA',
  openGraph: {
    type: 'website',
    locale: 'en_US',
    url: 'https://www.emiliaprotocol.ai',
    siteName: 'EMILIA',
    title: 'EMILIA | Build Your AI Workforce',
    description:
      'Find specialized agents or bring your own. Explore the marketplace and a private local workforce alpha, with Gate enforcing limits on configured paths.',
    images: [
      {
        url: '/opengraph-image',
        width: 1200,
        height: 630,
        alt: 'EMILIA: Build your AI workforce. Find specialized agents or bring your own.',
      },
    ],
  },
  twitter: {
    card: 'summary_large_image',
    title: 'EMILIA | Build Your AI Workforce',
    description:
      'Find specialized agents or bring your own. Give them a job, set their limits and review the work. Workforce workspace: private local alpha.',
    images: ['/twitter-image'],
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
      { url: '/favicon.svg', type: 'image/svg+xml', sizes: 'any' },
      { url: '/favicon.ico', sizes: '16x16 32x32 48x48' },
    ],
  },
  category: 'technology',
};

// Site-wide JSON-LD Organization + WebSite schema. Embedded in the root
// layout so every page inherits it. Stable @ids let route-level structured
// data refer back to the same site and organization entities.
const ORGANIZATION_JSONLD = {
  '@context': 'https://schema.org',
  '@type': 'Organization',
  '@id': 'https://www.emiliaprotocol.ai/#organization',
  name: 'EMILIA',
  legalName: ENTITY.legalName,
  alternateName: ['EMILIA', 'Emilia Protocol', 'emiliaprotocol.ai'],
  url: 'https://www.emiliaprotocol.ai',
  logo: {
    '@type': 'ImageObject',
    url: 'https://www.emiliaprotocol.ai/logo.png',
    width: 512,
    height: 512,
  },
  email: ENTITY.email,
  description:
    'EMILIA is building an AI workforce business, connecting a builder marketplace to employer-owned jobs, limits and work records. '
    + 'Gate enforces customer authority on configured execution paths. The workforce workspace is a private local alpha; EMILIA Protocol is its open foundation.',
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
  '@id': 'https://www.emiliaprotocol.ai/#website',
  name: 'EMILIA',
  alternateName: ['EMILIA', 'emiliaprotocol.ai'],
  url: 'https://www.emiliaprotocol.ai',
  publisher: { '@id': 'https://www.emiliaprotocol.ai/#organization' },
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
        <link rel="alternate" href="/llms.txt" type="text/plain" title="EMILIA LLM context index" />
        <link
          rel="alternate"
          href="/.well-known/emilia-context.json"
          type="application/json"
          title="EMILIA machine-readable context"
        />
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
          // Site-wide WebSite schema linked to the Organization entity.
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
