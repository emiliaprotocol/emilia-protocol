import { headers } from 'next/headers';

export const metadata = {
  title: 'AI Agent Consequence Firewall',
  description:
    'EMILIA Gate blocks consequential AI-agent actions until exact-action authority verifies, '
    + 'then records one-time execution evidence on the open EMILIA Protocol.',
  alternates: { canonical: '/gate' },
  openGraph: {
    title: 'EMILIA Gate — The Consequence Firewall for AI Agents',
    description:
      'Protocol proves. Gate prevents. Deny consequential machine actions until exact-action authority verifies at the system-of-record boundary.',
    url: 'https://www.emiliaprotocol.ai/gate',
    type: 'website',
  },
  twitter: {
    card: 'summary_large_image',
    title: 'EMILIA Gate — The Consequence Firewall',
    description:
      'Deny consequential machine actions until exact-action authority verifies.',
  },
};

const GATE_JSONLD = {
  '@context': 'https://schema.org',
  '@type': ['SoftwareApplication', 'Product'],
  '@id': 'https://www.emiliaprotocol.ai/gate#product',
  name: 'EMILIA Gate',
  alternateName: 'The Consequence Firewall',
  url: 'https://www.emiliaprotocol.ai/gate',
  applicationCategory: 'SecurityApplication',
  applicationSubCategory: 'AI agent consequence firewall',
  operatingSystem: 'Cross-platform',
  description:
    'A deny-by-default enforcement product for consequential machine actions. '
    + 'At an integrated system-of-record or actuator boundary, EMILIA Gate requires '
    + 'exact-action authorization evidence before protected execution and records the result.',
  brand: {
    '@type': 'Brand',
    name: 'EMILIA',
  },
  manufacturer: {
    '@type': 'Organization',
    name: 'EMILIA Protocol, Inc.',
    url: 'https://www.emiliaprotocol.ai',
  },
  isBasedOn: {
    '@type': 'CreativeWork',
    name: 'EMILIA Protocol',
    url: 'https://www.emiliaprotocol.ai/protocol',
    license: 'https://www.apache.org/licenses/LICENSE-2.0',
  },
  featureList: [
    'Exact-action authorization challenges',
    'Deny-by-default enforcement for protected actions',
    'Named-human and multi-party approval profiles',
    'One-time authorization consumption',
    'Portable evidence for independent offline verification',
    'MCP and system-of-record integration patterns',
  ],
  subjectOf: [
    {
      '@type': 'TechArticle',
      name: 'EMILIA Engineering Evidence',
      url: 'https://www.emiliaprotocol.ai/proof',
    },
    {
      '@type': 'WebPage',
      name: 'EMILIA Assurance Plane',
      url: 'https://www.emiliaprotocol.ai/assurance',
    },
  ],
};

export default async function GateLayout({ children }) {
  const nonce = (await headers()).get('x-nonce') ?? '';

  return (
    <>
      <script
        type="application/ld+json"
        suppressHydrationWarning
        dangerouslySetInnerHTML={{ __html: JSON.stringify(GATE_JSONLD) }}
        nonce={nonce}
      />
      {children}
    </>
  );
}
