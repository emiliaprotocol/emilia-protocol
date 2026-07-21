import type { Metadata } from 'next';

export const metadata: Metadata = {
  title: 'EMILIA Gate Cloud — Managed Consequence Firewall',
  description:
    'Managed policy, exact-action approval orchestration, durable consumption, '
    + 'evidence operations, and monitoring for EMILIA Gate deployments.',
  alternates: { canonical: '/product/cloud' },
  openGraph: {
    title: 'EMILIA Gate Cloud',
    description:
      'Managed consequence-firewall operations with customer-pinned trust and '
      + 'open, independently reproducible evidence.',
    url: 'https://www.emiliaprotocol.ai/product/cloud',
    type: 'article',
  },
  keywords: [
    'EMILIA Gate Cloud',
    'hosted AI authorization',
    'managed authorization receipts',
    'signoff workflow as a service',
  ],
};

export default function CloudProductLayout({ children }: { children: React.ReactNode }) {
  return children;
}
