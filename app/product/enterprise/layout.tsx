import type { Metadata } from 'next';

export const metadata: Metadata = {
  title: 'EMILIA Gate Enterprise — Private Consequence Firewall',
  description:
    'Bound authorization for infrastructure changes, data exports, ' +
    'permission escalations, and production deployments. PAM-layer ' +
    'extension with cryptographic action-binding and named signoff.',
  alternates: { canonical: '/product/enterprise' },
  openGraph: {
    title: 'EMILIA Gate Enterprise',
    description:
      'Action-bound authorization layered on top of PAM. Cryptographic ' +
      'evidence for every consequential enterprise change.',
    url: 'https://www.emiliaprotocol.ai/product/enterprise',
    type: 'article',
  },
  keywords: [
    'enterprise AI governance',
    'privileged access management',
    'PAM AI integration',
    'zero trust action',
    'production deployment authorization',
  ],
};

export default function EnterpriseProductLayout({ children }: { children: React.ReactNode }) {
  return children;
}
