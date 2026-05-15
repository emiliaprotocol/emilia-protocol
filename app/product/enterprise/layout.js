export const metadata = {
  title: 'Enterprise — Privileged Action Authorization for Zero Trust',
  description:
    'Bound authorization for infrastructure changes, data exports, ' +
    'permission escalations, and production deployments. PAM-layer ' +
    'extension with cryptographic action-binding and named signoff.',
  alternates: { canonical: '/product/enterprise' },
  openGraph: {
    title: 'EMILIA Enterprise',
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

export default function EnterpriseProductLayout({ children }) {
  return children;
}
