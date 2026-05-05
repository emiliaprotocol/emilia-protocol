export const metadata = {
  title: 'Enterprise Use Case — Privileged Action Authorization for Zero Trust',
  description:
    'Bound authorization for infrastructure changes, data exports, ' +
    'permission escalations, production deployments, and other privileged ' +
    'enterprise actions. PAM-layer extension with cryptographic ' +
    'action-binding and named accountable signoff.',
  alternates: { canonical: '/use-cases/enterprise' },
  openGraph: {
    title: 'EMILIA Protocol for Enterprise Privileged Actions',
    description:
      'Action-bound authorization layered on top of PAM. Cryptographic ' +
      'evidence for every consequential change.',
    url: 'https://www.emiliaprotocol.ai/use-cases/enterprise',
    type: 'article',
  },
  keywords: [
    'privileged access management',
    'PAM AI integration',
    'zero trust action authorization',
    'production deployment authorization',
    'enterprise AI governance',
    'data export authorization',
    'permission escalation control',
  ],
};

export default function EntUseCaseLayout({ children }) {
  return children;
}
