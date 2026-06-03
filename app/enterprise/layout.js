export const metadata = {
  title: 'Enterprise — Privileged Action Authorization',
  description:
    'Enterprise overview for EP: privileged action authorization, PAM ' +
    'integration, named signoff for production deployments, data exports, ' +
    'permission escalations, and infrastructure changes.',
  alternates: { canonical: '/enterprise' },
  openGraph: {
    title: 'EMILIA Protocol for Enterprise',
    description:
      'Action-bound authorization layered on PAM, IAM, and audit ' +
      'pipelines for consequential enterprise changes.',
    url: 'https://www.emiliaprotocol.ai/enterprise',
    type: 'article',
  },
  keywords: [
    'enterprise AI authorization',
    'PAM AI integration',
    'production deployment approval',
    'enterprise zero trust',
  ],
};

export default function EnterpriseLayout({ children }) {
  return children;
}
