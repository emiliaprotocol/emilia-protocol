import type { Metadata } from 'next';

export const metadata: Metadata = {
  title: 'Enterprise — Privileged-Action Solution Profile',
  description:
    'A bounded EMILIA solution profile for exact-action checks around infrastructure changes, ' +
    'data exports, permission escalations, and deployment approvals.',
  alternates: { canonical: '/use-cases/enterprise' },
  openGraph: {
    title: 'EMILIA Protocol for Enterprise Privileged Actions',
    description:
      'Action-bound evidence and admission checks for buyer-selected privileged operations.',
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

export default function EntUseCaseLayout({ children }: { children: React.ReactNode }) {
  return children;
}
